"""IP reputation engine: cache SQLite (TTL), rate limiting, circuit breaker, private IP handling.
Tidak pernah crash karena satu provider gagal; setiap kegagalan tercatat dan ditampilkan."""
import json
import sqlite3
from contextlib import contextmanager
import time
from datetime import date, datetime, timedelta, timezone

import numpy as np
import pandas as pd

from cybersec_report.core import scoring as scoring_mod
from cybersec_report.core.validation import classify_ip
from cybersec_report.threat_intel.base import ProviderAuthError, ProviderError, ProviderQuotaExceeded, ProviderRateLimited


class RateLimiter:
    """Jaga jarak minimal 60/rpm detik antar request (sleep/clock bisa diinjeksi untuk test)."""
    def __init__(self, rpm, sleep=time.sleep, clock=time.monotonic):
        self.interval = 60.0 / rpm if rpm and rpm > 0 else 0.0
        self.sleep, self.clock, self._last = sleep, clock, None

    def wait(self):
        if self.interval and self._last is not None:
            delta = self.clock() - self._last
            if delta < self.interval:
                self.sleep(self.interval - delta)
        self._last = self.clock()


class ReputationCache:
    """Cache hasil lookup: key (provider, indicator), simpan lookup_date + fetched_at, TTL jam.
    Hanya hasil SUKSES yang di-cache (kegagalan tidak boleh 'menempel')."""
    def __init__(self, path, clock=time.time):
        self.path, self.clock = str(path), clock
        self._init()

    @contextmanager
    def _conn(self):
        """Commit + CLOSE (sqlite3 'with' saja tidak menutup koneksi; penting di Windows agar file tidak terkunci)."""
        conn = sqlite3.connect(self.path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init(self):
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS reputation (provider TEXT, indicator TEXT, lookup_date TEXT,
                         fetched_at REAL, payload TEXT, PRIMARY KEY (provider, indicator))""")
            c.execute("""CREATE TABLE IF NOT EXISTS provider_state (provider TEXT PRIMARY KEY, reason TEXT, until REAL)""")

    # --- status kuota provider (persisten antar-run: provider yang kuotanya habis tidak dicoba lagi) ---
    def set_exhausted(self, provider, reason, until=None):
        if until is None:  # asumsi kuota harian: reset 00:00 UTC berikutnya
            now = datetime.fromtimestamp(self.clock(), tz=timezone.utc)
            until = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO provider_state VALUES (?,?,?)", (provider, reason, until))
        return until

    def get_exhausted(self, provider):
        with self._conn() as c:
            row = c.execute("SELECT reason, until FROM provider_state WHERE provider=?", (provider,)).fetchone()
        if row and row[1] > self.clock():
            return {"reason": row[0], "until": row[1]}
        return None

    def clear_exhausted(self, provider=None):
        with self._conn() as c:
            if provider:
                c.execute("DELETE FROM provider_state WHERE provider=?", (provider,))
            else:
                c.execute("DELETE FROM provider_state")

    def get(self, provider, indicator, ttl_hours):
        with self._conn() as c:
            row = c.execute("SELECT fetched_at, payload FROM reputation WHERE provider=? AND indicator=?",
                            (provider, indicator)).fetchone()
        if row and (self.clock() - row[0]) <= ttl_hours * 3600:
            return json.loads(row[1])
        return None

    def put(self, provider, indicator, payload):
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO reputation VALUES (?,?,?,?,?)",
                      (provider, indicator, date.today().isoformat(), self.clock(), json.dumps(payload)))


def select_ips_for_lookup(profile, max_ips):
    """Pilih IP PUBLIK yang dicek reputasinya. Seleksi BERSELANG-SELING antara dua daftar prioritas:
    (1) paling banyak serangan Critical, (2) paling banyak event total. Alasan: hanya memakai Critical
    akan melewatkan sumber terbesar yang kebetulan berseverity Low (mis. satu IP scanner dengan 15%
    seluruh event). max_ips <= 0 -> semua IP publik."""
    pub = profile[profile["Source IP"].map(lambda x: classify_ip(x) == "PUBLIC")]
    if not max_ips or max_ips <= 0:
        return pub.sort_values(["Attack Count", "Source IP"], ascending=[False, True])["Source IP"].tolist()
    by_crit = pub.sort_values(["Critical", "Attack Count", "Unique Attack", "Source IP"], ascending=[False, False, False, True])["Source IP"].tolist()
    by_vol = pub.sort_values(["Attack Count", "Unique Attack", "Source IP"], ascending=[False, False, True])["Source IP"].tolist()
    chosen, seen = [], set()
    for ip in [x for pair in zip(by_vol, by_crit) for x in pair]:  # volume dulu, lalu Critical, bergantian
        if ip not in seen:
            seen.add(ip)
            chosen.append(ip)
        if len(chosen) >= max_ips:
            break
    return chosen


def estimate_minutes(n_ips, providers_cfg):
    """Estimasi waktu lookup (provider berjalan berurutan, dibatasi provider paling lambat)."""
    rpms = [c["requests_per_minute"] for c in providers_cfg.values() if c.get("enabled") and c.get("requests_per_minute")]
    return round(n_ips / min(rpms), 1) if rpms else 0.0


class ReputationEngine:
    """Strategi (settings.reputation.strategy):
    - "failover" (default): SATU provider dipakai sampai kuota/limit-nya habis, lalu otomatis pindah ke
      provider berikutnya (urutan: provider_order). Hasil yang sudah ada di cache (provider mana pun)
      dipakai tanpa memanggil API. Tujuan: tidak memboroskan token.
    - "all": semua provider aktif dipanggil untuk setiap IP (korelasi dua sumber, boros token)."""
    CIRCUIT_BREAKER_FAILS = 5

    def __init__(self, providers, cache, settings, sleep=time.sleep, clock=time.monotonic, progress=None):
        self.providers = {p.name: p for p in providers}
        self.cache, self.cfg, self.progress = cache, settings["reputation"], progress
        self.limiters = {p.name: RateLimiter(self.cfg["providers"].get(p.name, {}).get("requests_per_minute", 0), sleep, clock)
                         for p in providers}
        order = [n for n in self.cfg.get("provider_order", []) if n in self.providers]
        self.order = order + [n for n in self.providers if n not in order]
        self.strategy = self.cfg.get("strategy", "failover")

    # ---- helpers ----
    def _mark_exhausted(self, name, reason, persist, stats, log):
        stats["providers"][name]["state"] = f"exhausted: {reason}"
        if persist:
            self.cache.set_exhausted(name, reason)
        nxt = [n for n in self.order if n != name and stats["providers"][n]["state"] == "active"]
        used = stats["providers"][name]["api_calls"]
        msg = f"INFO {name}: kuota/limit habis setelah {used} request ({reason})."
        if nxt:
            msg += f" Otomatis beralih ke {nxt[0]}."
            stats["switches"].append({"from": name, "to": nxt[0], "after_api_calls": used})
        else:
            msg += " Tidak ada provider lain yang aktif."
        log.append(msg)

    def _query(self, name, ip, res, stats, log, fails):
        """Satu panggilan ke provider. True bila sukses. Semua error ditangani; tidak pernah melempar."""
        st, p = stats["providers"][name], self.providers[name]
        self.limiters[name].wait()
        st["api_calls"] += 1
        try:
            data = p.query_ip(ip)
        except ProviderAuthError as e:
            st["state"] = f"disabled: {e}"
            res["errors"][name] = str(e)
            log.append(f"ERROR {name}: {e}. Provider dinonaktifkan untuk sisa proses.")
            return False
        except ProviderQuotaExceeded as e:
            res["errors"][name] = str(e)
            self._mark_exhausted(name, str(e), True, stats, log)
            return False
        except ProviderRateLimited as e:  # 429 yang tidak mereda: jangan disimpan permanen (mungkin hanya per-menit)
            res["errors"][name] = str(e)
            self._mark_exhausted(name, str(e), False, stats, log)
            return False
        except ProviderError as e:
            st["failed"] += 1
            res["errors"][name] = str(e)
            fails[name] += 1
            log.append(f"WARNING {name} {ip}: {e}")
            if fails[name] >= self.CIRCUIT_BREAKER_FAILS:
                st["state"] = f"disabled: {fails[name]} kegagalan beruntun"
                log.append(f"ERROR {name}: circuit breaker aktif setelah {fails[name]} kegagalan beruntun.")
            return False
        self.cache.put(name, ip, data)
        res["providers"][name] = data
        st["ok"] += 1
        fails[name] = 0
        if p.remaining_quota() == 0:  # header menyatakan sisa kuota 0: beralih SEBELUM kena error
            self._mark_exhausted(name, "sisa kuota 0 (header respons)", True, stats, log)
        return True

    def lookup(self, ips):
        ips = list(dict.fromkeys(ips))
        results, log = {}, []
        stats = {"requested": len(ips), "public_queued": 0, "private_skipped": 0, "invalid": 0, "providers": {},
                 "strategy": self.strategy, "order": list(self.order), "switches": []}
        queue = []
        for ip in ips:
            kind = classify_ip(ip)
            if kind == "PRIVATE_IP":
                results[ip] = {"status": "PRIVATE_IP", "providers": {}, "errors": {}}
                stats["private_skipped"] += 1
            elif kind == "INVALID":
                results[ip] = {"status": "INVALID_IP", "providers": {}, "errors": {}}
                stats["invalid"] += 1
            else:
                queue.append(ip)
        stats["public_queued"] = len(queue)

        for name, p in self.providers.items():
            stats["providers"][name] = {"ok": 0, "cached": 0, "failed": 0, "api_calls": 0, "state": "active"}
        for name, p in self.providers.items():
            st = stats["providers"][name]
            ex = self.cache.get_exhausted(name)
            if not p.is_configured():
                st["state"] = "unavailable: API key not configured"
                log.append(f"WARNING {name}: Provider unavailable / API key not configured")
            elif ex:
                until = datetime.fromtimestamp(ex["until"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                st["state"] = f"exhausted: {ex['reason']} (dilewati sampai {until})"
                log.append(f"INFO {name}: kuota tercatat habis pada run sebelumnya, dilewati sampai {until} (tanpa membuang request).")
        fails = {n: 0 for n in self.providers}
        ttl = self.cfg["cache_ttl_hours"]
        announced_none = False
        for i, ip in enumerate(queue, 1):
            res = {"status": "UNAVAILABLE", "providers": {}, "errors": {}, "source": None}
            if self.strategy == "all":
                for name in self.order:
                    st = stats["providers"][name]
                    if st["state"] != "active":
                        res["errors"][name] = st["state"]
                        continue
                    cached = self.cache.get(name, ip, ttl)
                    if cached is not None:
                        res["providers"][name] = cached
                        st["cached"] += 1
                        st["ok"] += 1
                    else:
                        self._query(name, ip, res, stats, log, fails)
                active_n = sum(1 for n in self.order if stats["providers"][n]["state"] == "active" or n in res["providers"])
                got = len(res["providers"])
                res["status"] = "CHECKED" if got and got >= active_n else ("PARTIAL" if got else "UNAVAILABLE")
            else:  # failover
                for name in self.order:  # 1) cache dulu, dari provider mana pun (gratis)
                    cached = self.cache.get(name, ip, ttl)
                    if cached is not None:
                        res["providers"][name] = cached
                        stats["providers"][name]["cached"] += 1
                        stats["providers"][name]["ok"] += 1
                        break
                if not res["providers"]:  # 2) satu provider sampai habis, lalu berikutnya
                    for name in self.order:
                        st = stats["providers"][name]
                        if st["state"] != "active":
                            res["errors"].setdefault(name, st["state"])
                            continue
                        if self._query(name, ip, res, stats, log, fails):
                            break
                    if not res["providers"] and not announced_none and not any(
                            stats["providers"][n]["state"] == "active" for n in self.order):
                        log.append("ERROR Semua provider tidak tersedia/kuota habis: IP berikutnya tidak dapat dicek hari ini.")
                        announced_none = True
                res["status"] = "CHECKED" if res["providers"] else "UNAVAILABLE"
            res["source"] = next(iter(res["providers"]), None)
            results[ip] = res
            if self.progress:
                self.progress(i, len(queue))
        return {"results": results, "stats": stats, "log": log}


INTERPRETATION = {"Critical": "Sangat mencurigakan menurut provider", "High": "Mencurigakan menurut provider",
                  "Medium": "Perlu dipantau", "Guarded": "Indikasi rendah", "Low": "Tidak terindikasi menurut provider",
                  "PRIVATE_IP": "IP privat (tidak dicek)"}


def interpret(level, status):
    if level in INTERPRETATION:
        return INTERPRETATION[level]
    return "Belum dicek (bukan berarti aman)" if status in ("Not checked", "UNAVAILABLE") else "-"


def evidence_text(vt, ab):
    """Ringkasan bukti dari provider yang BENAR-BENAR dipakai (tidak mengarang sumber yang tidak dipanggil)."""
    parts = []
    if vt:
        engines = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
        parts.append(f"VirusTotal: {vt['malicious']} malicious" + (f" + {vt['suspicious']} suspicious" if vt["suspicious"] else "")
                     + f" dari {engines} engine")
    if ab:
        last = f", terakhir dilaporkan {str(ab['lastReportedAt'])[:10]}" if ab.get("lastReportedAt") else ""
        parts.append(f"AbuseIPDB: confidence {ab['abuseConfidenceScore']}%, {ab['totalReports']} laporan{last}")
    return " | ".join(parts) if parts else "-"


def attach_reputation(profile, lookup, scoring_cfg):
    """Gabungkan hasil reputasi ke profil source IP. Sort: Threat Score desc, lalu Attack Count desc.
    IP yang tidak dicek diberi status jelas ('Not assessed'/'PRIVATE_IP'), bukan angka 0."""
    rows = []
    for ip in profile["Source IP"]:
        r = (lookup or {}).get("results", {}).get(ip)
        status = "Not checked" if r is None else r["status"]
        vt = (r or {}).get("providers", {}).get("virustotal")
        ab = (r or {}).get("providers", {}).get("abuseipdb")
        sc = scoring_mod.compute_threat_score((r or {}).get("providers", {}), scoring_cfg) if r else \
            {"score": None, "level": "Not assessed"}
        level = "PRIVATE_IP" if status == "PRIVATE_IP" else sc["level"]
        rows.append({"VT Malicious": vt["malicious"] if vt else np.nan,
                     "VT Suspicious": vt["suspicious"] if vt else np.nan,
                     "VT Engines": (vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]) if vt else np.nan,
                     "AbuseIPDB Score": ab["abuseConfidenceScore"] if ab else np.nan,
                     "AbuseIPDB Reports": ab["totalReports"] if ab else np.nan,
                     "AS / ISP": (vt or {}).get("as_owner") or (ab or {}).get("isp") or "-",
                     "Threat Score": sc["score"] if sc["score"] is not None else np.nan,
                     "Risk Level": level, "Interpretation": interpret(level, status),
                     "Evidence": evidence_text(vt, ab), "TI Status": status,
                     "TI Source": ((r or {}).get("source") or "-") if r and r.get("providers") else "-"})
    out = pd.concat([profile.reset_index(drop=True), pd.DataFrame(rows)], axis=1)
    return out.sort_values(["Threat Score", "Attack Count", "Source IP"], ascending=[False, False, True],
                           na_position="last").reset_index(drop=True)


def ioc_report(profile_with_rep, lookup):
    """Tabel IOC lengkap untuk output IOC_Reputation_<YYYY_MM>.xlsx (hanya IP yang dicek)."""
    rows = []
    for ip, r in (lookup or {}).get("results", {}).items():
        vt, ab = r["providers"].get("virustotal") or {}, r["providers"].get("abuseipdb") or {}
        rows.append({"Source IP": ip, "Status": r["status"], "VT malicious": vt.get("malicious"),
                     "VT suspicious": vt.get("suspicious"), "VT harmless": vt.get("harmless"),
                     "VT undetected": vt.get("undetected"), "VT AS owner": vt.get("as_owner"),
                     "AbuseIPDB score": ab.get("abuseConfidenceScore"), "AbuseIPDB reports": ab.get("totalReports"),
                     "AbuseIPDB last reported": ab.get("lastReportedAt"), "ISP": ab.get("isp"),
                     "AbuseIPDB country": ab.get("countryCode"), "Errors": "; ".join(f"{k}: {v}" for k, v in r["errors"].items())})
    df = pd.DataFrame(rows)
    if len(df) and profile_with_rep is not None:
        df = df.merge(profile_with_rep[["Source IP", "Threat Score", "Risk Level", "Country", "Attack Count"]], on="Source IP", how="left")
    return df
