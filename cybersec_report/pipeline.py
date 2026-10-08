"""Orkestrasi pipeline IPS (dipakai UI Streamlit dan test):
RAW -> SCHEMA -> NORMALIZE -> VALIDATE -> ANALYTICS -> REPUTATION -> FINDINGS -> PPT -> VERIFY."""
from datetime import date
from pathlib import Path

from cybersec_report.core import analytics, history, ingestion, insights, normalization, period as period_mod
from cybersec_report.core import reputation as rep_mod
from cybersec_report.core import snapshot as snapshot_mod
from cybersec_report.core import validation
from cybersec_report.core.audit import AuditLog
from cybersec_report.core.config_loader import (cache_dir, output_dir, get_api_key, load_asset_inventory,
                                                load_attack_knowledge, load_device_environment, load_scoring,
                                                load_settings, load_source_mapping)
from cybersec_report.report import exports, ppt_generator, ppt_verify
from cybersec_report.sources import ips as ips_src
from cybersec_report.threat_intel import PROVIDERS


def build_providers(enabled, settings, api_overrides=None):
    """enabled: {'virustotal': True, 'abuseipdb': True}. Provider tanpa API key tetap dibuat
    (engine melaporkan 'API key not configured', tidak crash)."""
    cfg = settings["reputation"]
    out = []
    for name, cls in PROVIDERS.items():
        if enabled.get(name, False):
            out.append(cls(api_key=get_api_key(cls.env_key, api_overrides), timeout=cfg["timeout_seconds"],
                           max_retries=cfg["max_retries"], backoff=cfg["backoff_base_seconds"],
                           max_retry_after=cfg.get("max_retry_after_seconds", 120)))
    return out


class IPSPipeline:
    def __init__(self, settings=None):
        self.settings = settings or load_settings()
        self.raw = self.meta = self.schema = self.norm = self.validation = None
        self.period = None
        self.sections = self.cross = None
        self.audit = None
        self.lookup = None
        self.rep = {}
        self.filter_desc = ""

    # ---- 1-4: ingestion, schema, normalisasi, validasi ----
    def ingest(self, file, filename=None, sheet=None):
        self.raw, self.meta = ingestion.read_table(file, filename, sheet)
        self.schema = normalization.detect_schema(list(self.raw.columns), "IPS", load_source_mapping())
        return self.meta

    def prepare(self, manual_mapping=None, device_env=None):
        """Terapkan mapping manual user (jika ada), normalisasi, validasi. Normalisasi tetap
        dijalankan walau kolom wajib hilang (field = NaN); validasi yang memblokir report."""
        if manual_mapping:
            self.schema = normalization.apply_manual_mapping(self.schema, manual_mapping)
        env_map = device_env if device_env is not None else load_device_environment()
        n = normalization.normalize(self.raw, self.schema, "IPS", env_map)
        self.norm = ips_src.enrich(n, load_attack_knowledge())
        self.validation = validation.validate_ips(self.raw, self.norm, self.schema, self.settings, self.meta["filename"])
        self.period = period_mod.detect_period(self.norm, self.meta["filename"])
        return self.validation

    def set_period(self, month, year, start=None, end=None):
        self.period = period_mod.make_period(month, year, start, end, source="manual")

    # ---- 5: analytics + cross validation ----
    def analyze(self):
        self.audit = AuditLog(self.meta["filename"])
        self.sections, self.filter_desc = analytics.compute_ips_sections(
            self.norm, self.settings, load_asset_inventory(), self.audit, self.meta["filename"])
        self.cross = {"checks": [], "overall": "PASS", "blocking": False}
        for a in self.sections:
            if a["total_events"] > 0:
                res = validation.cross_validate_ips(a, self.settings["tolerance_pct"])
                for c in res["checks"]:
                    c["check"] = f"[{a['name']}] " + c["check"]
                self.cross["checks"] += res["checks"]
        self.cross["overall"] = validation.overall_status(self.cross["checks"])
        self.cross["blocking"] = any(c["status"] == "FAIL" for c in self.cross["checks"])
        self.rep = {a["name"]: {"profile": rep_mod.attach_reputation(a["source_profile"], None, load_scoring()),
                    "summary": None, "stats": None} for a in self.sections}
        return self.sections

    # ---- 6-8: reputation ----
    def plan_reputation(self, max_ips):
        sel = {a["name"]: rep_mod.select_ips_for_lookup(a["source_profile"], max_ips) for a in self.sections}
        union = list(dict.fromkeys(ip for ips in sel.values() for ip in ips))
        return sel, union

    def _cached_results(self, ips, cache_path=None):
        """Hasil reputasi yang SUDAH ada di cache (provider mana pun, dalam TTL). Tidak memanggil API / tidak memakai token."""
        cache = rep_mod.ReputationCache(cache_path or cache_dir() / "reputation.sqlite")
        ttl = self.settings["reputation"]["cache_ttl_hours"]
        out = {}
        for ip in ips:
            if validation.classify_ip(ip) != "PUBLIC":
                continue
            for name in PROVIDERS:
                c = cache.get(name, ip, ttl)
                if c is not None:
                    out[ip] = {"status": "CHECKED", "providers": {name: c}, "errors": {}, "source": name, "from_cache": True}
                    break
        return out

    def _apply_reputation(self, results, queued_by_section):
        scoring_cfg = load_scoring()
        for a in self.sections:
            ips = set(a["source_profile"]["Source IP"])
            sub = {"results": {ip: r for ip, r in results.items() if ip in ips},
                   "stats": {"requested": len(ips), "public_queued": queued_by_section.get(a["name"], 0),
                             "private_skipped": 0, "invalid": 0, "providers": {}},
                   "log": []}
            prof = rep_mod.attach_reputation(a["source_profile"], sub, scoring_cfg)
            self.rep[a["name"]] = {"profile": prof, "summary": insights.reputation_summary(prof), "stats": sub["stats"]}

    def apply_cached_reputation(self, cache_path=None):
        """Dipanggil otomatis setelah analyze: IP yang pernah dicek (upload/bulan sebelumnya) langsung tampil tanpa query ulang."""
        ips = list(dict.fromkeys(ip for a in self.sections for ip in a["source_profile"]["Source IP"]))
        results = self._cached_results(ips, cache_path)
        self._apply_reputation(results, {a["name"]: sum(1 for ip in a["source_profile"]["Source IP"] if ip in results) for a in self.sections})
        return len(results)

    def run_reputation(self, enabled, max_ips, progress=None, cache_path=None, sleep=None, providers=None, api_overrides=None):
        providers = providers if providers is not None else build_providers(enabled, self.settings, api_overrides)
        cache = rep_mod.ReputationCache(cache_path or cache_dir() / "reputation.sqlite")
        kwargs = {"sleep": sleep} if sleep else {}
        engine = rep_mod.ReputationEngine(providers, cache, self.settings, progress=progress, **kwargs)
        sel, union = self.plan_reputation(max_ips)
        self.lookup = engine.lookup(union)
        # gabungkan dengan IP lain yang sudah ada di cache (di luar batas Maks. IP) agar cakupan tidak turun
        all_ips = list(dict.fromkeys(ip for a in self.sections for ip in a["source_profile"]["Source IP"]))
        merged = {**self._cached_results([ip for ip in all_ips if ip not in self.lookup["results"]], cache_path), **self.lookup["results"]}
        self._apply_reputation(merged, {n: len(v) for n, v in sel.items()})
        for a in self.sections:  # stats penuh dari lookup untuk UI
            self.rep[a["name"]]["stats"] = {**self.lookup["stats"], "public_queued": len(sel[a["name"]])}
        return self.lookup

    # ---- findings (dipakai preview UI dan generate) ----
    def compute_findings(self):
        """Return (findings_by_section, mom_by_section). MoM hanya bila bulan sebelumnya tersimpan."""
        p, rules = self.period, load_attack_knowledge()
        findings, mom_by = {}, {}
        for a in self.sections:
            prev = history.previous_snapshot(p["report_year"], p["report_month"], a["name"]) if p and p.get("report_month") else None
            mom = history.compare(a, prev, self.settings["mom"]["stable_threshold_pct"])
            mom_by[a["name"]] = mom
            findings[a["name"]] = insights.build_ips_findings(a, rules, self.settings, self.rep[a["name"]]["summary"], mom)
        return findings, mom_by

    # ---- view-model: satu bentuk data untuk dashboard (live dari upload ATAU dibuka dari snapshot) ----
    def view_model(self, section=None):
        """section=None -> semua section (tampilan live); section='IPS P1FWX0209' -> hanya hostname itu (satu snapshot per hostname)."""
        p = self.period
        if not self.sections or not (p and p.get("report_month")):
            raise RuntimeError("Dashboard butuh analytics dan periode yang sudah ditentukan.")
        findings, mom = self.compute_findings()
        secs = [a for a in self.sections if section in (None, a["name"])]
        names = [a["name"] for a in secs]
        run = {"stats": self.lookup["stats"], "log": self.lookup["log"][:50]} if self.lookup else None
        return {"period": p, "source_file": self.meta["filename"], "filter": self.filter_desc,
                "hostname": secs[0].get("hostname") if len(secs) == 1 else None,
                "total_events": sum(a["total_events"] for a in secs),
                "sections": secs, "rep": {n: self.rep[n] for n in names},
                "findings": {n: findings[n] for n in names}, "mom": {n: mom[n] for n in names},
                "reputation_run": run, "validation_overall": self.validation["overall"], "cross_overall": self.cross["overall"]}

    def save_dashboard_snapshot(self, names=None):
        """Simpan SATU snapshot per hostname/section (IPS_<host>_<YYYY-MM>.json). names=None -> semua. Return daftar path."""
        return [snapshot_mod.save_snapshot(self.view_model(a["name"]), hostname=a.get("hostname") or "ALL-HOSTS")
                for a in self.sections if names is None or a["name"] in names]

    # ---- 9-12: generate ----
    def generate(self, out_dir=None, allow_override=False, save_history=True):
        if self.validation["blocking"]:
            raise RuntimeError("Critical validation gagal. Report tidak dihasilkan.")
        if self.cross["blocking"] and not allow_override:
            raise RuntimeError("Cross-validation mismatch. Report diblokir (aktifkan override untuk menghasilkan dengan WARNING).")
        p = self.period
        if not p or not p.get("report_month"):
            raise RuntimeError("Periode report belum ditentukan.")
        out = Path(out_dir or output_dir())
        out.mkdir(parents=True, exist_ok=True)
        tag = f"{p['report_year']}_{p['report_month']:02d}"
        findings, mom_by = self.compute_findings()
        files = {"pptx": out / f"Cybersecurity_Monthly_Report_{tag}.pptx",
                 "summary": out / f"Cybersecurity_Monthly_Summary_{tag}.xlsx",
                 "ioc": out / f"IOC_Reputation_{tag}.xlsx",
                 "audit": out / f"Report_Audit_{tag}.json",
                 "validation": out / f"Validation_Report_{tag}.xlsx"}
        ppt_generator.generate_ips_deck(self.sections, p, self.meta["filename"], findings, self.rep, self.settings, files["pptx"])
        ppt = ppt_verify.verify_ppt(files["pptx"], self.sections)
        raw_total = ppt_verify.independent_raw_total(self.raw, self.schema, self.settings["ips"]["allowed_actions"])
        recon = ppt_verify.reconcile(raw_total, self.sections, ppt["numbers"])
        self.audit.record("ALL", "reconciliation", recon["match"], "", "raw_total == analytics_total == ppt_total")
        profiles = {n: v["profile"] for n, v in self.rep.items()}
        exports.write_summary_xlsx(files["summary"], self.sections, p, recon, mom_by, profiles)
        ioc_df = rep_mod.ioc_report(None, self.lookup) if self.lookup else None
        exports.write_ioc_xlsx(files["ioc"], ioc_df, (self.lookup or {}).get("stats"), (self.lookup or {}).get("log"))
        exports.write_validation_xlsx(files["validation"], self.validation, self.cross, ppt, recon)
        self.audit.save(files["audit"], meta={"period": f"{p['month_name']} {p['report_year']}", "period_source": p["source"],
                                              "filter": self.filter_desc, "reconciliation": recon})
        if save_history:
            for a in self.sections:
                history.save_snapshot(p["report_year"], p["report_month"], a["name"], a)
        snap = None
        try:
            snap = [str(x) for x in self.save_dashboard_snapshot()]
        except Exception as e:  # dashboard snapshot tidak boleh menggagalkan generate
            self.audit.record("ALL", "dashboard_snapshot_failed", str(e), "", "save_snapshot")
        return {"dashboard_snapshot": snap, "files": {k: str(v) for k, v in files.items()}, "ppt_verification": ppt, "reconciliation": recon,
                "findings": findings, "mom": mom_by, "override_used": bool(self.cross["blocking"] and allow_override)}
