"""Data quality validation (sebelum analytics) dan cross-validation (sebelum PPT).
Status: PASS / WARNING / FAIL. FAIL pada level CRITICAL memblokir pembuatan report."""
import ipaddress

import pandas as pd


def check(name, status, detail, level="INFO", value=None):
    return {"check": name, "status": status, "level": level, "detail": detail, "value": value}


def _valid_ip(x):
    try:
        ipaddress.ip_address(str(x).strip())
        return True
    except ValueError:
        return False


def classify_ip(x):
    """PUBLIC / PRIVATE_IP / INVALID. Private = RFC1918, loopback, link-local, IPv6 ULA/local."""
    try:
        ip = ipaddress.ip_address(str(x).strip())
    except ValueError:
        return "INVALID"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "PRIVATE_IP"
    return "PUBLIC"


def _pct(n, total):
    return round(100.0 * n / total, 2) if total else 0.0


def overall_status(checks):
    if any(c["status"] == "FAIL" for c in checks):
        return "FAIL"
    if any(c["status"] == "WARNING" for c in checks):
        return "WARNING"
    return "PASS"


def validate_ips(df_raw, df_norm, schema, settings, filename=""):
    s_ips = settings["ips"]
    checks, total = [], len(df_norm)
    checks.append(check("File loaded", "PASS", f"{filename or 'file'}: {total:,} raw records", value=total))

    # --- CRITICAL: kolom wajib ---
    for req in schema["missing_required"]:
        checks.append(check(f"Kolom wajib '{req}'", "FAIL",
                            f"Kolom untuk '{req}' tidak terdeteksi. Report IPS tidak dapat dibuat tanpa kolom ini. "
                            "Petakan manual di UI atau perbaiki file.", "CRITICAL"))
    if not schema["missing_required"]:
        checks.append(check("Required columns detected", "PASS", "attack, severity, src_ip terdeteksi"))
    for canon, raws in schema["conflicts"].items():
        checks.append(check(f"Konflik mapping '{canon}'", "FAIL",
                            f"Beberapa kolom cocok: {raws}. Pilih satu di UI.", "CRITICAL"))
    for rec in schema["missing_recommended"]:
        extra = {"timestamp": "trend serangan tidak dapat dihitung"}.get(rec, "bagian report terkait dikurangi")
        checks.append(check(f"Kolom '{rec}' tidak ada", "WARNING", extra, "WARNING"))
    if "timestamp" not in schema["mapping"]:
        checks.append(check("Timestamp tidak tersedia", "WARNING",
                            "Attack trend tidak dapat dihitung; periode report diambil dari nama file/input manual.", "WARNING"))
    if schema["unmapped_columns"]:
        checks.append(check("Unmapped columns", "WARNING", f"Kolom tidak dipakai: {schema['unmapped_columns']}", "WARNING"))

    # --- duplicate rows (raw) ---
    dups = int(df_raw.duplicated().sum())
    checks.append(check("Duplicate rows", "WARNING" if dups else "PASS",
                        f"{dups} baris duplikat persis ({_pct(dups, total)}%)" if dups else "Tidak ada duplikat", "WARNING" if dups else "INFO", dups))

    # --- null values per kolom ter-mapping ---
    for canon in schema["mapping"]:
        if canon in df_norm.columns:
            n = int(df_norm[canon].isna().sum())
            if n:
                checks.append(check(f"Null '{canon}'", "WARNING", f"{n} baris kosong ({_pct(n, total)}%)", "WARNING", n))
    # --- IP validity ---
    for col, label in (("src_ip", "source IP"), ("dst_ip", "destination IP")):
        if col in schema["mapping"]:
            vals = df_norm[col].dropna()
            invalid = int((~vals.map(_valid_ip)).sum())
            checks.append(check(f"Invalid {label}", "WARNING" if invalid else "PASS",
                                f"{invalid} IP tidak valid dari {len(vals):,}" if invalid else f"{len(vals):,} IP valid, 0 tidak valid",
                                "WARNING" if invalid else "INFO", invalid))
    # --- country ---
    if "src_country" in schema["mapping"]:
        bad = set(settings["invalid_country_values"])
        n = int(df_norm["src_country"].isna().sum() + df_norm["src_country"].dropna().str.lower().isin(bad).sum())
        checks.append(check("Invalid country", "WARNING" if n else "PASS",
                            f"{n} baris country kosong/tidak valid ({_pct(n, total)}%)" if n else "Country valid", "WARNING" if n else "INFO", n))
    # --- severity ---
    unk = int((df_norm["severity"] == "Unknown").sum())
    checks.append(check("Severity valid", "WARNING" if unk else "PASS",
                        f"{unk} baris severity tidak dikenali (ditampilkan sebagai 'Unknown', tidak dibuang)" if unk else "Semua severity valid",
                        "WARNING" if unk else "INFO", unk))
    # --- date ---
    if "timestamp" in schema["mapping"]:
        ts = pd.to_datetime(df_norm["timestamp"], errors="coerce")
        bad = int(ts.isna().sum() - df_norm["timestamp"].isna().sum())
        checks.append(check("Invalid date", "WARNING" if bad else "PASS",
                            f"{bad} timestamp tidak bisa diparse" if bad else "Timestamp valid", "WARNING" if bad else "INFO", bad))
    # --- count ---
    if "count" in schema["mapping"]:
        neg = int((df_norm["count_invalid_value"] < 0).sum())
        nonnum = int(df_norm["count_invalid_value"].isna().sum())
        if neg:
            checks.append(check("Negative count", "FAIL", f"{neg} baris count negatif; total event tidak dapat dipercaya.", "CRITICAL", neg))
        else:
            checks.append(check("Negative count", "PASS", "Tidak ada count negatif"))
        if nonnum:
            checks.append(check("Non-numeric count", "WARNING", f"{nonnum} baris count bukan angka (dihitung 0 event)", "WARNING", nonnum))
    else:
        checks.append(check("Kolom count tidak ada", "WARNING", "Setiap baris dihitung 1 event.", "WARNING"))
    # --- action ---
    if "action" in schema["mapping"]:
        known = set(s_ips["known_actions"])
        acts = set(df_norm["action"].dropna().unique())
        unknown = sorted(acts - known)
        checks.append(check("Unknown action", "WARNING" if unknown else "PASS",
                            f"Action tidak dikenal: {unknown}" if unknown else f"Action dikenali: {sorted(acts)}",
                            "WARNING" if unknown else "INFO", len(unknown)))
        allowed = set(s_ips["allowed_actions"])
        out = df_norm[~df_norm["action"].isin(allowed)]
        checks.append(check("Action filter", "PASS",
                            f"{len(df_norm) - len(out):,} record masuk scope (action blocked/dropped/denied); {len(out):,} record ({out['count'].sum():,.0f} event) dikecualikan"))
    # --- unknown source (device belum dipetakan ke environment) ---
    if "device" in schema["mapping"]:
        unmapped = sorted(df_norm.loc[df_norm["environment"] == "Unmapped", "device"].dropna().unique())
        if unmapped:
            checks.append(check("Unknown source", "WARNING",
                                f"{len(unmapped)} device belum dipetakan ke environment (DCI/NTT/GCP): {unmapped}. "
                                "Report digabung sebagai 'All Devices' sampai dipetakan di UI.", "WARNING", len(unmapped)))
        else:
            checks.append(check("Unknown source", "PASS", "Semua device sudah dipetakan ke environment"))
    # --- IP public/private (untuk threat intelligence) ---
    if "src_ip" in schema["mapping"]:
        kinds = df_norm["src_ip"].dropna().map(classify_ip).value_counts()
        pub = df_norm.loc[df_norm["src_ip"].map(lambda x: classify_ip(x) == "PUBLIC" if pd.notna(x) else False), "src_ip"].nunique()
        priv = df_norm.loc[df_norm["src_ip"].map(lambda x: classify_ip(x) == "PRIVATE_IP" if pd.notna(x) else False), "src_ip"].nunique()
        checks.append(check("Source IP public/private", "PASS" if not priv else "WARNING",
                            f"{pub:,} source IP publik unik, {priv:,} private (tidak akan di-query ke API eksternal)",
                            "INFO" if not priv else "WARNING", {"public": int(pub), "private": int(priv)}))
    return {"checks": checks, "overall": overall_status(checks),
            "blocking": any(c["status"] == "FAIL" and c["level"] == "CRITICAL" for c in checks)}


def cross_validate_ips(a, tolerance_pct=0.01):
    """Validasi silang angka analytics SEBELUM PPT dibuat (spesifikasi bagian AF)."""
    out, total = [], a["total_events"]

    def eq(name, left, right, note=""):
        ok = abs(left - right) <= 1e-9
        out.append(check(name, "PASS" if ok else "FAIL", f"{left:,.0f} vs {right:,.0f} {note}".strip(), "CRITICAL" if not ok else "INFO", [left, right]))

    def pct100(name, df):
        s = float(df["Percent"].sum()) if len(df) else 100.0
        ok = abs(s - 100.0) <= tolerance_pct or len(df) == 0
        out.append(check(name, "PASS" if ok else "FAIL", f"Total persentase = {s:.4f}% (toleransi {tolerance_pct}%)", "CRITICAL" if not ok else "INFO", s))

    eq("Severity total = total event", float(a["severity"]["Count"].sum()), total)
    for sev, df in a["top_by_severity"].items():
        sev_total = float(a["severity"].set_index("Severity").loc[sev, "Count"])
        eq(f"Tabel attack {sev} = total {sev}", float(df["Count"].sum()), sev_total)
        pct100(f"Persentase tabel attack {sev} = 100%", df)
    eq("Country total = total event", float(a["top_country"]["Count"].sum()), total)
    eq("Destination total = total event", float(a["top_destination"]["Count"].sum()), total)
    pct100("Persentase country = 100%", a["top_country"])
    pct100("Persentase destination = 100%", a["top_destination"])
    top_attack_total = float(a["top_attacks"].loc[a["top_attacks"]["Attack Name"] != "Others", "Count"].sum())
    ok = top_attack_total <= total + 1e-9
    out.append(check("Top attack total <= severity total", "PASS" if ok else "FAIL", f"{top_attack_total:,.0f} <= {total:,.0f}", "CRITICAL" if not ok else "INFO"))
    return {"checks": out, "overall": overall_status(out), "blocking": any(c["status"] == "FAIL" for c in out)}
