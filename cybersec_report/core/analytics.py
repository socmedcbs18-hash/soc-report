"""Analytics IPS. Semua kalkulasi berjalan pada canonical schema.
- Total attack = SUM(count), bukan jumlah baris (rekonsiliasi: raw records vs aggregated events).
- Persentase memakai penyebut konteks: attack Critical dibagi total Critical, bukan total semua."""
import pandas as pd

from cybersec_report.sources import ips as ips_src

UNKNOWN_LABEL = "(tidak diketahui)"
SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def top_n_table(series, label_col, n=5, denom=None):
    """Top-N + 'Others'. Item <= n: tampilkan semua. Item > n: Top n + Others.
    Urutan deterministik: count turun, lalu label naik. Percent dihitung dari denom
    (default: jumlah series itu sendiri) dan TIDAK dibulatkan (pembulatan hanya saat render)."""
    s = series[series > 0]
    if s.empty:
        return pd.DataFrame(columns=[label_col, "Count", "Percent"])
    items = sorted(s.items(), key=lambda kv: (-kv[1], str(kv[0])))
    denom = float(s.sum()) if denom is None else float(denom)
    rows = items[:n] + ([("Others", sum(v for _, v in items[n:]))] if len(items) > n else [])
    df = pd.DataFrame(rows, columns=[label_col, "Count"])
    df["Count"] = df["Count"].astype(float)
    df["Percent"] = df["Count"] / denom * 100.0 if denom else 0.0
    return df


def _sum_by(df, col):
    return df.assign(_k=df[col].fillna(UNKNOWN_LABEL)).groupby("_k")["count"].sum()


def compute_ips_analytics(df, settings, asset_inv=None, audit=None, slide="IPS", source_file="",
                          filter_desc="", raw_records=None, excluded=None, environment=None):
    """df: canonical, SUDAH difilter scope action. raw_records/excluded: info rekonsiliasi."""
    n = settings.get("top_n", 5)
    asset_inv = asset_inv or {}
    desc = settings["severity_descriptions"]
    total = float(df["count"].sum())
    a = {"slide": slide, "environment": environment, "filter": filter_desc,
         "devices": sorted(df["device"].dropna().unique().tolist()) if "device" in df else [],
         "actions": sorted(df["action"].dropna().unique().tolist()) if "action" in df else [],
         "total_events": total, "records_in_scope": int(len(df))}
    excl_events = float(excluded["count"].sum()) if excluded is not None and len(excluded) else 0.0
    a["reconciliation"] = {
        "raw_records_in_file": int(raw_records if raw_records is not None else len(df)),
        "records_in_scope": int(len(df)),
        "aggregated_events_in_scope": total,
        "records_excluded_by_action": int(len(excluded)) if excluded is not None else 0,
        "events_excluded_by_action": excl_events,
    }

    # --- action breakdown (SEMUA event di file, termasuk yang tidak dihitung) ---
    full = pd.concat([df, excluded]) if excluded is not None and len(excluded) else df
    if "action" in full and full["action"].notna().any():
        g = full.assign(_a=full["action"].fillna("(kosong)")).groupby("_a")["count"].sum().sort_values(ascending=False)
        counted = set(df["action"].dropna().unique())
        all_ev = float(g.sum())
        a["action_breakdown"] = pd.DataFrame({"Action": g.index.tolist(), "Events": g.values.astype(float),
                                              "Percent": (g.values / all_ev * 100.0) if all_ev else 0.0,
                                              "Counted": [x in counted for x in g.index]})
    else:
        a["action_breakdown"] = pd.DataFrame(columns=["Action", "Events", "Percent", "Counted"])

    # --- severity ---
    sev_counts = df.groupby("severity")["count"].sum()
    levels = SEV_ORDER + [s for s in ("Info", "Unknown") if sev_counts.get(s, 0) > 0]
    sev = pd.DataFrame({"Severity": levels, "Count": [float(sev_counts.get(s, 0)) for s in levels]})
    sev["Description"] = sev["Severity"].map(lambda s: desc.get(s, ""))
    sev["Percent"] = sev["Count"] / total * 100.0 if total else 0.0
    a["severity"] = sev[["Severity", "Description", "Count", "Percent"]]

    # --- attack per severity (penyebut = total severity tsb) ---
    a["top_by_severity"] = {}
    for s in levels:
        sub = df[df["severity"] == s]
        if sub["count"].sum() > 0:
            a["top_by_severity"][s] = top_n_table(sub.groupby("attack_name")["count"].sum(), "Attack Name", n)
    a["top_attacks"] = top_n_table(df.groupby("attack_name")["count"].sum(), "Attack Name", n, denom=total)
    a["attack_detail"] = (df.groupby(["attack_name", "severity", "category"])["count"].sum().reset_index()
                          .sort_values(["count", "attack_name"], ascending=[False, True]).reset_index(drop=True))

    # --- destination (label 'IP - nama aset' bila ada di inventory) ---
    dst = top_n_table(_sum_by(df, "dst_ip"), "Dest", n, denom=total)
    dst["Dest"] = dst["Dest"].map(lambda ip: f"{ip} - {asset_inv[ip]}" if ip in asset_inv else ip)
    a["top_destination"] = dst
    a["top_country"] = top_n_table(_sum_by(df, "src_country"), "Source Country", n, denom=total)

    # --- profil source IP ---
    g = df.assign(_ip=df["src_ip"].fillna(UNKNOWN_LABEL)).groupby("_ip")
    prof = pd.DataFrame({
        "Source IP": g.size().index,
        "Country": g["src_country"].agg(lambda x: x.dropna().mode().iloc[0] if x.notna().any() else UNKNOWN_LABEL).values,
        "Attack Count": g["count"].sum().values,
        "Unique Attack": g["attack_name"].nunique().values,
        "Unique Destination": g["dst_ip"].nunique().values,
        "Critical": g.apply(lambda x: x.loc[x["severity"] == "Critical", "count"].sum()).values,
        "High": g.apply(lambda x: x.loc[x["severity"] == "High", "count"].sum()).values,
        "Top Attack": g.apply(lambda x: x.groupby("attack_name")["count"].sum().idxmax()).values,
    })
    a["source_profile"] = prof.sort_values(["Attack Count", "Source IP"], ascending=[False, True]).reset_index(drop=True)

    # --- kategori, unique, konsentrasi ---
    a["categories"] = top_n_table(df.groupby("category")["count"].sum(), "Category", 99, denom=total)
    a["unique"] = {"source_ip": int(df["src_ip"].nunique()), "destination": int(df["dst_ip"].nunique()),
                   "attack": int(df["attack_name"].nunique()), "country": int(df["src_country"].nunique())}
    p = a["source_profile"]
    top5_ip = float(p["Attack Count"].head(5).sum())
    a["concentration"] = {
        "top1_source_ip": p.iloc[0]["Source IP"] if len(p) else None,
        "top1_source_ip_events": float(p.iloc[0]["Attack Count"]) if len(p) else 0.0,
        "top1_source_ip_pct": float(p.iloc[0]["Attack Count"]) / total * 100 if len(p) and total else 0.0,
        "top5_source_ip_pct": top5_ip / total * 100 if total else 0.0,
        "ips_multi_signature": int((p["Unique Attack"] > 1).sum()),
        "ips_multi_destination": int((p["Unique Destination"] > 1).sum()),
        "ips_with_critical": int((p["Critical"] > 0).sum()),
    }

    if audit is not None:
        _record_audit(audit, a, slide, source_file, filter_desc)
    return a


def _record_audit(audit, a, slide, src, flt):
    audit.record(slide, "raw_records_in_file", a["reconciliation"]["raw_records_in_file"], "", "COUNT(rows)", src)
    audit.record(slide, "total_events", a["total_events"], flt, "SUM(count)", src)
    audit.record(slide, "unique_source_ip", a["unique"]["source_ip"], flt, "NUNIQUE(srcip)", src)
    for _, r in a["severity"].iterrows():
        audit.record(slide, f"severity[{r['Severity']}]", r["Count"], flt + f" AND severity=={r['Severity']}", "SUM(count)", src)
    for s, df in a["top_by_severity"].items():
        for _, r in df.iterrows():
            audit.record(slide, f"attack_{s}[{r['Attack Name']}]", r["Count"],
                         flt + f" AND severity=={s}", "SUM(count) GROUP BY attack" + (" (rank>5 = Others)" if r["Attack Name"] == "Others" else ""), src)
    for name, key, col in (("destination", "top_destination", "Dest"), ("country", "top_country", "Source Country")):
        for _, r in a[key].iterrows():
            audit.record(slide, f"{name}[{r[col]}]", r["Count"], flt, f"SUM(count) GROUP BY {name}", src)


def _env_label(sub):
    envs = sorted({e for e in sub["environment"].dropna().unique() if e != "Unmapped"}) if "environment" in sub else []
    return envs[0] if len(envs) == 1 else None


def compute_ips_sections(df_norm, settings, asset_inv=None, audit=None, source_file=""):
    """Pecah laporan. settings.ips.split_by:
    - "device" (default): satu section per HOSTNAME (kolom device/devname) -> tiap hostname punya snapshot & MoM sendiri.
    - "environment": per environment hasil mapping device -> environment (mode lama).
    - "none": semua hostname digabung ('IPS (All Devices)').
    Tanpa kolom device -> otomatis satu section. Jumlah semua section = total event scope."""
    in_scope, excluded, filter_desc = ips_src.scope_filter(df_norm, settings["ips"]["allowed_actions"])
    raw_total = len(df_norm)
    mode = settings["ips"].get("split_by", "device")
    has_device = "device" in df_norm and df_norm["device"].notna().any()
    if mode == "device" and not has_device:
        mode = "none"
    if mode == "environment" and not ((in_scope["environment"] != "Unmapped").any() if len(in_scope) else False):
        mode = "none"                       # belum ada mapping environment -> jangan menebak
    if mode == "none":
        groups = [("IPS (All Devices)", None, "All Devices", None, in_scope, excluded)]
    elif mode == "environment":
        envs = sorted(in_scope["environment"].unique().tolist())
        groups = [(f"IPS {e}", None, e, e, in_scope[in_scope["environment"] == e], excluded[excluded["environment"] == e]) for e in envs]
    else:
        key = lambda d: d["device"].fillna("(tanpa hostname)")
        hosts = sorted(set(key(in_scope)) | set(key(excluded)))
        groups = []
        for h in hosts:
            sub, exc = in_scope[key(in_scope) == h], excluded[key(excluded) == h]
            env = _env_label(pd.concat([sub, exc]))
            groups.append((f"IPS {h}", h, f"{h} · {env}" if env else h, env, sub, exc))
    sections = []
    for name, host, label, env, sub, exc in groups:
        a = compute_ips_analytics(sub, settings, asset_inv, audit, name, source_file, filter_desc,
                                  raw_records=(raw_total if mode == "none" else len(sub) + len(exc)),
                                  excluded=exc, environment=env)
        a.update({"name": name, "hostname": host, "label": label, "split_by": mode})
        sections.append(a)
    return sections, filter_desc
