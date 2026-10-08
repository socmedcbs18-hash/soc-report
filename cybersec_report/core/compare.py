"""Perbandingan dua snapshot IPS (bulan berbeda, hostname sama ATAU berbeda; syaratnya sama-sama IPS).
Murni dari data snapshot: tidak ada angka yang dikarang. Baris yang tidak ada di salah satu sisi ditandai New/Gone."""
import pandas as pd

SEV_ORDER = ["Critical", "High", "Medium", "Low"]
_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def pick_section(vm, name=None):
    secs = vm["sections"]
    if name:
        for a in secs:
            if a["name"] == name:
                return a
    return secs[0]


def _status(a, b, stable_pct):
    if a == 0 and b == 0:
        return "→ Stable"
    if a == 0:
        return "★ New"
    if b == 0:
        return "✕ Gone"
    pct = (b - a) / a * 100.0
    return "→ Stable" if abs(pct) < stable_pct else ("↑ Increase" if b > a else "↓ Decrease")


def _delta_table(df, key_cols, stable_pct):
    df["Δ"] = df["B"] - df["A"]
    df["Δ%"] = [((b - a) / a * 100.0) if a else None for a, b in zip(df["A"], df["B"])]
    df["Trend"] = [_status(a, b, stable_pct) for a, b in zip(df["A"], df["B"])]
    return df


def compare_sections(a, b, stable_pct=5.0):
    sa, sb = a["severity"].set_index("Severity")["Count"], b["severity"].set_index("Severity")["Count"]
    rows = [("Total events", a["total_events"], b["total_events"])]
    rows += [(s, float(sa.get(s, 0)), float(sb.get(s, 0))) for s in SEV_ORDER]
    rows += [("Unique source IP", a["unique"]["source_ip"], b["unique"]["source_ip"]),
             ("Unique attack", a["unique"]["attack"], b["unique"]["attack"]),
             ("Unique country", a["unique"]["country"], b["unique"]["country"])]
    kpi = _delta_table(pd.DataFrame(rows, columns=["Metric", "A", "B"]).astype({"A": float, "B": float}), ["Metric"], stable_pct)

    def attacks(x):
        d = x["attack_detail"]
        g = d.groupby("attack_name").agg(count=("count", "sum"), severity=("severity", lambda s: min(s, key=lambda v: _RANK.get(v, 9))))
        return g
    ga, gb = attacks(a), attacks(b)
    att = pd.DataFrame({"A": ga["count"], "B": gb["count"]}).fillna(0.0)
    att["Severity"] = gb["severity"].combine_first(ga["severity"])
    att = att.reset_index().rename(columns={"attack_name": "Attack"})
    att = _delta_table(att, ["Attack"], stable_pct)
    att["_r"] = att["Severity"].map(lambda v: _RANK.get(v, 9))
    att = att.sort_values(["_r", "B", "Attack"], ascending=[True, False, True]).drop(columns="_r").reset_index(drop=True)

    pa, pb = a["source_profile"], b["source_profile"]
    ctry = pd.DataFrame({"A": pa.groupby("Country")["Attack Count"].sum(), "B": pb.groupby("Country")["Attack Count"].sum()}).fillna(0.0)
    ctry = _delta_table(ctry.reset_index().rename(columns={"Country": "Country"}), ["Country"], stable_pct)
    ctry = ctry.sort_values(["B", "A"], ascending=False).reset_index(drop=True)

    ips = pd.merge(pa[["Source IP", "Country", "Attack Count"]].rename(columns={"Attack Count": "A"}),
                   pb[["Source IP", "Country", "Attack Count"]].rename(columns={"Attack Count": "B"}),
                   on="Source IP", how="outer", suffixes=("_a", "_b"))
    ips["Country"] = ips["Country_b"].combine_first(ips["Country_a"])
    ips = ips[["Source IP", "Country", "A", "B"]].fillna({"A": 0.0, "B": 0.0})
    ips["Status"] = ["Persisten (muncul di kedua periode)" if x and y else ("Baru di B" if y else "Hilang di B") for x, y in zip(ips["A"], ips["B"])]
    ips = ips.sort_values(["B", "A"], ascending=False).reset_index(drop=True)

    warnings = []
    if a.get("hostname") != b.get("hostname"):
        warnings.append(f"Hostname berbeda ({a.get('hostname') or a['name']} vs {b.get('hostname') or b['name']}): "
                        "perbandingan tetap valid secara angka, tetapi bukan tren satu perangkat.")
    return {"kpi": kpi, "attacks": att, "countries": ctry, "source_ips": ips, "warnings": warnings}

