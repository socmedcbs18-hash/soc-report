"""SLA MTTR/MTTC/MTTRV per Severity sesuai MOM unit head (semua dihitung dari LOGGED = Created On).

MTTR  = Created -> Active            batas 5 menit
MTTC  = Created -> Contained On      batas = SLA MTTC severity + 5 menit (allowance respons)
MTTRV = Created -> Resolved On       batas = Total Time severity (tabel MOM)
"""
import numpy as np
import pandas as pd

from config.settings import SLA_MTTR_MENIT, SLA_TARGET_MENIT, SLA_PRIORITY_KE_SEVERITY

LEVELS = ["Critical", "High", "Medium", "Low"]


def sla_severity(inc):
    """Severity untuk SLA = Priority tiket Ivanti (0/1 High, 2 Medium, 3 Low; tanpa Critical). Bila Priority kosong,
    pakai kolom Severity (Critical dihitung High). Return (severity, sumber)."""
    n = len(inc)
    sev = pd.Series([None] * n, index=inc.index, dtype=object)
    src = pd.Series(["Tidak diketahui"] * n, index=inc.index, dtype=object)
    if "Priority" in inc.columns:
        pr = pd.to_numeric(inc["Priority"], errors="coerce").map(SLA_PRIORITY_KE_SEVERITY)
        m = pr.notna()
        sev[m] = pr[m]
        src[m] = "Priority Ivanti"
    if "Severity" in inc.columns:
        v = inc["Severity"].astype(str).str.strip().str.lower()
        v = v.replace({"critical": "high", "informational": "low", "info": "low", "notice": "low"})
        m2 = sev.isna() & v.isin(["high", "medium", "low"])
        sev[m2] = v[m2].str.title()
        src[m2] = "Severity (Priority kosong; Critical dihitung High)"
    return sev, src


def target_series(sev, key):
    """Batas SLA (menit, dari Logged) per tiket. key: 'mttc' (sudah + allowance MTTR) atau 'mttrv' (total)."""
    if key == "mttc":
        d = {k: v["mttc"] + SLA_MTTR_MENIT for k, v in SLA_TARGET_MENIT.items()}
    else:
        d = {k: v["total"] for k, v in SLA_TARGET_MENIT.items()}
    return sev.map(d).astype(float)


def compute_sla_flags(inc, dur):
    """inc: DataFrame tiket; dur: hasil compute_state_durations (MTTR/MTTC/MTTRV dalam detik, dari Logged)."""
    out = pd.DataFrame(index=inc.index)
    sev, src = sla_severity(inc)
    out["_SLA_Severity"], out["_SLA_Severity_Sumber"] = sev, src
    out["_Target_MTTR_menit"] = float(SLA_MTTR_MENIT)
    out["_Target_MTTC_menit"] = target_series(sev, "mttc")
    out["_Target_MTTRV_menit"] = target_series(sev, "mttrv")
    mttr, mttc, mttrv = dur["MTTR_sec"] / 60, dur["MTTC_sec"] / 60, dur["MTTRV_sec"] / 60
    out["_MTTR_menit"], out["_MTTC_menit"], out["_MTTRV_menit"] = mttr, mttc, mttrv
    out["_Breach_MTTR"] = (mttr > out["_Target_MTTR_menit"]).fillna(False)
    out["_Breach_MTTC"] = (mttc > out["_Target_MTTC_menit"]).fillna(False)
    out["_Breach_MTTRV"] = (mttrv > out["_Target_MTTRV_menit"]).fillna(False)
    out["_Breach_Any"] = out["_Breach_MTTR"] | out["_Breach_MTTC"] | out["_Breach_MTTRV"]
    # sisa waktu containment setelah respons (contoh MOM: batas 35, MTTR 7 -> 28 menit)
    out["_MTTC_Sisa_setelah_Active_menit"] = (out["_Target_MTTC_menit"] - mttr).where(mttr.notna())
    jenis = []
    for a, b, c in zip(out["_Breach_MTTR"], out["_Breach_MTTC"], out["_Breach_MTTRV"]):
        jenis.append(", ".join(n for n, f in (("MTTR", a), ("MTTC", b), ("MTTRV", c)) if f))
    out["_Jenis_Breach"] = jenis
    return out


def build_breach_tables(inc, id_col="Incident", name_col="Summary"):
    """inc: tiket dengan kolom hasil compute_sla_flags. Return (detail, per_insiden)."""
    b = inc[inc["_Breach_Any"]].copy()
    if b.empty:
        cols = ["Tiket", "Insiden", "Severity", "Jenis_Breach", "MTTR_menit", "MTTC_menit", "MTTRV_menit",
                "Batas_MTTC_menit", "Batas_MTTRV_menit", "Kelebihan_terbesar_menit", "Owner", "Created On"]
        return pd.DataFrame(columns=cols), pd.DataFrame(columns=["Insiden", "Severity", "Jumlah_Breach", "MTTR", "MTTC", "MTTRV"])
    ex = pd.concat([
        (b["_MTTR_menit"] - b["_Target_MTTR_menit"]).where(b["_Breach_MTTR"]),
        (b["_MTTC_menit"] - b["_Target_MTTC_menit"]).where(b["_Breach_MTTC"]),
        (b["_MTTRV_menit"] - b["_Target_MTTRV_menit"]).where(b["_Breach_MTTRV"]),
    ], axis=1).max(axis=1)
    det = pd.DataFrame({
        "Tiket": b[id_col].astype(str) if id_col in b.columns else b.index.astype(str),
        "Insiden": b[name_col].astype(str) if name_col in b.columns else "",
        "Severity": b["_SLA_Severity"].fillna("Tidak diketahui"),
        "Jenis_Breach": b["_Jenis_Breach"],
        "MTTR_menit": b["_MTTR_menit"].round(1),
        "MTTC_menit": b["_MTTC_menit"].round(1),
        "MTTRV_menit": b["_MTTRV_menit"].round(1),
        "Batas_MTTC_menit": b["_Target_MTTC_menit"],
        "Batas_MTTRV_menit": b["_Target_MTTRV_menit"],
        "Kelebihan_terbesar_menit": ex.round(1),
        "Owner": b["Owner"].astype(str) if "Owner" in b.columns else "",
        "Created On": b["Created On"] if "Created On" in b.columns else pd.NaT,
    })
    det = det.sort_values("Kelebihan_terbesar_menit", ascending=False).reset_index(drop=True)
    g = det.assign(_a=b["_Breach_MTTR"].values, _b=b["_Breach_MTTC"].values, _c=b["_Breach_MTTRV"].values) \
        .groupby(["Insiden", "Severity"]).agg(Jumlah_Breach=("Tiket", "count"), MTTR=("_a", "sum"),
                                              MTTC=("_b", "sum"), MTTRV=("_c", "sum")).reset_index()
    per = g.sort_values("Jumlah_Breach", ascending=False).reset_index(drop=True)
    return det, per


def build_p95_table(inc):
    """Persentil ke-95 MTTR/MTTC/MTTRV (menit, dari Logged) per Severity untuk SEMUA tiket (permintaan CTO).
    MTTC hanya tiket yang punya Contained On. Status = apakah P95 masih dalam batas SLA."""
    from config.settings import SLA_TARGET_MENIT
    rows = []
    groups = [(k, inc[inc["_SLA_Severity"].fillna("Tidak diketahui") == k]) for k in LEVELS + ["Tidak diketahui"]]
    groups.append(("SEMUA", inc))
    for k, g in groups:
        if len(g) == 0:
            continue
        t = SLA_TARGET_MENIT.get(k, {})
        lim = {"mttr": float(SLA_MTTR_MENIT), "mttc": (t["mttc"] + SLA_MTTR_MENIT) if t else np.nan,
               "mttrv": float(t["total"]) if t else np.nan}
        row = {"Severity": k, "Jumlah_Tiket": len(g)}
        for name, col in [("MTTR", "MTTR_sec"), ("MTTC", "MTTC_sec"), ("MTTRV", "MTTRV_sec")]:
            x = pd.to_numeric(g[col], errors="coerce").dropna() / 60
            p95 = float(np.percentile(x, 95)) if len(x) else np.nan
            row[f"Tiket_{name}"] = int(len(x))
            row[f"P95_{name}_menit"] = round(p95, 1) if len(x) else None
            row[f"Batas_{name}_menit"] = lim[name.lower()] if k != "SEMUA" else None
            row[f"Status_{name}"] = ("-" if k == "SEMUA" or not len(x) or np.isnan(lim[name.lower()])
                                     else ("Dalam batas" if p95 <= lim[name.lower()] else "Melewati batas"))
        rows.append(row)
    return pd.DataFrame(rows)


def build_ticket_flags(inc, id_col="Incident", name_col="Summary"):
    """Satu baris per tiket dengan flag breach, untuk rasio breach vs tidak breach per insiden."""
    return pd.DataFrame({
        "Tiket": inc[id_col].astype(str) if id_col in inc.columns else inc.index.astype(str),
        "Insiden": inc[name_col].astype(str) if name_col in inc.columns else "",
        "Severity": inc["_SLA_Severity"].fillna("Tidak diketahui"),
        "Breach_MTTR": inc["_Breach_MTTR"].astype(bool), "Breach_MTTC": inc["_Breach_MTTC"].astype(bool),
        "Breach_MTTRV": inc["_Breach_MTTRV"].astype(bool),
    }).reset_index(drop=True)


def incident_breach_ratio(flags, severities=None, jenis=None, min_tiket=1):
    """Per insiden: total tiket, tiket breach, tidak breach, % (permintaan CTO). jenis: subset ['MTTR','MTTC','MTTRV']."""
    f = flags
    if severities is not None:
        f = f[f["Severity"].isin(severities)]
    jenis = jenis or ["MTTR", "MTTC", "MTTRV"]
    if len(f) == 0:
        return pd.DataFrame(columns=["Insiden", "Severity", "Total_Tiket", "Tiket_Breach", "Tiket_Tidak_Breach",
                                     "%_Breach", "%_Tidak_Breach"])
    br = np.zeros(len(f), dtype=bool)
    for j in jenis:
        br |= f[f"Breach_{j}"].values
    g = f.assign(_b=br).groupby(["Insiden", "Severity"]).agg(Total_Tiket=("Tiket", "count"), Tiket_Breach=("_b", "sum")).reset_index()
    g["Tiket_Breach"] = g["Tiket_Breach"].astype(int)
    g["Tiket_Tidak_Breach"] = g["Total_Tiket"] - g["Tiket_Breach"]
    g["%_Breach"] = (100 * g["Tiket_Breach"] / g["Total_Tiket"]).round(1)
    g["%_Tidak_Breach"] = (100 - g["%_Breach"]).round(1)
    return g[g["Total_Tiket"] >= min_tiket]
