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
    """Severity untuk SLA: kolom Severity bila baku, selain itu Priority Ivanti. Return (severity, sumber)."""
    n = len(inc)
    sev = pd.Series([None] * n, index=inc.index, dtype=object)
    src = pd.Series(["Tidak diketahui"] * n, index=inc.index, dtype=object)
    if "Severity" in inc.columns:
        v = inc["Severity"].astype(str).str.strip().str.lower()
        m = v.isin(["critical", "high", "medium", "low"])
        sev[m] = v[m].str.title()
        src[m] = "Severity"
        m2 = v.isin(["informational", "info", "notice"])
        sev[m2] = "Low"
        src[m2] = "Severity (Informational dianggap Low)"
    if "Priority" in inc.columns:
        pr = pd.to_numeric(inc["Priority"], errors="coerce").map(SLA_PRIORITY_KE_SEVERITY)
        m3 = sev.isna() & pr.notna()
        sev[m3] = pr[m3]
        src[m3] = "Priority (Severity kosong)"
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
