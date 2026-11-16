"""Kualitas deteksi: True Positive vs False Positive per rule (permintaan CTO: TP harus lebih banyak dari FP)."""
import pandas as pd

from core.tp_detail import rule_name


def _tri(s):
    s = str(s).strip().lower()
    return "TP" if s.startswith("true") else ("FP" if s.startswith("false") else "Belum")


def rekomendasi(total_fp, pct_fp):
    if total_fp >= 5 and pct_fp >= 80:
        return "Tuning atau nonaktifkan: hampir semua tiket False Positive"
    if pct_fp >= 50:
        return "Tuning kondisi/threshold: False Positive lebih banyak dari True Positive"
    if total_fp >= 10:
        return "Pertahankan; kurangi False Positive (kecualikan sumber sah) atau turunkan severity"
    return "Pantau"


def build_fp_analysis(df, name_col="Summary"):
    """Return (summary dict, per_rule DataFrame). df: tiket (kolom Triage). Persen dihitung dari tiket yang sudah di-triage."""
    empty = pd.DataFrame(columns=["No", "Insiden", "Total", "False_Positive", "True_Positive", "Belum_Triage",
                                  "%_FP", "%_dari_semua_FP", "Kumulatif_%", "Rekomendasi"])
    if df is None or len(df) == 0 or "Triage" not in df.columns:
        return {}, empty
    d = df.copy()
    if "_Test_Ticket" in d.columns:
        d = d[~d["_Test_Ticket"].fillna(False).astype(bool)]
    d["_t"] = d["Triage"].map(_tri)
    d["_rule"] = d[name_col].map(rule_name)
    tp, fp, bl = int((d["_t"] == "TP").sum()), int((d["_t"] == "FP").sum()), int((d["_t"] == "Belum").sum())
    triaged = tp + fp
    summ = {"total": len(d), "tp": tp, "fp": fp, "belum": bl,
            "pct_tp": round(100 * tp / triaged, 1) if triaged else None,
            "pct_fp": round(100 * fp / triaged, 1) if triaged else None,
            "fp_dipotong_agar_tp_lebih_banyak": max(0, fp - tp + 1)}
    g = d.groupby("_rule").agg(Total=("_t", "size"), False_Positive=("_t", lambda s: int((s == "FP").sum())),
                               True_Positive=("_t", lambda s: int((s == "TP").sum())),
                               Belum_Triage=("_t", lambda s: int((s == "Belum").sum()))).reset_index()
    tri = g["False_Positive"] + g["True_Positive"]
    g["%_FP"] = (100 * g["False_Positive"] / tri.where(tri > 0)).round(1)
    g = g.sort_values(["False_Positive", "Total"], ascending=False).reset_index(drop=True)
    g["%_dari_semua_FP"] = (100 * g["False_Positive"] / fp).round(1) if fp else 0.0
    g["Kumulatif_%"] = g["%_dari_semua_FP"].cumsum().round(1)
    g["Rekomendasi"] = [rekomendasi(a, b if pd.notna(b) else 0) for a, b in zip(g["False_Positive"], g["%_FP"])]
    g = g.rename(columns={"_rule": "Insiden"})
    g.insert(0, "No", g.index + 1)
    return summ, g


def simulate_reduction(per_rule, summ, top_n, reduksi_pct):
    """Perkiraan: FP dari top_n rule teratas turun reduksi_pct% (TP dianggap tetap). Bukan hasil tes."""
    if not summ or per_rule is None or len(per_rule) == 0:
        return {}
    cut = per_rule.head(top_n)["False_Positive"].sum() * reduksi_pct / 100
    fp2 = summ["fp"] - cut
    tp2 = summ["tp"]
    return {"fp_baru": int(round(fp2)), "tp": tp2, "pct_fp_baru": round(100 * fp2 / (fp2 + tp2), 1) if (fp2 + tp2) else None,
            "tp_lebih_banyak": bool(tp2 > fp2), "tiket_berkurang": int(round(cut))}
