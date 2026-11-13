"""Tahap Kill Chain berbasis HASIL investigasi (Triage + Cause Code), bukan hanya nama rule.

Prinsip (standar Lockheed Martin Kill Chain / MITRE ATT&CK):
- Kill Chain menggambarkan progres AKTIVITAS PENYERANG. Tiket False Positive bukan aktivitas serangan,
  jadi tidak dihitung sebagai tahap apa pun (label rule asli disimpan di _KC_Potensial / _MITRE_Potensial).
- Cause Code 'Prevented' (diisi analyst; di data Sept-Okt hanya pada tiket yang belum diberi Triage) = serangan dicegah sebelum berdampak: tahap dibatasi sampai
  Delivery (percobaan), tidak dihitung Exploitation/Installation/C2/AOO.
- True Positive 'Breach - Reported' atau TP tanpa Cause Code: label rule dipertahankan.
- Triage kosong (belum di-triage): label rule dipertahankan, ditandai belum terkonfirmasi, KECUALI Actions on Objectives
  (tujuan tercapai) yang butuh konfirmasi True Positive / Breach - Reported.
"""
import pandas as pd

LATE = {"Exploitation", "Installation", "Privilege Escalation", "Command & Control", "Actions on Objectives"}
ORDER = ["Reconnaissance", "Weaponization", "Delivery"]


def _toks(x):
    return [t.strip() for t in str(x).strip("[]").split(",") if t.strip()]


def _fmt(items):
    return "[" + ", ".join(items) + "]" if items else "[]"


def refine_outcome(triage, cause, mitre, kc):
    """Return (mitre, kc, basis, changed)."""
    tri = str(triage or "").strip().lower()
    cc = str(cause or "").strip().lower()
    st = _toks(kc)
    if tri.startswith("false"):
        return "[]", "[]", "False Positive - bukan aktivitas serangan, tidak dihitung di Kill Chain/MITRE", True
    if cc.startswith("prevented"):
        cap = [x for x in st if x not in LATE]
        if any(x in LATE for x in st) and "Delivery" not in cap:
            cap.append("Delivery")
        return mitre, _fmt(cap), "Cause Code Prevented: serangan dicegah, tahap dibatasi sampai Delivery", cap != st
    if cc.startswith("breach"):
        return mitre, kc, "Cause Code Breach - Reported: tahap sesuai label rule", False
    if tri.startswith("true"):
        return mitre, kc, "True Positive tanpa Cause Code: tahap sesuai label rule (belum tentu tercapai)", False
    if "Actions on Objectives" in st:
        # AOO = tujuan penyerang TERCAPAI (data keluar/dampak). Tanpa konfirmasi analyst tidak boleh diklaim.
        sisa = [x for x in st if x != "Actions on Objectives"]
        return mitre, _fmt(sisa), "Belum di-triage: Actions on Objectives butuh konfirmasi (True Positive / Breach - Reported), tidak dihitung", True
    return mitre, kc, "Belum di-triage dan tanpa Cause Code: label rule dipertahankan, belum terkonfirmasi", False


def apply_outcome(df, mitre_col, kc_col):
    if "Triage" not in df.columns:
        return df
    cause = df["Cause Code"] if "Cause Code" in df.columns else pd.Series([""] * len(df), index=df.index)
    df["_KC_Potensial"] = df[kc_col].values
    df["_MITRE_Potensial"] = df[mitre_col].values
    m, k, b = [], [], []
    for tri, cc, mi, kc in zip(df["Triage"].values, cause.values, df[mitre_col].values, df[kc_col].values):
        a, c, d, _ = refine_outcome(tri, cc, mi, kc)
        m.append(a); k.append(c); b.append(d)
    df[mitre_col] = m
    df[kc_col] = k
    df["_Basis_Hasil"] = b
    return df
