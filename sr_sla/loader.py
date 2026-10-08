"""
SLA SR Security Operations - Loader
=========================================================
Baca & normalisasi export Service Request bulanan (sheet 'Cybersecurity
L2 only', dikonfirmasi dari file sample SR_Updated_Cyber.xlsx - 4718 baris
Jan-Sep 2026, 23 kolom). MODUL TERPISAH dari SOC/Cynet/IOC - tidak import
apapun dari modul lain, sesuai prinsip module isolation proyek ini.

TEMUAN DARI INSPEKSI FILE ASLI:
- Kolom 'Days'/'Hours'/'Minutes'/'Seconds' = breakdown durasi resolusi
  (ResolvedOn - CreatedOn), diverifikasi cocok persis ke detik.
- 'Response Meet/Breach' dan 'Resolution Meet/Breach' = 2 dimensi SLA
  TERPISAH (Response jarang breach ~0.3%, Resolution lebih sering ~14.7%).
- 'Technician' punya missing value (~5%, tiket belum ditugaskan) -
  DITANDAI 'Unassigned', bukan dibuang diam-diam.
- 'OwnerTeam' TIDAK dipakai untuk filter - nama sheet 'Cybersecurity L2
  only' sudah mengindikasikan data ini scope tim Security Operations,
  sesuai konfirmasi user 'Technician' adalah kolom individu tim SOC.
"""

import pandas as pd

SHEET_NAME_CANDIDATES = ["Cybersecurity L2 only", "cybersecurity l2 only"]


def _find_sheet(xl):
    for cand in SHEET_NAME_CANDIDATES:
        for actual in xl.sheet_names:
            if actual.strip().lower() == cand.lower():
                return actual
    # Fallback: kalau nama sheet beda dari contoh, pakai sheet PERTAMA -
    # lebih baik daripada gagal total, TAPI ditandai jelas di caller.
    return xl.sheet_names[0] if xl.sheet_names else None


def normalize_sr_columns(df):
    """Normalisasi 1 file SR bulanan ke skema kanonik."""
    df = df.copy()

    for col in ["CreatedOn", "Approved_On", "ResolvedOn"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    # Technician kosong -> 'Unassigned' (BUKAN dibuang - tiket ini tetap
    # relevan buat hitungan total SR, cuma tidak bisa dikaitkan ke individu).
    if "Technician" in df.columns:
        df["Technician"] = df["Technician"].fillna("Unassigned").astype(str).str.strip()
        df["Technician"] = df["Technician"].replace({"": "Unassigned", "nan": "Unassigned"})
    else:
        df["Technician"] = "Unassigned"

    # Durasi resolusi dalam JAM (desimal) - dihitung dari Days/Hours/Minutes/Seconds
    # kalau ada (sudah diverifikasi akurat), fallback ke ResolvedOn-CreatedOn
    # kalau kolom itu tidak ada (robustness untuk format masa depan).
    if all(c in df.columns for c in ["Days", "Hours", "Minutes", "Seconds"]):
        df["Resolution_Duration_Hours"] = (
            df["Days"].fillna(0) * 24 + df["Hours"].fillna(0)
            + df["Minutes"].fillna(0) / 60 + df["Seconds"].fillna(0) / 3600
        )
    elif "CreatedOn" in df.columns and "ResolvedOn" in df.columns:
        df["Resolution_Duration_Hours"] = (
            (df["ResolvedOn"] - df["CreatedOn"]).dt.total_seconds() / 3600
        )
    else:
        df["Resolution_Duration_Hours"] = None

    for col in ["Response Meet/Breach", "Resolution Meet/Breach"]:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.upper()

    keep_cols = [
        "ServiceReqNumber", "Requestor", "Service", "ServiceRequestName",
        "Type Of Request", "Source", "CreatedOn", "ResolvedOn",
        "Resolution_Duration_Hours", "Technician", "OwnerTeam", "Status",
        "Response Meet/Breach", "Resolution Meet/Breach",
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols].reset_index(drop=True)


def load_sr_excel(uploaded_file):
    """Baca 1 file Excel SR bulanan. Return: (data_normalized, sheet_used, dq_report)."""
    xl = pd.ExcelFile(uploaded_file)
    sheet_used = _find_sheet(xl)
    if sheet_used is None:
        raise KeyError("File Excel ini tidak punya sheet sama sekali.")

    raw = pd.read_excel(xl, sheet_name=sheet_used)
    n_before = len(raw)
    data = normalize_sr_columns(raw)

    dq = {
        "sheet_used": sheet_used,
        "sheet_matched_expected": sheet_used.strip().lower() in [s.lower() for s in SHEET_NAME_CANDIDATES],
        "total_rows": n_before,
        "unassigned_technician": int((data["Technician"] == "Unassigned").sum()) if "Technician" in data.columns else 0,
        "missing_resolved_on": int(data["ResolvedOn"].isna().sum()) if "ResolvedOn" in data.columns else 0,
    }
    return data, dq
