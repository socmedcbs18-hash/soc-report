"""
CyNET Compliance Loader
=========================================================
Baca file Excel Cynet bulanan (sheet Endpoints + Servers) dan normalisasi
ke skema kanonik. MODUL TERPISAH dari SOC.

TEMUAN DARI INSPEKSI 6 FILE ASLI (Maret-Agustus 2026) - kolom TIDAK
KONSISTEN antar bulan:
- Kolom hostname: "Hostname" (Maret), "Endpoint" (April-Agustus, mayoritas),
  "Servers" (Juni-sheet Server, 1x anomali penamaan).
- Kolom "OS": baru ada mulai Agustus - bulan sebelumnya TIDAK punya kolom
  ini (JANGAN dipaksa ada, tampilkan "Unknown" kalau tidak ada).
- Sheet "ACTION_REQUIRED" dan "Remediation Plan": DIABAIKAN sepenuhnya
  sesuai instruksi - tidak dipakai untuk kalkulasi/chart/summary apapun.
"""

import re

import pandas as pd

# Ambang compliance resmi sesuai SOP - Agent Version >= 4.30 dianggap
# Compliant, di bawah itu Non-Compliant.
COMPLIANCE_THRESHOLD = (4, 30)

# Variasi nama kolom hostname yang ditemukan di data asli - urutan
# menentukan prioritas kalau lebih dari 1 kandidat muncul (seharusnya
# tidak pernah terjadi, tapi jaga-jaga).
HOSTNAME_COLUMN_CANDIDATES = ["Hostname", "Endpoint", "Servers", "Host", "Device"]


def parse_agent_version(v):
    """Parse 'Agent Version' jadi tuple (major, minor) untuk perbandingan
    NUMERIK yang benar - BUKAN string comparison (spec eksplisit
    memperingatkan: '4.30' vs '4.9' sebagai STRING salah bandingnya,
    padahal 4.30 > 4.9 secara version number).

    Return None kalau version kosong/tidak bisa diparse - JANGAN
    dianggap Compliant secara default (sesuai instruksi eksplisit)."""
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = str(v).strip()
    if not s or s.lower() in ("nan", "none", "unknown", ""):
        return None
    parts = s.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except (ValueError, IndexError):
        return None


def is_compliant_version(version_tuple):
    """True/False/None (None = versi tidak valid/kosong, BUKAN False -
    supaya bisa dibedakan dari Non-Compliant asli di data quality report)."""
    if version_tuple is None:
        return None
    return version_tuple >= COMPLIANCE_THRESHOLD


def _find_hostname_column(df):
    for cand in HOSTNAME_COLUMN_CANDIDATES:
        if cand in df.columns:
            return cand
    return None


def normalize_cynet_columns(df, asset_type):
    """Normalisasi 1 sheet (Endpoints ATAU Servers) ke skema kanonik.

    asset_type: "Endpoint" atau "Server" - ditentukan dari NAMA SHEET oleh
    caller (bukan ditebak dari isi data)."""
    df = df.copy()

    host_col = _find_hostname_column(df)
    if host_col is None:
        raise KeyError(
            f"Tidak ditemukan kolom hostname (dicoba: {HOSTNAME_COLUMN_CANDIDATES}) "
            f"di sheet {asset_type}. Kolom yang ada: {list(df.columns)}"
        )

    # Normalisasi identifier device sesuai instruksi (bagian 14):
    # trim whitespace, lowercase untuk MATCHING (tapi simpan versi asli
    # untuk ditampilkan) - supaya beda kapitalisasi/spasi TIDAK dianggap
    # device baru saat month-to-month matching.
    df["Hostname_Raw"] = df[host_col].astype(str).str.strip()
    df["Hostname_Key"] = df["Hostname_Raw"].str.lower()

    if "IP" in df.columns:
        df["IP"] = df["IP"].astype(str).str.strip()

    df["OS"] = df["OS"].astype(str).str.strip() if "OS" in df.columns else "Unknown"
    df["OS"] = df["OS"].replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"})

    df["Agent_Version_Raw"] = df["Agent Version"] if "Agent Version" in df.columns else None
    df["Agent_Version_Parsed"] = df["Agent_Version_Raw"].apply(parse_agent_version)

    # Compliance dihitung ULANG dari Agent Version (source of truth resmi
    # sesuai instruksi) - Is_Compliant dari file MENTAH TIDAK DIPAKAI untuk
    # kalkulasi apapun, cuma disimpan sebagai referensi cross-check.
    df["Is_Compliant_Calculated"] = df["Agent_Version_Parsed"].apply(is_compliant_version)
    df["Is_Compliant_Raw_File"] = df["Is_Compliant"] if "Is_Compliant" in df.columns else None

    for col in ["First Seen", "Last Seen"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", format="mixed")

    df["Asset_Type"] = asset_type

    # Hapus duplikat hostname dalam sheet yang sama (data quality) - simpan
    # baris PERTAMA, catat berapa yang dibuang untuk data quality report.
    n_before = len(df)
    df = df.drop_duplicates(subset=["Hostname_Key"], keep="first")
    n_dropped_dup = n_before - len(df)

    keep_cols = ["Hostname_Raw", "Hostname_Key", "IP", "OS", "Agent_Version_Raw",
                 "Agent_Version_Parsed", "Is_Compliant_Calculated", "Is_Compliant_Raw_File",
                 "First Seen", "Last Seen", "Asset_Type"]
    keep_cols = [c for c in keep_cols if c in df.columns]
    result = df[keep_cols].reset_index(drop=True)
    result.attrs["n_dropped_duplicates"] = n_dropped_dup
    return result


def load_cynet_excel(uploaded_file):
    """Baca 1 file Excel bulanan Cynet (sheet Endpoints + Servers) dari
    Streamlit file_uploader. Sheet 'ACTION_REQUIRED' dan 'Remediation Plan'
    DIABAIKAN SEPENUHNYA - tidak pernah dibaca sama sekali.

    Return: (data_gabungan, data_quality_report)"""
    xl = pd.ExcelFile(uploaded_file)

    # Cari nama sheet Endpoints/Servers - toleransi variasi kapitalisasi/
    # bentuk tunggal-jamak ("Endpoint"/"Endpoints", "Server"/"Servers")
    # karena belum ada kepastian penamaan akan selalu sama persis.
    def _find_sheet(candidates):
        for c in candidates:
            for actual in xl.sheet_names:
                if actual.strip().lower() == c.lower():
                    return actual
        return None

    ep_sheet = _find_sheet(["Endpoints", "Endpoint", "endpoint"])
    sv_sheet = _find_sheet(["Servers", "Server", "servers"])

    if ep_sheet is None and sv_sheet is None:
        raise KeyError(
            f"Tidak ditemukan sheet Endpoints maupun Servers. Sheet yang ada: {xl.sheet_names}"
        )

    frames = []
    dq_report = []

    if ep_sheet is not None:
        df_ep_raw = pd.read_excel(xl, sheet_name=ep_sheet)
        df_ep = normalize_cynet_columns(df_ep_raw, "Endpoint")
        frames.append(df_ep)
        dq_report.append({"Sheet": ep_sheet, "Baris_Mentah": len(df_ep_raw),
                           "Duplikat_Hostname_Dibuang": df_ep.attrs.get("n_dropped_duplicates", 0)})
    else:
        dq_report.append({"Sheet": "Endpoints", "Baris_Mentah": 0, "Duplikat_Hostname_Dibuang": 0})

    if sv_sheet is not None:
        df_sv_raw = pd.read_excel(xl, sheet_name=sv_sheet)
        df_sv = normalize_cynet_columns(df_sv_raw, "Server")
        frames.append(df_sv)
        dq_report.append({"Sheet": sv_sheet, "Baris_Mentah": len(df_sv_raw),
                           "Duplikat_Hostname_Dibuang": df_sv.attrs.get("n_dropped_duplicates", 0)})
    else:
        dq_report.append({"Sheet": "Servers", "Baris_Mentah": 0, "Duplikat_Hostname_Dibuang": 0})

    combined = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()

    # Cek device yang muncul di KEDUA sheet Endpoint & Server (data quality
    # issue - sesuai instruksi bagian 20) - berdasarkan Hostname_Key yang
    # sudah dinormalisasi.
    cross_overlap = 0
    if len(frames) == 2:
        ep_keys = set(frames[0]["Hostname_Key"])
        sv_keys = set(frames[1]["Hostname_Key"])
        cross_overlap = len(ep_keys & sv_keys)

    dq_df = pd.DataFrame(dq_report)
    dq_df.attrs["cross_overlap_endpoint_server"] = cross_overlap

    # Missing/invalid Agent Version - data quality insight (bagian 15)
    n_invalid_version = combined["Agent_Version_Parsed"].isna().sum() if len(combined) > 0 else 0
    dq_df.attrs["n_invalid_version"] = int(n_invalid_version)

    return combined, dq_df
