import re
from config.constants import REMOVE_PREFIX, REMOVE_SUFFIX, REMOVE_TAG_PATTERN


def clean_rule_name(text):
    """
    Normalisasi nama rule untuk keperluan matching Splunk <-> Ivanti <-> Master.

    Kenapa tidak cukup pakai remove_prefix()/remove_suffix() versi .replace() biasa:
    - .replace() tidak "anchored" (bisa menghapus substring di tengah kalimat kalau
      kebetulan match), dan tidak case-insensitive.
    - Suffix seperti "- Severity 3" harus dihapus SEBELUM "- Rule", karena pola aslinya
      "... - Rule - Rule - Severity 3" -> kalau "- Rule" distrip duluan, "- Severity 3"
      masih nempel di ujung dan bikin match gagal.
    - Rule dari ESV2 (lama, sudah pensiun) dan ESV3 (baru) punya isi sama tapi tag beda
      -> harus distandarkan ke satu tag sebelum dibandingkan.
    """
    if text is None:
        return ""

    s = str(text)

    # 1) Tag environment ESV2/ESV3 -> disamakan
    s = re.sub(REMOVE_TAG_PATTERN, "[ESV]", s, flags=re.IGNORECASE)

    # 2) Prefix kategori di awal string (case-insensitive, anchored ke awal)
    for prefix in REMOVE_PREFIX:
        s = re.sub(r"^\s*" + re.escape(prefix), "", s, flags=re.IGNORECASE).strip()

    s = re.sub(r"^\[ESV\]\s*-\s*", "[ESV] ", s)  # rapikan "[ESV] - X" -> "[ESV] X"
    s = s.rstrip(".")

    # 3) Suffix severity dulu, baru suffix "- Rule" (bisa berulang), anchored ke akhir
    s = re.sub(r"\s*-\s*Severity\s*\d+\s*$", "", s, flags=re.IGNORECASE)
    for _ in range(3):
        s = re.sub(r"\s*-\s*Rule\.?\s*$", "", s, flags=re.IGNORECASE)

    s = re.sub(r"_+\s*$", "", s)          # trailing underscore sisa penulisan Ivanti
    s = re.sub(r"\s+", " ", s).strip().lower()

    return s


def clean_string(text):

    if text is None:
        return ""

    text = str(text)

    text = text.strip()

    text = re.sub(r"\s+"," ",text)

    return text


def remove_prefix(text,prefix):

    for p in prefix:

        text = text.replace(p,"")

    return clean_string(text)


def remove_suffix(text,suffix):

    for s in suffix:

        text = text.replace(s,"")

    return clean_string(text)


def read_any_table(path_or_buffer, sheet_name=None, filename_hint=None):
    """Baca file .xlsx ATAU .csv secara otomatis berdasarkan ekstensi.

    - path_or_buffer: path lokal (str/Path) ATAU file-like object (dari
      Streamlit uploader).
    - sheet_name: cuma dipakai kalau filenya .xlsx (CSV tidak punya sheet).
    - filename_hint: nama file asli - WAJIB diisi kalau path_or_buffer adalah
      file-like object (Streamlit uploader) yang tidak punya ekstensi jelas
      di path-nya sendiri.

    CSV di-deteksi delimiter-nya otomatis (koma ATAU titik-koma) - banyak
    export dari region ID/EU pakai titik-koma karena koma dipakai sebagai
    desimal. Kalau dibaca pakai koma padahal aslinya titik-koma, hasilnya
    1 kolom raksasa gabungan semua field - dicek & di-retry otomatis.
    """
    import pandas as pd

    name = filename_hint
    if name is None:
        name = getattr(path_or_buffer, "name", None) or str(path_or_buffer)

    is_csv = str(name).lower().endswith(".csv")

    if is_csv:
        df = pd.read_csv(path_or_buffer, sep=None, engine="python")
        # Jaga-jaga kalau auto-detect tetap gagal (mis. cuma 1 baris data) -
        # coba eksplisit titik-koma sebagai fallback terakhir.
        if len(df.columns) == 1 and ";" in str(df.columns[0]):
            if hasattr(path_or_buffer, "seek"):
                path_or_buffer.seek(0)
            df = pd.read_csv(path_or_buffer, sep=";")
        return df
    if sheet_name:
        return pd.read_excel(path_or_buffer, sheet_name=sheet_name)
    return pd.read_excel(path_or_buffer)


def normalize_incident_columns(df):
    """Normalisasi skema BARU tiket Ivanti (per update terakhir user) ke skema
    kanonik yang dipakai pipeline. Beberapa field baru JUSTRU LEBIH AKURAT
    dari sebelumnya - 'Active DateTime'/'Duration Active (Minutes)'/
    'Duration Resolved (Minutes)'/'FlagBreachResponse'/'FlagBreachReso'/
    'Response_meet/breach'/'Resolution_meet/breach' SUDAH DIHITUNG Ivanti
    sendiri - dipakai LANGSUNG, tidak dihitung ulang dari nol lagi.

    Field yang TIDAK ADA lagi di skema baru (dibanding sebelumnya): "Alert
    Time" (dulu dipakai proxy MTTD) - MTTD jadi tidak bisa dihitung dari
    skema baru ini, kecuali ada sumber lain."""
    import pandas as pd

    df = df.copy()

    # Kolom "Created On" muncul 2x di header asli - pandas otomatis rename
    # yang kedua jadi "Created On.1" - buang duplikatnya.
    dup_cols = [c for c in df.columns if c.startswith("Created On.")]
    if dup_cols:
        df = df.drop(columns=dup_cols)

    # Nama kolom MITRE/KillChain/Triage berbeda antar versi export Ivanti
    # (lama: 'Incident MITRE'/'Incident KillChain'; export Sept 2026:
    # 'IncidentMitre'/'IncidentKillChain'). Dicocokkan TANPA spasi/underscore/
    # huruf besar-kecil, lalu dinamai ke bentuk kanonik yang dipakai pipeline.
    # Hanya 3 nama ini yang di-alias - kolom lain TIDAK ditebak.
    import re as _re
    _alias = {"incidentmitre": "Incident MITRE", "incidentkillchain": "Incident KillChain", "triage": "Triage"}
    for _c in list(df.columns):
        _target = _alias.get(_re.sub(r"[^a-z0-9]", "", str(_c).lower()))
        if _target and _c != _target and _target not in df.columns:
            df = df.rename(columns={_c: _target})

    rename_map = {
        "Ticket Number": "Incident",
        "Active DateTime": "Responded On",  # konsep "mulai ditangani" = Active
        "FlagBreachReso": "FlagBreachResolution",  # standarkan ejaan (typo di header asli)
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns and rename_map[k] not in df.columns})

    for col in ["Created On", "Resolved On", "Closed On", "Responded On", "Resolved Date Time"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    # Priority HARUS numerik (0-3) untuk semua agregasi (.min()/.max() dsb)
    # di hilir pipeline. DITEMUKAN di data asli: 1 baris punya nilai
    # "[Exploitation, Actions on Objectives]" di kolom Priority (anomali
    # data - kemungkinan salah kolom saat export, nilai KillChain nyasar
    # ke Priority). pd.to_numeric(errors='coerce') -> nilai yang tidak
    # bisa dikonversi jadi NaN (ditandai 'Missing Priority' di Validator
    # yang sudah ada, BUKAN bikin pipeline crash dengan TypeError int<=str).
    if "Priority" in df.columns:
        df["Priority"] = pd.to_numeric(df["Priority"], errors="coerce")

    return df


def normalize_master_rules_columns(df, assume_all_enabled=False):
    """Samakan variasi nama kolom Master Rules dari sumber export yang beda-beda
    ke skema kanonik yang dipakai pipeline: Rule_ID, Rule_Names, Rule_Status
    (+ Security_Domain/severity kalau ada, dibiarkan apa adanya).

    Kalau kolom yang dibutuhkan (Rule_Names) BENAR-BENAR tidak ada dalam
    bentuk apapun yang dikenali, TIDAK menebak - biarkan KeyError asli
    muncul supaya user tahu persis kolom apa yang kurang, bukan silent-wrong.

    assume_all_enabled: kalau True DAN tidak ada kolom status yang terdeteksi
    sama sekali, SEMUA rule diisi "Enabled" (bukan "Unknown") - HANYA dipakai
    kalau user secara EKSPLISIT konfirmasi (mis. lewat checkbox di UI) bahwa
    file yang diupload memang sudah difilter cuma berisi rule aktif saja oleh
    sumbernya (mis. diminta ke tim Splunk "export semua rule yang enabled").
    TIDAK PERNAH diasumsikan otomatis oleh kode - harus eksplisit dari user."""
    import pandas as pd

    rename_map = {
        "title": "Rule_Names",       # ditemukan di export Splunk region tertentu
        "Alert Name": "Rule_Names",  # ditemukan di export Splunk versi lain
        "No": "Rule_ID",
        "security_domain": "Security_Domain",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns and v not in df.columns})

    if "Rule_ID" not in df.columns:
        df.insert(0, "Rule_ID", ["AUTO_" + str(i).zfill(5) for i in range(len(df))])

    # Deteksi kolom status secara fleksibel - banyak variasi nama yang mungkin
    # dipakai user (status/Status/Rule Status/Active/Enabled/dst). Kalau ketemu
    # SATU kandidat yang jelas, pakai itu. Kalau tidak ketemu SAMA SEKALI,
    # BARU diisi "Unknown" - tidak menebak dari kolom yang ambigu.
    if "Rule_Status" not in df.columns:
        status_candidates = [
            c for c in df.columns
            if c.lower().strip() in (
                "status", "rule status", "rule_status", "active", "is_active",
                "enabled", "state", "rule state", "aktif"
            )
        ]
        if len(status_candidates) == 1:
            df = df.rename(columns={status_candidates[0]: "Rule_Status"})
            print(f"   [INFO] Kolom status ditemukan & dipakai: '{status_candidates[0]}' -> Rule_Status")
        elif len(status_candidates) > 1:
            print(f"   [WARNING] Ada {len(status_candidates)} kolom yang mirip status "
                  f"({status_candidates}) - TIDAK dipilih otomatis (ambigu, salah pilih lebih "
                  f"berisiko daripada kosong). Rule_Status diisi 'Unknown'.")
            df["Rule_Status"] = "Unknown"
        else:
            if assume_all_enabled:
                print("   [INFO] Kolom Rule_Status tidak ditemukan, TAPI user konfirmasi file ini "
                      "cuma berisi rule yang sudah Enabled - semua rule diisi 'Enabled'.")
                df["Rule_Status"] = "Enabled"
            else:
                print("   [WARNING] Kolom Rule_Status tidak ditemukan di file Master Rules - "
                      "diisi 'Unknown' untuk semua rule (Enabled/Disabled TIDAK bisa dihitung "
                      "sampai file sumbernya punya kolom status).")
                df["Rule_Status"] = "Unknown"

    # Normalisasi NILAI status - kolomnya mungkin sudah ketemu, tapi isinya bisa
    # "Active"/"Yes"/"1"/"True" (bukan literal "Enabled") - kalau tidak
    # distandarkan, hitungan Enabled/Disabled tetap 0 walau kolomnya benar.
    enabled_values = {"enabled", "active", "yes", "1", "1.0", "true", "on", "aktif"}
    disabled_values = {"disabled", "inactive", "no", "0", "0.0", "false", "off", "nonaktif", "tidak aktif"}

    def _norm_status(v):
        s = str(v).strip().lower()
        if s in enabled_values:
            return "Enabled"
        if s in disabled_values:
            return "Disabled"
        return v  # biarkan apa adanya kalau tidak dikenali (mis. "Unknown" tetap "Unknown")

    df["Rule_Status"] = df["Rule_Status"].apply(_norm_status)

    return df


def safe_divide(a,b):

    if b==0:

        return 0

    return round((a/b)*100,2)


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "INFO": 0}
_SEVERITY_DISPLAY = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}


def clean_severity(raw):
    """Standardisasi severity dari berbagai sumber. Data Splunk mentah ternyata
    tidak selalu 1 kata bersih - ditemukan nilai gabungan seperti
    "CRITICAL HIGH LOW MEDIUM" (kemungkinan beberapa varian rule tergabung jadi
    1 nama alert), nilai sampah seperti "ERROR", dan bahkan angka mentah (3).
    Kalau ada >=1 kata severity valid dalam string, ambil yang PALING PARAH
    (pendekatan konservatif untuk konteks keamanan - lebih baik overestimate
    daripada meremehkan). Kalau tidak ada kata valid sama sekali -> Unknown."""
    if raw is None:
        return "Unknown"
    s = str(raw).strip().upper()
    if s in ("NAN", "NONE", ""):
        return "Unknown"

    found_ranks = [_SEVERITY_RANK[tok] for tok in s.split() if tok in _SEVERITY_RANK]
    if found_ranks:
        return _SEVERITY_DISPLAY[max(found_ranks)]
    return "Unknown"


def clean_nonsplunk_time(value):
    """Parse waktu dari file alert non-Splunk yang formatnya campur (string
    dd/mm/yyyy HH:MM:SS di sheet Akamai, datetime asli di sheet CSPM/Defender)."""
    import pandas as pd

    if pd.isna(value):
        return pd.NaT
    if isinstance(value, str):
        for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
            try:
                return pd.to_datetime(value, format=fmt)
            except Exception:
                pass
        return pd.to_datetime(value, dayfirst=True, errors="coerce")
    return pd.to_datetime(value, errors="coerce")