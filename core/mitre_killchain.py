"""
MITRE ATT&CK & Cyber Kill Chain Parser
=========================================================
Parsing kolom "Incident MITRE" dan "Incident KillChain" dari export Ivanti
terbaru. Dibangun berdasarkan inspeksi LANGSUNG ke 219 baris data asli
(Export_Data_SOC_1.xlsx, insiden 18-24 Sept 2026) - BUKAN asumsi.

Temuan kualitas data dari inspeksi tersebut (ditangani semua di bawah):
- 3 cara berbeda merepresentasikan "kosong": '[]', NaN, '-', '--'
- 1 baris MITRE format tidak valid: 'T.0001' (bukan pola TXXXX/TAXXXX)
- 1 baris MITRE valid tapi tanpa kurung siku: 'T1134.002'
- 1 baris KillChain huruf kecil tanpa kurung: 'delivery'
- 1 baris KillChain BERISI MITRE Technique ID yang salah kolom:
  'T1106, T1083, T1614' - kesalahan input di sumber, bukan variasi format
- MITRE sering mencampur Tactic ID (TA####) dan Technique ID (T####)
  dalam 1 list yang sama, mis. '[TA0006,T1110,T1110.003]'

8 stage Kill Chain yang TERKONFIRMASI dipakai organisasi ini (bukan
standar Lockheed Martin klasik - versi mereka menyisipkan "Privilege
Escalation" dari terminologi MITRE ATT&CK Tactic):
Reconnaissance, Weaponization, Delivery, Exploitation, Installation,
Privilege Escalation, Command & Control (ditambah Okt 2026), Actions on Objectives.
"""

import re

import pandas as pd

_TACTIC_PATTERN = re.compile(r"^TA\d+$", re.IGNORECASE)
_TECHNIQUE_PATTERN = re.compile(r"^T\d+(\.\d+)?$", re.IGNORECASE)
_EMPTY_MARKERS = {"nan", "none", "null", "", "-", "--", "[]"}

VALID_KILLCHAIN_STAGES = {
    "reconnaissance", "weaponization", "delivery", "exploitation",
    "installation", "privilege escalation", "command & control", "actions on objectives",
}

# Urutan logis stage (dipakai summary, funnel, drill-down). "Command & Control"
# ditambahkan sebagai stage ke-8 atas konfirmasi user (Okt 2026; 14 tiket di data
# Sept 2026) dan ditempatkan tepat sebelum "Actions On Objectives". Ubah URUTAN di
# sini saja bila posisinya perlu digeser.
KILLCHAIN_STAGE_ORDER = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation",
                         "Installation", "Privilege Escalation", "Command & Control", "Actions On Objectives"]

# Nama resmi MITRE ATT&CK - dicek terhadap SEMUA 47 Technique & 7 Tactic
# yang benar-benar ditemukan di data asli (Export_Data_SOC_1.xlsx). Kalau
# nanti muncul kode yang tidak ada di kamus ini (technique baru), fallback
# ke "(nama tidak dikenal)" - TIDAK mengarang nama.
MITRE_TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0010": "Exfiltration", "TA0043": "Reconnaissance",
    "TA0011": "Command and Control",   # ditemukan di data Sept 2026
}

MITRE_TECHNIQUE_NAMES = {
    "T1005": "Data from Local System", "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information", "T1036": "Masquerading",
    "T1040": "Network Sniffing", "T1046": "Network Service Discovery",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1052": "Exfiltration Over Physical Medium", "T1055": "Process Injection",
    "T1057": "Process Discovery", "T1070": "Indicator Removal",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078": "Valid Accounts", "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1091": "Replication Through Removable Media", "T1098": "Account Manipulation",
    "T1098.002": "Account Manipulation: Additional Email Delegate Permissions",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1105": "Ingress Tool Transfer", "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1134.002": "Access Token Manipulation: Create Process with Token",
    "T1136": "Create Account", "T1136.003": "Create Account: Cloud Account",
    "T1190": "Exploit Public-Facing Application",
    "T1204.002": "User Execution: Malicious File",
    "T1213": "Data from Information Repositories",
    "T1222": "File and Directory Permissions Modification",
    "T1485": "Data Destruction", "T1530": "Data from Cloud Storage",
    "T1531": "Account Access Removal", "T1552": "Unsecured Credentials",
    "T1556": "Modify Authentication Process", "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.002": "Impair Defenses: Disable Windows Event Logging",
    "T1565": "Data Manipulation", "T1565.001": "Data Manipulation: Stored Data Manipulation",
    "T1566": "Phishing", "T1567": "Exfiltration Over Web Service",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1578.002": "Modify Cloud Compute Infrastructure: Create Cloud Instance",
    "T1578.003": "Modify Cloud Compute Infrastructure: Delete Cloud Instance",
    "T1586.003": "Compromise Accounts: Cloud Accounts",
    "T1621": "Multi-Factor Authentication Request Generation",
    # Ditemukan di data Sept 2026; nama mengikuti penamaan resmi MITRE ATT&CK.
    "T1059": "Command and Scripting Interpreter",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1090": "Proxy",
    "T1201": "Password Policy Discovery",
    "T1580": "Cloud Infrastructure Discovery",
    "T1583.004": "Acquire Infrastructure: Server",
    "T1089": "Disabling Security Tools (technique lama/deprecated di ATT&CK; kini di T1562.001)",
}


def mitre_technique_label(code):
    """'T1078' -> 'T1078 - Valid Accounts'. Kode tidak dikenal TETAP
    ditampilkan (bukan disembunyikan), cuma nama-nya jujur '(nama tidak
    dikenal)' - supaya tidak mengarang nama technique yang belum kita punya."""
    name = MITRE_TECHNIQUE_NAMES.get(code.upper())
    return f"{code} - {name}" if name else f"{code} (nama tidak dikenal)"


def mitre_tactic_label(code):
    name = MITRE_TACTIC_NAMES.get(code.upper())
    return f"{code} - {name}" if name else f"{code} (nama tidak dikenal)"


def parse_bracket_list(raw):
    """String seperti '[T1021]', '[TA0006, T1110]', 'T1134.002', '-', NaN,
    dsb -> list token bersih (string). SEMUA representasi kosong yang
    ditemukan di data asli (kurung kosong, NaN, satu/dua strip) dianggap
    SATU MAKNA: list kosong - bukan dibedakan jadi kategori berbeda."""
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return []
    s = str(raw).strip()
    if s.lower() in _EMPTY_MARKERS:
        return []
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if not s.strip():
        return []
    return [t.strip() for t in s.split(",") if t.strip()]


def classify_mitre_tokens(tokens):
    """Pisahkan token MITRE jadi Tactic (TA####) vs Technique (T####,
    boleh ada sub-technique .XXX) vs Invalid (format tidak dikenali sama
    sekali, mis. 'T.0001' - BUKAN pola TXXXX yang valid)."""
    tactics, techniques, invalid = [], [], []
    for t in tokens:
        if _TACTIC_PATTERN.match(t):
            tactics.append(t.upper())
        elif _TECHNIQUE_PATTERN.match(t):
            techniques.append(t.upper())
        else:
            invalid.append(t)
    return tactics, techniques, invalid


def classify_killchain_tokens(tokens):
    """Validasi token KillChain terhadap 8 stage yang terkonfirmasi dipakai
    organisasi ini. Token yang tidak cocok SAMA SEKALI (mis. MITRE ID yang
    kesasar masuk kolom ini) masuk kategori invalid - DITANDAI, bukan
    didiamkan atau dipaksa jadi stage yang salah."""
    valid, invalid = [], []
    for t in tokens:
        key = t.strip().lower()
        if key in VALID_KILLCHAIN_STAGES:
            valid.append(key.title())
        else:
            invalid.append(t)
    return valid, invalid


def enrich_incident_mitre_killchain(df):
    """Tambahkan kolom hasil parsing ke DataFrame insiden. Dipanggil SEKALI
    di awal pipeline (mirip normalize_incident_columns) - kolom baru:
    _MITRE_Tactics, _MITRE_Techniques, _MITRE_Invalid,
    _KillChain_Stages, _KillChain_Invalid."""
    df = df.copy()
    if "Incident MITRE" in df.columns:
        parsed = df["Incident MITRE"].apply(parse_bracket_list)
        classified = parsed.apply(classify_mitre_tokens)
        df["_MITRE_Tactics"] = classified.apply(lambda x: x[0])
        df["_MITRE_Techniques"] = classified.apply(lambda x: x[1])
        df["_MITRE_Invalid"] = classified.apply(lambda x: x[2])
    else:
        df["_MITRE_Tactics"] = [[] for _ in range(len(df))]
        df["_MITRE_Techniques"] = [[] for _ in range(len(df))]
        df["_MITRE_Invalid"] = [[] for _ in range(len(df))]

    if "Incident KillChain" in df.columns:
        parsed_kc = df["Incident KillChain"].apply(parse_bracket_list)
        classified_kc = parsed_kc.apply(classify_killchain_tokens)
        df["_KillChain_Stages"] = classified_kc.apply(lambda x: x[0])
        df["_KillChain_Invalid"] = classified_kc.apply(lambda x: x[1])
    else:
        df["_KillChain_Stages"] = [[] for _ in range(len(df))]
        df["_KillChain_Invalid"] = [[] for _ in range(len(df))]

    # Triage (True Positive/False Positive) - field BARU, dikonfirmasi dari
    # inspeksi Export_Data_SOC_2.xlsx. Nilai yang tidak dikenal (NaN, atau
    # anomali seperti literal 'Incident' yang ditemukan 1x di data asli)
    # DITANDAI 'Unknown' - TIDAK dipaksa jadi True/False Positive.
    if "Triage" in df.columns:
        df["_Triage"] = df["Triage"].apply(normalize_triage)
    else:
        df["_Triage"] = "Unknown"

    return df


def normalize_triage(value):
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "Unknown"
    v = str(value).strip().lower()
    if v == "true positive":
        return "True Positive"
    if v == "false positive":
        return "False Positive"
    return "Unknown"


def build_triage_summary(df):
    """Ringkasan True Positive/False Positive/Unknown - KPI baru, dihitung
    dari SELURUH insiden (TIDAK difilter), supaya rasio TP/FP itu sendiri
    kelihatan apa adanya."""
    if "_Triage" not in df.columns:
        return pd.DataFrame(columns=["Triage", "Count", "Percent"])
    counts = df["_Triage"].value_counts()
    total = len(df)
    rows = [{"Triage": k, "Count": int(v), "Percent": round(100 * v / max(total, 1), 1)}
            for k, v in counts.items()]
    return pd.DataFrame(rows).sort_values("Count", ascending=False).reset_index(drop=True)


# =========================================================
# Parser GENERIK untuk field 'Description' (BARU) - format "key: value"
# dipisah spasi ganda, TAPI key yang muncul BERBEDA-BEDA tergantung jenis
# alert (AWS CloudTrail vs WAF vs Windows Event, dst) - TIDAK ada skema
# tetap. Parser ini TIDAK menebak skema universal, cuma mengekstrak
# apapun pola "key: value" yang ADA di teks itu, apa adanya.
# =========================================================

def parse_description_kv(text):
    """'_time: 123  app: AwsApiCall  count: 1' -> {'_time': '123', 'app':
    'AwsApiCall', 'count': '1'}. Return dict KOSONG kalau teks tidak
    mengikuti pola ini sama sekali (BUKAN error) - beberapa Description
    cuma teks bebas (mis. 'alert testing')."""
    if text is None or (isinstance(text, float) and pd.isna(text)):
        return {}
    text = str(text)
    # "View result in Splunk: <url>" selalu di akhir - pisahkan dulu biar
    # tidak ikut kepotong aneh oleh split spasi-ganda di bawah.
    splunk_url = None
    url_match = re.search(r"View result in Splunk:\s*(\S+)", text)
    if url_match:
        splunk_url = url_match.group(1)
        text = text[:url_match.start()]

    # Key:value dipisah 2+ spasi - pola yang DIKONFIRMASI konsisten dari
    # inspeksi data asli, meski SET key-nya beda-beda tiap baris. VALUE
    # BOLEH mengandung colon sendiri (mis. timestamp '18-09-2026 00:20:00')
    # - batas antar pasangan HANYA dari lookahead spasi-ganda+key:, BUKAN
    # dari larangan colon di value (itu bug yang pernah ditemukan - value
    # berisi timestamp salah terpecah jadi key palsu seperti '20: 00').
    pairs = re.findall(r"(\w+):\s*(.+?)(?=\s{2,}\w+:|$)", text)
    # Key yang MURNI angka (mis. '1', '16') adalah artefak parsing dari
    # format alert non-Splunk (mis. Microsoft Defender yang pakai narasi
    # 'Severity  Medium' tanpa pola key:value asli) - disaring, bukan field
    # sungguhan.
    result = {k.strip(): v.strip() for k, v in pairs if v.strip() and not k.strip().isdigit()}
    if splunk_url:
        result["Splunk_URL"] = splunk_url
    return result


def build_mitre_technique_summary(df):
    """Frekuensi tiap MITRE Technique - untuk TTP Trends (bar chart).
    Kolom 'Label' berisi 'T1078 - Valid Accounts' (kode + nama resmi)
    untuk ditampilkan di chart/tabel, bukan cuma kode mentah."""
    all_techniques = [t for row in df["_MITRE_Techniques"] for t in row]
    if not all_techniques:
        return pd.DataFrame(columns=["Technique", "Label", "Count"])
    result = (
        pd.Series(all_techniques).value_counts().reset_index()
        .rename(columns={"index": "Technique", 0: "Count", "count": "Count"})
    )
    result["Label"] = result["Technique"].apply(mitre_technique_label)
    return result[["Technique", "Label", "Count"]]


def build_mitre_tactic_summary(df):
    all_tactics = [t for row in df["_MITRE_Tactics"] for t in row]
    if not all_tactics:
        return pd.DataFrame(columns=["Tactic", "Label", "Count"])
    result = (
        pd.Series(all_tactics).value_counts().reset_index()
        .rename(columns={"index": "Tactic", 0: "Count", "count": "Count"})
    )
    result["Label"] = result["Tactic"].apply(mitre_tactic_label)
    return result[["Tactic", "Label", "Count"]]


def build_killchain_summary(df):
    """Frekuensi tiap Kill Chain stage - untuk funnel/bar chart, diurutkan
    sesuai URUTAN LOGIS kill chain (bukan alfabetis atau by-count) supaya
    kelihatan progresi serangan yang sebenarnya."""
    stage_order = KILLCHAIN_STAGE_ORDER
    all_stages = [s for row in df["_KillChain_Stages"] for s in row]
    counts = pd.Series(all_stages).value_counts() if all_stages else pd.Series(dtype=int)
    rows = [{"Stage": s, "Count": int(counts.get(s, 0))} for s in stage_order]
    return pd.DataFrame(rows)


def build_data_quality_report(df):
    """Ringkasan anomali - BUKAN untuk kalkulasi, cuma buat ditampilkan
    sebagai Data Quality Warning di dashboard."""
    invalid_mitre = df[df["_MITRE_Invalid"].apply(len) > 0]
    invalid_kc = df[df["_KillChain_Invalid"].apply(len) > 0]
    rows = []
    for _, r in invalid_mitre.iterrows():
        rows.append({"Ticket": r.get("Incident", r.get("Ticket Number", "-")),
                     "Kolom": "Incident MITRE", "Nilai Bermasalah": ", ".join(r["_MITRE_Invalid"])})
    for _, r in invalid_kc.iterrows():
        rows.append({"Ticket": r.get("Incident", r.get("Ticket Number", "-")),
                     "Kolom": "Incident KillChain", "Nilai Bermasalah": ", ".join(r["_KillChain_Invalid"])})
    return pd.DataFrame(rows)


def generate_mitre_killchain_insights(technique_summary, tactic_summary, killchain_summary, total_incidents):
    """Insight dinamis ('so what', bukan cuma angka) dari pola MITRE &
    Kill Chain - dihasilkan dari data aktual, TIDAK hardcode kalimat."""
    insights = []

    if technique_summary is not None and len(technique_summary) > 0:
        top = technique_summary.iloc[0]
        pct = round(100 * top["Count"] / max(total_incidents, 1), 1)
        insights.append(
            f"**Technique paling sering**: {top['Label']} muncul di {int(top['Count'])} insiden "
            f"({pct}% dari total {total_incidents} insiden) - ini yang paling banyak dimanfaatkan penyerang."
        )

    if tactic_summary is not None and len(tactic_summary) > 0:
        top = tactic_summary.iloc[0]
        insights.append(
            f"**Tactic paling dominan**: {top['Label']} ({int(top['Count'])} kemunculan) - menunjukkan "
            f"tahap besar mana dalam alur serangan yang paling sering terdeteksi."
        )

    if killchain_summary is not None and len(killchain_summary) > 0 and killchain_summary["Count"].sum() > 0:
        # Stage dengan count TERBANYAK - beri interpretasi berbeda tergantung
        # posisinya di kill chain (early stage vs late stage punya makna beda).
        kc_sorted = killchain_summary[killchain_summary["Count"] > 0].sort_values("Count", ascending=False)
        top_stage = kc_sorted.iloc[0]
        early_stages = {"Reconnaissance", "Weaponization", "Delivery"}
        late_stages = {"Installation", "Privilege Escalation", "Command & Control", "Actions On Objectives"}

        if top_stage["Stage"] in early_stages:
            interpretation = ("mayoritas terdeteksi di tahap AWAL serangan - kabar baik, deteksi terjadi "
                              "sebelum penyerang berhasil masuk lebih dalam.")
        elif top_stage["Stage"] in late_stages:
            interpretation = ("mayoritas terdeteksi di tahap AKHIR/LANJUT serangan - perlu perhatian, "
                              "berarti deteksi seringkali baru terjadi setelah penyerang sudah cukup jauh masuk.")
        else:
            interpretation = "merupakan titik terbanyak dalam siklus serangan yang tercatat."

        insights.append(
            f"**Kill Chain**: stage '{top_stage['Stage']}' paling banyak tercatat "
            f"({int(top_stage['Count'])} insiden) - {interpretation}"
        )

        # Bandingkan early vs late total - insight tambahan soal postur deteksi keseluruhan
        early_total = kc_sorted[kc_sorted["Stage"].isin(early_stages)]["Count"].sum()
        late_total = kc_sorted[kc_sorted["Stage"].isin(late_stages)]["Count"].sum()
        if early_total + late_total > 0:
            early_pct = round(100 * early_total / (early_total + late_total), 1)
            insights.append(
                f"**Postur deteksi**: {early_pct}% insiden tercatat di tahap awal (Recon/Weaponization/"
                f"Delivery) vs {round(100 - early_pct, 1)}% di tahap lanjut (Installation/Privilege "
                f"Escalation/Command & Control/Actions on Objectives) - {'deteksi dini mendominasi' if early_pct >= 60 else 'porsi deteksi tahap lanjut cukup signifikan, cek apakah alerting tahap awal sudah optimal'}."
            )

    return insights


# =========================================================
# BoD FEEDBACK #1: Hierarki Tactic -> Technique -> Sub-Technique
# =========================================================

def build_mitre_hierarchy(df):
    """Hierarki 3 level untuk Sunburst/Treemap chart - sesuai skema resmi
    MITRE ATT&CK (Tactic -> Technique -> Sub-Technique).

    PENTING soal metodologi: hubungan Tactic-Technique di sini dibangun
    dari CO-OCCURRENCE per tiket (tactic & technique yang muncul di TIKET
    YANG SAMA dihitung 1 edge) - BUKAN dari tabel mapping resmi MITRE
    (yang tidak ada sebagai field terstruktur di data kita). Kalau 1 tiket
    tidak punya tactic sama sekali, technique-nya masuk bucket "Tactic
    Tidak Diketahui" (BUKAN ditebak tactic-nya)."""
    rows = []
    for _, r in df.iterrows():
        tactics = r["_MITRE_Tactics"] if r["_MITRE_Tactics"] else ["Tactic Tidak Diketahui"]
        for tech in r["_MITRE_Techniques"]:
            base = tech.split(".")[0]
            base_label = mitre_technique_label(base)
            sub_label = mitre_technique_label(tech) if "." in tech else base_label
            for tac in tactics:
                tac_label = mitre_tactic_label(tac) if tac != "Tactic Tidak Diketahui" else "Tactic Tidak Diketahui"
                rows.append({"Tactic": tac_label, "Technique": base_label, "SubTechnique": sub_label})

    if not rows:
        return pd.DataFrame(columns=["Tactic", "Technique", "SubTechnique", "Count"])
    hdf = pd.DataFrame(rows)
    result = hdf.groupby(["Tactic", "Technique", "SubTechnique"]).size().reset_index(name="Count")
    return result.sort_values("Count", ascending=False).reset_index(drop=True)


# =========================================================
# BoD FEEDBACK #2: Technique paling berbahaya berdasarkan IMPACT
# =========================================================

def build_technique_impact(df, technique_summary, min_sample=5):
    """Skor 'bahaya' per Technique berdasarkan IMPACT (Severity High/
    Critical ATAU breach SLA) - BUKAN cuma frekuensi kemunculan.

    PENTING - reliabilitas statistik: Technique dengan sampel SANGAT KECIL
    (mis. cuma 3-4 insiden) yang kebetulan semua High/breach BUKAN bukti
    kuat "technique ini berbahaya" - bisa cuma kebetulan sampel kecil.
    Kolom 'Sample_Size_Warning' ditandai True kalau n < min_sample - JANGAN
    disimpulkan sebagai temuan kuat, cuma informasi tambahan."""
    if technique_summary is None or len(technique_summary) == 0:
        return pd.DataFrame(columns=["Technique", "Label", "Count", "High_Severity_or_Breach_Count",
                                       "Impact_%", "Sample_Size_Warning"])

    rows = []
    for _, tech_row in technique_summary.iterrows():
        code = tech_row["Technique"]
        mask = df["_MITRE_Techniques"].apply(lambda lst: code in lst)
        subset = df[mask]
        n = len(subset)
        if n == 0:
            continue
        high_sev = 0
        if "Severity" in subset.columns:
            high_sev = int(subset["Severity"].astype(str).str.strip().str.lower().isin(["high", "critical"]).sum())
        breached = 0
        for col in ["FlagBreachResponse", "FlagBreachReso"]:
            if col in subset.columns:
                breached = max(breached, int((subset[col].astype(str) == "1").sum()))
        impact_count = max(high_sev, breached)
        rows.append({
            "Technique": code, "Label": tech_row["Label"], "Count": n,
            "High_Severity_or_Breach_Count": impact_count,
            "Impact_%": round(100 * impact_count / n, 1),
            "Sample_Size_Warning": n < min_sample,
        })
    result = pd.DataFrame(rows)
    if len(result) > 0:
        # Urutkan: sampel CUKUP dulu (paling berbahaya & bisa dipercaya),
        # sampel kecil di bawah - supaya tidak menyesatkan jadi ranking utama.
        result = result.sort_values(["Sample_Size_Warning", "Impact_%", "Count"],
                                     ascending=[True, False, False]).reset_index(drop=True)
    return result


# =========================================================
# BoD FEEDBACK #3: Drill-down dari stage Kill Chain tertinggi
# =========================================================

def build_mitre_by_killchain_stage(df, stage_name):
    """Untuk insiden yang PUNYA stage tertentu (mis. 'Exploitation' kalau
    itu yang paling tinggi) - breakdown Tactic & Technique KHUSUS di
    subset insiden itu, BUKAN dari semua insiden. Return juga hierarki
    2-level (Tactic->Technique) untuk network chart - supaya korelasi
    Tactic->Technique-nya kelihatan LANGSUNG, bukan 2 bar chart terpisah
    yang tidak terlihat hubungannya.

    PENTING: hier_df (pasangan Tactic-Technique) BEDA dari jumlah INSIDEN
    UNIK - 1 insiden bisa punya >1 Technique sekaligus (mis. T1098 DAN
    T1098.003 di tiket yang sama), jadi sum(hier_df.Count) per Tactic BISA
    lebih besar dari jumlah insiden asli. tactic_unique_n/technique_unique_n
    dihitung terpisah dengan SET per baris (dedup dalam 1 insiden) supaya
    tidak dobel-hitung - ini yang harus dipakai untuk LABEL/ukuran simpul
    chart, bukan sum pasangan."""
    mask = df["_KillChain_Stages"].apply(lambda lst: stage_name in lst)
    subset = df[mask]
    if len(subset) == 0:
        empty_t = pd.DataFrame(columns=["Technique", "Label", "Count"])
        empty_tac = pd.DataFrame(columns=["Tactic", "Label", "Count"])
        empty_hier = pd.DataFrame(columns=["Tactic", "Technique", "Count"])
        return empty_t, empty_tac, 0, empty_hier, {}, {}

    hier_rows = []
    tactic_unique_n, technique_unique_n = {}, {}
    for _, r in subset.iterrows():
        tactics = r["_MITRE_Tactics"] if r["_MITRE_Tactics"] else ["Tactic Tidak Diketahui"]
        seen_tactics = set()
        for tac in tactics:
            tac_label = mitre_tactic_label(tac) if tac != "Tactic Tidak Diketahui" else "Tactic Tidak Diketahui"
            seen_tactics.add(tac_label)
        for tac_label in seen_tactics:
            tactic_unique_n[tac_label] = tactic_unique_n.get(tac_label, 0) + 1

        seen_techniques = set(mitre_technique_label(t) for t in r["_MITRE_Techniques"])
        for tech_label in seen_techniques:
            technique_unique_n[tech_label] = technique_unique_n.get(tech_label, 0) + 1

        for tech in r["_MITRE_Techniques"]:
            tech_label = mitre_technique_label(tech)
            for tac in tactics:
                tac_label = mitre_tactic_label(tac) if tac != "Tactic Tidak Diketahui" else "Tactic Tidak Diketahui"
                hier_rows.append({"Tactic": tac_label, "Technique": tech_label})
    if hier_rows:
        hier_df = pd.DataFrame(hier_rows).groupby(["Tactic", "Technique"]).size().reset_index(name="Count")
        hier_df = hier_df.sort_values("Count", ascending=False).reset_index(drop=True)
    else:
        hier_df = pd.DataFrame(columns=["Tactic", "Technique", "Count"])

    return (build_mitre_technique_summary(subset), build_mitre_tactic_summary(subset), len(subset),
            hier_df, tactic_unique_n, technique_unique_n)


# =========================================================
# BoD FEEDBACK #4: Kill Chain FUNNEL (menurun ke kanan, bukan raw count)
# =========================================================

_STAGE_ORDER = KILLCHAIN_STAGE_ORDER


def build_killchain_funnel(df):
    """Versi FUNNEL dari Kill Chain - beda dari build_killchain_summary()
    yang menghitung SEMUA stage yang disebut di tiket (1 tiket bisa
    menyumbang ke banyak stage independen, TIDAK harus menurun).

    Funnel ini menghitung untuk TIAP insiden, stage TERDALAM/terjauh yang
    tercatat, lalu CUMULATIVE 'insiden yang mencapai SETIDAKNYA stage ini'.
    Hasilnya PASTI menurun/sama dari kiri ke kanan - bukan dipaksa, tapi
    definisi matematis 'mencapai setidaknya stage N' selalu superset dari
    'mencapai setidaknya stage N+1'. Ini yang dimaksud arahan BoD: 'kill
    chain seharusnya semakin ke kanan semakin kecil'."""
    deepest_idx = []
    for stages in df["_KillChain_Stages"]:
        idxs = [_STAGE_ORDER.index(s) for s in stages if s in _STAGE_ORDER]
        if idxs:
            deepest_idx.append(max(idxs))

    if not deepest_idx:
        return pd.DataFrame([{"Stage": s, "Reached_At_Least": 0} for s in _STAGE_ORDER])

    depth_counts = pd.Series(deepest_idx).value_counts()
    rows = []
    running_total = 0
    for i in reversed(range(len(_STAGE_ORDER))):
        running_total += int(depth_counts.get(i, 0))
        rows.append({"Stage": _STAGE_ORDER[i], "Reached_At_Least": running_total})
    rows.reverse()
    return pd.DataFrame(rows)
