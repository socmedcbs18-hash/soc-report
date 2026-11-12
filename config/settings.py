"""
=========================================================
SOC Weekly Report
=========================================================
Global Configuration
=========================================================
"""

from pathlib import Path

# =========================================================
# PROJECT PATH
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"

MASTER_DIR = INPUT_DIR / "master"
WEEKLY_DIR = INPUT_DIR / "weekly"
MONTHLY_DIR = INPUT_DIR / "monthly"

TEMPLATE_DIR = BASE_DIR / "templates"

# =========================================================
# MASTER FILE
# =========================================================

MASTER_RULE_FILE = MASTER_DIR / "Master_Rules_Splunk.xlsx"
DOMAIN_MAPPING_FILE = MASTER_DIR / "Domain_Mapping_Splunk.xlsx"

# =========================================================
# REPORT CONFIGURATION
# =========================================================

REPORT_NAME = "SOC Report Generator"

REPORT_VERSION = "1.0"

REPORT_AUTHOR = "SOC Team"

# Weekly dimulai Hari Minggu
WEEK_START_DAY = "Sunday"

# Weekly berakhir Hari Sabtu
WEEK_END_DAY = "Saturday"

# =========================================================
# SLA CONFIGURATION
# =========================================================

# SLA Response Time
SLA_MTTR_SECONDS = 300

# MOM manajemen (Nov 2026): MTTC (Created On -> Contained On) tampil
# bila kolom 'Contained On' ada dan terisi di data Ivanti (export Sept-Okt 2026 versi _1 sudah ada).
# Jika kolom tidak ada, MTTC otomatis disembunyikan. Set False untuk menyembunyikan paksa.
SHOW_MTTC = True

# Sumber label Kill Chain/MITRE di report: "mapping" = mapping v2.2 per nama rule (label tiket
# dipakai hanya untuk rule yang belum dipetakan); "tiket" = label Ivanti apa adanya.
# Di dashboard bisa dibalik lewat toggle tanpa generate ulang.
KILLCHAIN_LABEL_SOURCE = "mapping"

# =========================================================
# RULE CONFIGURATION
# =========================================================

# Rule dianggap Noise jika
# Alert > 20
# Incident = 0

NOISE_ALERT_THRESHOLD = 20

# Detection Rate
KEEP_THRESHOLD = 10
REVIEW_THRESHOLD = 5
TUNE_THRESHOLD = 1
# Ambang "Healthy" sungguhan - di bawah ini tapi >= KEEP_THRESHOLD dilabel
# "Acceptable" (lolos syarat minimal, tapi belum tentu bagus), supaya "Healthy"
# tidak menyesatkan (sebelumnya 16% pun dilabel Healthy - membingungkan).
HEALTHY_THRESHOLD = 25

# =========================================================
# DORMANT RULE
# =========================================================

DORMANT_DAYS = 60

# =========================================================
# EXCEL SHEET
# =========================================================

MASTER_RULE_SHEET = "Sheet1"

DOMAIN_KEYWORD_SHEET = "Keyword_Mapping"

DOMAIN_REFERENCE_SHEET = "ketentuan_domain"

# Alert dari device yang belum terintegrasi Splunk (Akamai, CSPM, Microsoft
# Defender, dst) - dikirim manual ke email lalu di-list ke Excel per minggu.
# File ini OPSIONAL per minggu (tidak semua minggu wajib ada) - kalau tidak
# ditemukan, laporan tetap jalan tanpa bagian ini.
NONSPLUNK_FILE_PREFIX = "alert_nonsplunk"

# Task pengecekan yang di-assign tim lain ke SOC TANPA insiden ter-assign resmi
# (mis. tim lain minta SOC cek sesuatu, tercatat sebagai "Task" bukan "Incident"
# di Ivanti). OPSIONAL per minggu - sama seperti alert non-Splunk.
TASK_FILE_PREFIX = "task_soc"

# Alert CTI eksternal (FortiRecon) - Stealer Infection, EASM Change, dst.
# OPSIONAL per periode, sama seperti task_soc/alert_nonsplunk.
CTI_FILE_PREFIX = "cti_fortirecon"

# =========================================================
# OUTPUT
# =========================================================

OUTPUT_WEEKLY_PREFIX = "SOC_Weekly_Report"

OUTPUT_MONTHLY_PREFIX = "SOC_Monthly_Report"

# =========================================================
# DATE FORMAT
# =========================================================

DATE_FORMAT = "%d-%b-%Y"

DATETIME_FORMAT = "%d-%b-%Y %H:%M:%S"

# =========================================================
# CHART
# =========================================================

TOP_RULE_LIMIT = 10

TOP_ANALYST_LIMIT = 10

TOP_DOMAIN_LIMIT = 10

# =========================================================
# LOGGING
# =========================================================

ENABLE_LOG = True

LOG_LEVEL = "INFO"

# =========================================================
# EXPORT
# =========================================================

EXPORT_EXECUTIVE = True
EXPORT_TOP_RULE = True
EXPORT_TUNING = True
EXPORT_DORMANT = True
EXPORT_ANALYST = True
EXPORT_INCIDENT = True
EXPORT_DOMAIN = True
EXPORT_INSIGHT = True

# =========================================================
# ENGINE
# =========================================================

AUTO_DISCOVER_WEEK = True

AUTO_GENERATE_CHART = True

AUTO_GENERATE_INSIGHT = True

# ==========================================================
# RULE NORMALIZATION
# ==========================================================

NORMALIZE_RULE = True

IGNORE_CASE = True

REMOVE_DUPLICATE_SPACE = True

REMOVE_SPECIAL_CHARACTER = False

# ==========================================================
# MATCHING
# ==========================================================

MATCH_THRESHOLD = 90

USE_FUZZY_MATCH = False

# ==========================================================
# (blok KPI duplikat dihapus - definisi tunggal ada di atas, baris 56-69)
# ==========================================================

# ==========================================================
# INCIDENT
# ==========================================================

BREACH_VALUE = "TRUE"

SOC_TEAM_NAME = "SOC"

# ==========================================================
# REPORT
# ==========================================================

TOP_RULE = 10

TOP_ANALYST = 10

TOP_PRIORITY = 10

TOP_DOMAIN = 10

# ==========================================================
# OUTPUT
# ==========================================================

AUTO_FORMAT = True

AUTO_FILTER = True

AUTO_FREEZE_PANE = True

AUTO_CREATE_CHART = True

AUTO_COLORING = True

AUTO_EXECUTIVE_SUMMARY = True

# Rule berstatus 'Usulan - konfirmasi SPL singkat' (mis. AKR WebMoni Public IP -> Command & Control):
# True  = label usulan ikut diterapkan ke tiket (ditandai 'usulan, belum dikonfirmasi SPL').
# False = tiket tetap memakai label asli Ivanti sampai tim Splunk mengonfirmasi.
# Perhatian: tahap Command & Control termasuk 'Exploitation ke atas' = Critical.
TERAPKAN_LABEL_USULAN = True

# Dasar penghitungan Kill Chain/MITRE: "confirmed" = hanya aktivitas yang terkonfirmasi (False Positive tidak dihitung,
# True Positive Prevented dibatasi sampai Delivery); "rule" = label rule apa adanya (potensi deteksi).
KILLCHAIN_BASIS = "confirmed"

# ---------------------------------------------------------------------------------------------
# SLA per Severity (MOM unit head, Nov 2026). Semua waktu dihitung dari LOGGED (Created On).
#   MTTR  : Created -> Active                    <= SLA_MTTR_MENIT (5 menit)
#   MTTC  : Created -> Contained On              <= mttc  + SLA_MTTR_MENIT
#           (contoh MOM: SLA 30 + 5 = 35 menit; bila MTTR aktual 7 menit, sisa waktu containment 28 menit)
#   MTTRV : Created -> Resolved On               <= total (kolom "Total Time" pada tabel MOM)
# 'mttc' & 'mttrv' = durasi SLA tiap fase menurut tabel MOM; 'total' = batas dari Logged sampai Resolved.
# Ubah angka di sini bila kebijakan berubah. Satuan: menit.
# ---------------------------------------------------------------------------------------------
SLA_MTTR_MENIT = 5
SLA_TARGET_MENIT = {
    "Critical": {"mttc": 20,  "mttrv": 40,  "total": 64},    # 1 jam 4 menit
    "High":     {"mttc": 50,  "mttrv": 100, "total": 154},   # 2 jam 34 menit
    "Medium":   {"mttc": 120, "mttrv": 240, "total": 364},   # 6 jam 4 menit
    "Low":      {"mttc": 240, "mttrv": 480, "total": 724},   # 12 jam 4 menit
}
# Bila Severity tiket kosong/tidak baku, pakai Priority Ivanti sebagai pengganti (dicatat di _SLA_Severity_Sumber)
SLA_PRIORITY_KE_SEVERITY = {0: "Critical", 1: "High", 2: "Medium", 3: "Low"}
