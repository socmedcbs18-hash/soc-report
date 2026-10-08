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