"""Penentuan periode report. Tidak ada bulan yang di-hardcode."""
import calendar
import re
from datetime import date

import pandas as pd

MONTH_ID = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus",
            "September", "Oktober", "November", "Desember"]
_MONTH_TOKENS = {
    1: ["januari", "january", "jan"], 2: ["februari", "february", "feb"], 3: ["maret", "march", "mar"],
    4: ["april", "apr"], 5: ["mei", "may"], 6: ["juni", "june", "jun"], 7: ["juli", "july", "jul"],
    8: ["agustus", "august", "agu", "aug", "agt"], 9: ["september", "sept", "sep"],
    10: ["oktober", "october", "okt", "oct"], 11: ["november", "nov", "nop"], 12: ["desember", "december", "des", "dec"],
}


def month_name(month):
    return MONTH_ID[int(month) - 1]


def make_period(month, year, start=None, end=None, source="manual", note=""):
    month, year = int(month), int(year)
    last = calendar.monthrange(year, month)[1]
    return {"report_month": month, "report_year": year, "month_name": month_name(month),
            "start_date": start or date(year, month, 1), "end_date": end or date(year, month, last),
            "source": source, "note": note}


def period_from_filename(name):
    """'IPS_Sep_2026.csv' -> (9, 2026). Return None bila tidak yakin."""
    stem = re.sub(r"\.[A-Za-z0-9]+$", "", name or "")
    m = re.search(r"(20\d{2})[-_.]?(0[1-9]|1[0-2])(?!\d)", stem)
    if m:
        return int(m.group(2)), int(m.group(1))
    year_m = re.search(r"(20\d{2})", stem)
    if not year_m:
        return None
    tokens = re.split(r"[^A-Za-z]+", stem.lower())
    for month, names in _MONTH_TOKENS.items():
        if any(t in names for t in tokens):
            return month, int(year_m.group(1))
    return None


def detect_period(df_norm=None, filename=""):
    """Prioritas: timestamp di data -> nama file -> belum diketahui (user wajib isi)."""
    if df_norm is not None and "timestamp" in df_norm.columns and df_norm["timestamp"].notna().any():
        ts = pd.to_datetime(df_norm["timestamp"], errors="coerce").dropna()
        if len(ts) >= 0.9 * df_norm["timestamp"].notna().sum() and len(ts) > 0:
            mode_month = ts.dt.to_period("M").mode().iloc[0]
            p = make_period(mode_month.month, mode_month.year, ts.min().date(), ts.max().date(), "timestamp")
            if ts.dt.to_period("M").nunique() > 1:
                p["note"] = "Data mencakup lebih dari satu bulan; bulan dominan dipakai."
            return p
    guess = period_from_filename(filename)
    if guess:
        p = make_period(guess[0], guess[1], source="filename",
                        note="Periode diambil dari NAMA FILE (data tidak punya timestamp). Mohon konfirmasi.")
        return p
    return {"report_month": None, "report_year": None, "month_name": None, "start_date": None,
            "end_date": None, "source": None, "note": "Periode tidak dapat ditentukan, mohon isi manual."}


def format_period_label(p):
    return f"{p['month_name']} {p['report_year']}" if p and p.get("report_month") else "-"
