"""Data sintetis berskema Ivanti (SOC) dengan perpindahan state machine di tengah bulan. BUKAN data produksi."""
import io

import numpy as np
import pandas as pd

COLS = ["Ticket Number", "Created On", "Resolved On", "Closed On", "Customer", "Email", "Ticket For Maintenance", "Incident Type", "Category Type",
        "Product Type", "Service", "Issue", "Sub_Issue", "Priority", "Status", "Source", "Team", "Owner", "Cause Code", "Active DateTime",
        "Duration Active (Minutes)", "FlagBreachResponse", "Response_meet/breach", "Resolved Date Time", "Duration Resolved (Minutes)",
        "FlagBreachReso", "Resolution_meet/breach"]
OWNERS = ["alif", "ari", "mikail", "yudhistira", "renaldy"]
CUTOVER = pd.Timestamp("2026-09-17 21:00:00")


def _row(tid, created, era, rng):
    new = era == "new"
    act = float(rng.choice([0, 0, 1, 2, 3, 4, 12])) if new else float(rng.choice([1, 1, 1, 2, 3]))
    resolved = None if (new and rng.random() < .55) else created + pd.Timedelta(minutes=float(rng.integers(5, 300)))
    pr = int(rng.choice([3, 3, 3, 3, 2, 1])) if new else int(rng.choice([1, 1, 1, 1, 2, 3]))
    breach = int(act > 5)
    return {"Ticket Number": tid, "Created On": created, "Resolved On": resolved, "Closed On": created + pd.Timedelta(hours=3),
            "Customer": "Alert Splunk" if new and rng.random() < .8 else "Budi Santoso", "Email": "x@alto.id", "Ticket For Maintenance": 0,
            "Incident Type": "Internal - Cybersecurity", "Category Type": "Incident", "Product Type": None if new else "Cybersecurity Internal Support",
            "Service": "CYBERSECURITY", "Issue": "Incident", "Sub_Issue": None if new else str(rng.choice(["USER - MALICIOUS ACTIVITY", "EMAIL - PHISING", "NETWORK - CLOUD"])),
            "Priority": pr, "Status": "Closed", "Source": str(rng.choice(["Alert", "Alert", "Email"])), "Team": "SOC", "Owner": str(rng.choice(OWNERS)),
            "Cause Code": None if new else str(rng.choice(["Prevented", "Breach - Reported", None])),
            "Active DateTime": created + pd.Timedelta(minutes=act), "Duration Active (Minutes)": act, "FlagBreachResponse": breach,
            "Response_meet/breach": "BREACHED" if breach else "MET", "Resolved Date Time": resolved,
            "Duration Resolved (Minutes)": None if resolved is None else (resolved - created).total_seconds() / 60, "FlagBreachReso": 0, "Resolution_meet/breach": "MET"}


def make_raw(year=2026, month=9, n_old=60, n_new=50, cutover=CUTOVER, seed=1, new_only=False):
    rng = np.random.default_rng(seed)
    rows, tid = [], 2_000_000
    start = pd.Timestamp(year=year, month=month, day=1)
    end = start + pd.offsets.MonthBegin(1)
    if new_only:
        cutover = start
        n_old = 0
    old_times = sorted(start + pd.Timedelta(seconds=float(x)) for x in rng.uniform(0, (cutover - start).total_seconds() - 60, n_old)) if n_old else []
    new_times = sorted(cutover + pd.Timedelta(seconds=float(x) + 1) for x in rng.uniform(0, (end - cutover).total_seconds() - 120, n_new))
    for t in old_times:
        tid += 7
        rows.append(_row(tid, t, "old", rng))
    for t in new_times:
        tid += 7
        rows.append(_row(tid, t, "new", rng))
    return pd.DataFrame(rows, columns=COLS)


def to_xlsx_bytes(df, sheet="SOC"):
    b = io.BytesIO()
    with pd.ExcelWriter(b, engine="openpyxl") as w:
        df.to_excel(w, sheet_name=sheet, index=False)
    return b.getvalue()


def make_df(**kw):
    from soc_incident.loader import detect_mapping, normalize
    raw = make_raw(**kw)
    df, _ = normalize(raw, detect_mapping(raw.columns))
    return df
