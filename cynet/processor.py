"""
CyNET Compliance Processor
=========================================================
Hitung compliance, OS breakdown, version distribution, upgrade tracking
antar bulan, dan persistent non-compliance. MODUL TERPISAH dari SOC.

Histori disimpan sebagai snapshot DETAIL PER DEVICE (bukan cuma agregat)
di database/cynet_monthly_raw/{period}.csv - dibutuhkan untuk month-to-
month upgrade tracking (bandingkan device yang SAMA antar bulan).
"""

from pathlib import Path

import pandas as pd

HISTORY_DIR = Path("database") / "cynet_monthly_raw"


# =========================================================
# PENYIMPANAN HISTORI (per periode, detail per device)
# =========================================================

def save_period_snapshot(data, period_key):
    """Simpan snapshot detail 1 bulan. Version_Major/Minor dipisah jadi
    kolom int terpisah (bukan tuple) supaya aman di-roundtrip CSV."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    df = data.copy()
    df["Version_Major"] = df["Agent_Version_Parsed"].apply(lambda v: v[0] if v is not None else None)
    df["Version_Minor"] = df["Agent_Version_Parsed"].apply(lambda v: v[1] if v is not None else None)
    df = df.drop(columns=["Agent_Version_Parsed"])
    df.to_csv(HISTORY_DIR / f"{period_key}.csv", index=False)


def list_available_periods():
    if not HISTORY_DIR.exists():
        return []
    return sorted([p.stem for p in HISTORY_DIR.glob("*.csv")])


def period_exists(period_key):
    return (HISTORY_DIR / f"{period_key}.csv").exists()


def load_period_snapshot(period_key):
    path = HISTORY_DIR / f"{period_key}.csv"
    if not path.exists():
        return None
    df = pd.read_csv(path)
    for col in ["First Seen", "Last Seen"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    df["Agent_Version_Parsed"] = df.apply(
        lambda r: (int(r["Version_Major"]), int(r["Version_Minor"]))
        if pd.notna(r.get("Version_Major")) and pd.notna(r.get("Version_Minor")) else None,
        axis=1,
    )
    return df


# =========================================================
# CURRENT MONTH: SUMMARY, OS BREAKDOWN, VERSION DISTRIBUTION
# =========================================================

def build_summary(data):
    """Per Asset_Type: Total, Compliant, Non-Compliant, Unknown Version,
    Compliance % (dihitung dari Version yang VALID saja - Unknown TIDAK
    dianggap Compliant maupun dimasukkan ke penyebut %, sesuai instruksi
    'Unknown/Invalid Version' harus jadi data-quality insight terpisah)."""
    rows = []
    for asset_type in ["Endpoint", "Server"]:
        d = data[data["Asset_Type"] == asset_type]
        total = len(d)
        compliant = int((d["Is_Compliant_Calculated"] == True).sum())
        non_compliant = int((d["Is_Compliant_Calculated"] == False).sum())
        unknown = int(d["Is_Compliant_Calculated"].isna().sum())
        valid_total = compliant + non_compliant
        pct = round(100 * compliant / valid_total, 1) if valid_total > 0 else None
        rows.append({
            "Category": asset_type, "Total": total, "Compliant": compliant,
            "Non_Compliant": non_compliant, "Unknown_Version": unknown,
            "Compliance_%": pct,
        })
    summary_df = pd.DataFrame(rows)

    total_all = int(summary_df["Total"].sum())
    compliant_all = int(summary_df["Compliant"].sum())
    non_compliant_all = int(summary_df["Non_Compliant"].sum())
    unknown_all = int(summary_df["Unknown_Version"].sum())
    valid_all = compliant_all + non_compliant_all
    pct_all = round(100 * compliant_all / valid_all, 1) if valid_all > 0 else None

    overall = {
        "Total_Devices": total_all, "Total_Endpoint": int(summary_df.loc[summary_df["Category"] == "Endpoint", "Total"].sum()),
        "Total_Server": int(summary_df.loc[summary_df["Category"] == "Server", "Total"].sum()),
        "Compliant": compliant_all, "Non_Compliant": non_compliant_all,
        "Unknown_Version": unknown_all, "Compliance_%": pct_all,
    }
    return summary_df, overall


def build_os_breakdown(data, asset_type):
    """Non-compliance breakdown per OS, untuk 1 Asset_Type - TOTAL, bukan
    cuma count non-compliant saja (sesuai instruksi bagian 8: tampilkan
    Total/Non-Compliant/Compliance% per OS, supaya kelihatan kalau masalah
    terkonsentrasi di 1 OS tertentu)."""
    d = data[data["Asset_Type"] == asset_type]
    if len(d) == 0:
        return pd.DataFrame()
    rows = []
    for os_name, grp in d.groupby("OS"):
        total = len(grp)
        compliant = int((grp["Is_Compliant_Calculated"] == True).sum())
        non_compliant = int((grp["Is_Compliant_Calculated"] == False).sum())
        valid = compliant + non_compliant
        pct = round(100 * compliant / valid, 1) if valid > 0 else None
        rows.append({"OS": os_name, "Total": total, "Compliant": compliant,
                     "Non_Compliant": non_compliant, "Compliance_%": pct})
    return pd.DataFrame(rows).sort_values("Non_Compliant", ascending=False).reset_index(drop=True)


def build_version_distribution(data):
    return (
        data.groupby("Agent_Version_Raw").size().reset_index(name="Count")
        .sort_values("Count", ascending=False).reset_index(drop=True)
    )


def build_non_compliant_detail(data):
    """Tabel device Non-Compliant (Agent Version < 4.30) - untuk filter &
    sorting di UI (bagian 9)."""
    d = data[data["Is_Compliant_Calculated"] == False].copy()
    d["Version_Sort_Key"] = d["Agent_Version_Parsed"].apply(lambda v: v if v is not None else (0, 0))
    cols = ["Hostname_Raw", "IP", "Asset_Type", "OS", "Agent_Version_Raw", "First Seen", "Last Seen", "Version_Sort_Key"]
    cols = [c for c in cols if c in d.columns]
    return d[cols].rename(columns={"Hostname_Raw": "Hostname"})


# =========================================================
# UPGRADE TRACKING (bulan sebelumnya -> bulan berjalan)
# =========================================================

def build_upgrade_tracking(prev_data, curr_data):
    """Bandingkan device yang SAMA (by Hostname_Key) antar 2 periode.
    Klasifikasi PERSIS sesuai definisi instruksi bagian 11:
    - Upgraded: prev Non-Compliant -> curr Compliant
    - Still Non-Compliant: prev Non-Compliant -> curr Non-Compliant
    - Already Compliant: prev Compliant -> curr Compliant
    - Regression: prev Compliant -> curr Non-Compliant
    - No Longer Seen / Missing: ada di prev, TIDAK ADA di curr (JANGAN
      dianggap upgraded/compliant - instruksi eksplisit)
    - New Device: ada di curr, TIDAK ADA di prev
    """
    prev = prev_data[["Hostname_Key", "Hostname_Raw", "Asset_Type", "Agent_Version_Raw", "Is_Compliant_Calculated"]].rename(
        columns={"Agent_Version_Raw": "Previous_Version", "Is_Compliant_Calculated": "Previous_Compliant"}
    )
    curr = curr_data[["Hostname_Key", "Hostname_Raw", "Asset_Type", "Agent_Version_Raw", "Is_Compliant_Calculated"]].rename(
        columns={"Agent_Version_Raw": "Current_Version", "Is_Compliant_Calculated": "Current_Compliant"}
    )

    merged = prev.merge(curr, on="Hostname_Key", how="outer", suffixes=("_prev", "_curr"))

    def classify(row):
        in_prev = pd.notna(row.get("Previous_Version"))
        in_curr = pd.notna(row.get("Current_Version"))
        if in_prev and not in_curr:
            return "No Longer Seen / Missing"
        if in_curr and not in_prev:
            return "New Device"
        pc, cc = row.get("Previous_Compliant"), row.get("Current_Compliant")
        if pc is False and cc is True:
            return "Upgraded"
        if pc is False and cc is False:
            return "Still Non-Compliant"
        if pc is True and cc is True:
            return "Already Compliant"
        if pc is True and cc is False:
            return "Regression / Downgraded"
        return "Unknown (versi tidak valid di salah satu periode)"

    merged["Upgrade_Status"] = merged.apply(classify, axis=1)
    merged["Hostname"] = merged["Hostname_Raw_curr"].fillna(merged["Hostname_Raw_prev"])
    merged["Category"] = merged["Asset_Type_curr"].fillna(merged["Asset_Type_prev"])

    result = merged[["Hostname", "Category", "Previous_Version", "Previous_Compliant",
                      "Current_Version", "Current_Compliant", "Upgrade_Status"]]
    return result


def build_upgrade_summary(upgrade_df):
    """Ringkasan jumlah per kategori Upgrade_Status + Upgrade Rate."""
    counts = upgrade_df["Upgrade_Status"].value_counts().to_dict()
    prev_non_compliant = counts.get("Upgraded", 0) + counts.get("Still Non-Compliant", 0)
    # No Longer Seen yang sebelumnya Non-Compliant JUGA bagian dari basis
    # "Previous Non-Compliant" tapi TIDAK dihitung sebagai upgraded (instruksi eksplisit)
    missing_prev_noncompliant = len(upgrade_df[
        (upgrade_df["Upgrade_Status"] == "No Longer Seen / Missing") &
        (upgrade_df["Previous_Compliant"] == False)
    ])
    total_prev_non_compliant_basis = prev_non_compliant + missing_prev_noncompliant
    upgrade_rate = (
        round(100 * counts.get("Upgraded", 0) / total_prev_non_compliant_basis, 1)
        if total_prev_non_compliant_basis > 0 else None
    )
    return {
        "Previous_Non_Compliant_Basis": total_prev_non_compliant_basis,
        "Upgraded": counts.get("Upgraded", 0),
        "Still_Non_Compliant": counts.get("Still Non-Compliant", 0),
        "Missing_Previously_Non_Compliant": missing_prev_noncompliant,
        "Regression": counts.get("Regression / Downgraded", 0),
        "New_Device": counts.get("New Device", 0),
        "Upgrade_Rate_%": upgrade_rate,
    }


# =========================================================
# PERSISTENT NON-COMPLIANCE (lintas banyak bulan)
# =========================================================

def build_persistent_non_compliance(all_periods_data, min_months=2):
    """all_periods_data: dict {period_key: dataframe}. Cari device yang
    Non-Compliant TERUS-MENERUS di >= min_months bulan TERAKHIR berturut."""
    if len(all_periods_data) < min_months:
        return pd.DataFrame()

    sorted_periods = sorted(all_periods_data.keys())
    recent_periods = sorted_periods[-min_months:]

    device_status = {}
    for period in recent_periods:
        df = all_periods_data[period]
        for _, row in df.iterrows():
            key = row["Hostname_Key"]
            if key not in device_status:
                device_status[key] = {"Hostname": row["Hostname_Raw"], "Category": row["Asset_Type"], "statuses": []}
            device_status[key]["statuses"].append(row["Is_Compliant_Calculated"])

    persistent = []
    for key, info in device_status.items():
        if len(info["statuses"]) == len(recent_periods) and all(s is False for s in info["statuses"]):
            persistent.append({
                "Hostname": info["Hostname"], "Category": info["Category"],
                "Non_Compliant_Since": recent_periods[0],
                "Months_Persistent": len(recent_periods),
            })
    return pd.DataFrame(persistent)


def find_oldest_non_compliant(all_periods_data):
    """Device yang paling lama berstatus Non-Compliant, dilihat dari
    periode PALING AWAL di histori yang tersedia dia sudah Non-Compliant
    dan MASIH Non-Compliant di periode terakhir."""
    if len(all_periods_data) < 2:
        return pd.DataFrame()
    sorted_periods = sorted(all_periods_data.keys())
    latest_period = sorted_periods[-1]
    latest_df = all_periods_data[latest_period]
    latest_noncompliant_keys = set(latest_df[latest_df["Is_Compliant_Calculated"] == False]["Hostname_Key"])

    first_seen_noncompliant = {}
    for period in sorted_periods:
        df = all_periods_data[period]
        nc = df[(df["Is_Compliant_Calculated"] == False) & (df["Hostname_Key"].isin(latest_noncompliant_keys))]
        for _, row in nc.iterrows():
            key = row["Hostname_Key"]
            if key not in first_seen_noncompliant:
                first_seen_noncompliant[key] = {
                    "Hostname": row["Hostname_Raw"], "Category": row["Asset_Type"],
                    "Non_Compliant_Since": period, "Current_Version": None,
                }
    latest_by_key = latest_df.set_index("Hostname_Key")
    for key, info in first_seen_noncompliant.items():
        if key in latest_by_key.index:
            info["Current_Version"] = latest_by_key.loc[key, "Agent_Version_Raw"]

    result = pd.DataFrame(list(first_seen_noncompliant.values()))
    if len(result) > 0:
        result = result.sort_values("Non_Compliant_Since").reset_index(drop=True)
    return result


# =========================================================
# DYNAMIC INSIGHTS (bagian 17 - TIDAK hardcode kalimat, dihasilkan dari data)
# =========================================================

def generate_insights(overall_summary, os_breakdown_endpoint, os_breakdown_server, upgrade_summary=None):
    insights = []

    if overall_summary["Compliance_%"] is not None:
        insights.append(
            f"**Overall Compliance:** {overall_summary['Compliance_%']}% of Cynet-protected devices "
            f"are running Agent version 4.30 or higher."
        )
    insights.append(f"**Non-Compliance:** {overall_summary['Non_Compliant']} devices remain below the required version.")
    if overall_summary["Unknown_Version"] > 0:
        insights.append(f"**Data Quality:** {overall_summary['Unknown_Version']} devices have unknown/invalid Agent Version and could not be classified.")

    if len(os_breakdown_server) > 0:
        top_os_server = os_breakdown_server.iloc[0]
        if top_os_server["Non_Compliant"] > 0:
            insights.append(f"**Server:** Most server non-compliance is concentrated on {top_os_server['OS']} ({int(top_os_server['Non_Compliant'])} devices).")
    if len(os_breakdown_endpoint) > 0:
        top_os_ep = os_breakdown_endpoint.iloc[0]
        if top_os_ep["Non_Compliant"] > 0:
            insights.append(f"**Endpoint:** Most endpoint non-compliance is concentrated on {top_os_ep['OS']} ({int(top_os_ep['Non_Compliant'])} devices).")

    if upgrade_summary is not None:
        u = upgrade_summary
        if u["Previous_Non_Compliant_Basis"] > 0:
            insights.append(
                f"**Upgrade Progress:** {u['Upgraded']} of {u['Previous_Non_Compliant_Basis']} devices "
                f"that were non-compliant in the previous month have been upgraded."
            )
        if u["Still_Non_Compliant"] > 0:
            insights.append(f"**Outstanding:** {u['Still_Non_Compliant']} devices remain below version 4.30 and require follow-up.")
        if u["Regression"] > 0:
            insights.append(f"**Regression:** {u['Regression']} devices previously compliant are now below version 4.30 and require investigation.")
        if u["Missing_Previously_Non_Compliant"] > 0:
            insights.append(f"**Missing:** {u['Missing_Previously_Non_Compliant']} previously non-compliant devices are no longer seen this month - status unknown, NOT counted as upgraded.")

    return insights
