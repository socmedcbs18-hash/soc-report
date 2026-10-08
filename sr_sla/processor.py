"""
SLA SR Security Operations - Processor
=========================================================
Hitung KPI, performa per Technician, dan histori bulanan dari data SR yang
sudah dinormalisasi. MODUL TERPISAH dari SOC/Cynet/IOC.
"""

from pathlib import Path

import pandas as pd

HISTORY_DIR = Path("database") / "sr_sla_monthly_raw"


# =========================================================
# PENYIMPANAN HISTORI (pola sama seperti Cynet - snapshot detail per periode)
# =========================================================

def save_period_snapshot(data, period_key):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    data.to_csv(HISTORY_DIR / f"{period_key}.csv", index=False)


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
    for col in ["CreatedOn", "ResolvedOn"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    return df


# =========================================================
# SUMMARY & KPI
# =========================================================

def build_summary(data):
    total = len(data)
    resp_breach = int((data["Response Meet/Breach"] == "BREACHED").sum())
    reso_breach = int((data["Resolution Meet/Breach"] == "BREACHED").sum())
    resp_valid = data["Response Meet/Breach"].isin(["MET", "BREACHED"]).sum()
    reso_valid = data["Resolution Meet/Breach"].isin(["MET", "BREACHED"]).sum()

    return {
        "Total_SR": total,
        "Response_Breach": resp_breach,
        "Response_Breach_%": round(100 * resp_breach / max(resp_valid, 1), 1),
        "Resolution_Breach": reso_breach,
        "Resolution_Breach_%": round(100 * reso_breach / max(reso_valid, 1), 1),
        "Avg_Resolution_Hours": round(data["Resolution_Duration_Hours"].dropna().mean(), 1)
                                  if data["Resolution_Duration_Hours"].notna().any() else None,
        "Closed": int((data["Status"] == "Closed").sum()) if "Status" in data.columns else None,
        "Open": total - int((data["Status"] == "Closed").sum()) if "Status" in data.columns else None,
    }


def build_technician_performance(data):
    """Performa per individu - Total SR ditangani, breach Response/Resolution,
    breach rate %, rata-rata durasi resolusi. Technician 'Unassigned'
    TETAP dihitung (transparansi - berapa banyak SR belum ditugaskan),
    tapi diurutkan PALING BAWAH (bukan bagian penilaian performa individu)."""
    rows = []
    for tech, grp in data.groupby("Technician"):
        n = len(grp)
        resp_breach = int((grp["Response Meet/Breach"] == "BREACHED").sum())
        reso_breach = int((grp["Resolution Meet/Breach"] == "BREACHED").sum())
        avg_hours = grp["Resolution_Duration_Hours"].dropna().mean()
        rows.append({
            "Technician": tech,
            "Total_SR": n,
            "Response_Breach": resp_breach,
            "Resolution_Breach": reso_breach,
            "Breach_Rate_%": round(100 * reso_breach / max(n, 1), 1),
            "Avg_Resolution_Hours": round(avg_hours, 1) if pd.notna(avg_hours) else None,
        })
    result = pd.DataFrame(rows)
    is_unassigned = result["Technician"] == "Unassigned"
    result = pd.concat([
        result[~is_unassigned].sort_values("Resolution_Breach", ascending=False),
        result[is_unassigned],
    ], ignore_index=True)
    return result


def build_breach_detail(data):
    """Daftar SR yang breach (Response ATAU Resolution) - untuk drill-down
    'siapa saja yang melakukan breach' sesuai permintaan user."""
    mask = (data["Response Meet/Breach"] == "BREACHED") | (data["Resolution Meet/Breach"] == "BREACHED")
    cols = ["ServiceReqNumber", "Technician", "Service", "ServiceRequestName", "Status",
            "CreatedOn", "ResolvedOn", "Resolution_Duration_Hours",
            "Response Meet/Breach", "Resolution Meet/Breach"]
    cols = [c for c in cols if c in data.columns]
    return data[mask][cols].sort_values("Resolution_Duration_Hours", ascending=False, na_position="last")


# =========================================================
# TREND LINTAS BULAN
# =========================================================

def build_trend(all_periods_data):
    """all_periods_data: dict {period_key: dataframe}. Trend Total SR,
    Breach count, Breach rate lintas bulan."""
    rows = []
    for period, df in sorted(all_periods_data.items()):
        s = build_summary(df)
        rows.append({
            "Period": period, "Total_SR": s["Total_SR"],
            "Response_Breach": s["Response_Breach"], "Resolution_Breach": s["Resolution_Breach"],
            "Resolution_Breach_%": s["Resolution_Breach_%"],
        })
    return pd.DataFrame(rows)


# =========================================================
# INSIGHT DINAMIS
# =========================================================

def generate_insights(summary, tech_perf, trend_df=None):
    insights = []
    insights.append(f"**Total SR periode ini**: {summary['Total_SR']:,} tiket, "
                    f"{summary['Resolution_Breach']} di antaranya breach SLA Resolution "
                    f"({summary['Resolution_Breach_%']}%).")

    non_unassigned = tech_perf[tech_perf["Technician"] != "Unassigned"]
    if len(non_unassigned) > 0:
        top = non_unassigned.iloc[0]
        if top["Resolution_Breach"] > 0:
            insights.append(f"**Technician dengan breach terbanyak**: {top['Technician']} "
                            f"({top['Resolution_Breach']} breach dari {top['Total_SR']} SR ditangani, "
                            f"{top['Breach_Rate_%']}% breach rate).")

        best = non_unassigned.sort_values("Breach_Rate_%").iloc[0]
        if best["Total_SR"] >= 5 and best["Breach_Rate_%"] == 0:
            insights.append(f"**Performa terbaik**: {best['Technician']} - 0% breach dari "
                            f"{best['Total_SR']} SR yang ditangani.")

    unassigned_row = tech_perf[tech_perf["Technician"] == "Unassigned"]
    if len(unassigned_row) > 0 and unassigned_row.iloc[0]["Total_SR"] > 0:
        insights.append(f"**Perlu perhatian**: {int(unassigned_row.iloc[0]['Total_SR'])} SR belum "
                        "ditugaskan ke Technician manapun.")

    if trend_df is not None and len(trend_df) >= 2:
        last2 = trend_df.tail(2)
        prev_rate, curr_rate = last2.iloc[0]["Resolution_Breach_%"], last2.iloc[1]["Resolution_Breach_%"]
        diff = round(curr_rate - prev_rate, 1)
        if diff > 0:
            insights.append(f"**Tren memburuk**: Breach rate naik {diff} poin persen dibanding bulan lalu.")
        elif diff < 0:
            insights.append(f"**Tren membaik**: Breach rate turun {abs(diff)} poin persen dibanding bulan lalu.")

    return insights
