"""
SLA SR Security Operations Dashboard
=========================================================
UI Streamlit untuk SLA SR Security Operations - SELF-CONTAINED, tidak
mengimpor apapun dari app.py/core/cynet/ioc (module isolation). Navigasi
2 halaman (Summary/Details) - pola sama seperti Cynet Agent Compliance.
"""

import re

import pandas as pd
import streamlit as st

from sr_sla.loader import load_sr_excel
from sr_sla.processor import (
    save_period_snapshot, list_available_periods, load_period_snapshot, period_exists,
    build_summary, build_technician_performance, build_breach_detail, build_trend, generate_insights,
)

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_OK = True
except ImportError:
    PLOTLY_OK = False

COLOR_GOOD = "#0F9D58"
COLOR_BAD = "#DB4437"
COLOR_NEUTRAL = "#9AA0A6"
COLOR_ACCENT = "#4285F4"
PALETTE = ["#1F4E78", "#4285F4", "#F57C00", "#0F9D58", "#DB4437", "#9B59B6", "#5CB85C", "#95A5A6"]


def _chart_key(name):
    if "_sr_sla_chart_counter" not in st.session_state:
        st.session_state["_sr_sla_chart_counter"] = 0
    st.session_state["_sr_sla_chart_counter"] += 1
    return f"srsla_{name}_{st.session_state['_sr_sla_chart_counter']}"


def _plot_bar_horizontal(df, label_col, value_col, color=COLOR_ACCENT):
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data)")
        return
    if not PLOTLY_OK:
        st.bar_chart(df.set_index(label_col)[value_col], key=_chart_key("fallback"))
        return
    fig = px.bar(df, x=value_col, y=label_col, orientation="h", text_auto=True, color_discrete_sequence=[color])
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="white", paper_bgcolor="white",
                       font=dict(size=14), showlegend=False, yaxis=dict(categoryorder="total ascending"))
    st.plotly_chart(fig, use_container_width=True, key=_chart_key("bar"))


def _plot_trend_line(df, x_col, y_cols, color_map=None):
    if df is None or len(df) < 2:
        st.caption("Historical comparison is not available yet. Upload previous month data.")
        return
    if not PLOTLY_OK:
        st.line_chart(df.set_index(x_col)[y_cols], key=_chart_key("fallback"))
        return
    df = df.copy()
    df[x_col] = df[x_col].astype(str)
    fig = px.line(df, x=x_col, y=y_cols, markers=True, color_discrete_map=color_map or {})
    fig.update_traces(line=dict(width=3), marker=dict(size=9))
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="white", paper_bgcolor="white",
                       font=dict(size=14), legend=dict(orientation="h", y=-0.2))
    fig.update_xaxes(type="category")
    st.plotly_chart(fig, use_container_width=True, key=_chart_key("trend"))


INDO_MONTHS = {
    "januari": "01", "februari": "02", "maret": "03", "april": "04", "mei": "05", "juni": "06",
    "juli": "07", "agustus": "08", "september": "09", "oktober": "10", "november": "11", "desember": "12",
}


def _guess_period_from_filename(filename):
    m = re.search(r"(20\d{2})[-_]?(\d{2})", filename)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    lower = filename.lower()
    for name, num in INDO_MONTHS.items():
        if name in lower:
            year_m = re.search(r"(20\d{2})", filename)
            year = year_m.group(1) if year_m else str(pd.Timestamp.now().year)
            return f"{year}-{num}"
    return None


def _render_sidebar():
    st.sidebar.subheader("SLA SR Security Operations")
    st.sidebar.markdown("**Data Upload**")
    uploaded_file = st.sidebar.file_uploader("Excel file SR bulanan", type=["xlsx"], key="sr_sla_upload")

    if uploaded_file is not None:
        guessed = _guess_period_from_filename(uploaded_file.name) or ""
        period_input = st.sidebar.text_input("Reporting Period (YYYY-MM)", value=guessed, key="sr_sla_period_input")

        if period_input.strip() and period_exists(period_input.strip()):
            st.sidebar.warning(f"⚠️ Reporting period **{period_input.strip()}** already exists. "
                                "Klik 'Process / Save' lagi untuk REPLACE data yang ada.")

        if st.sidebar.button("Process / Save", type="primary", key="sr_sla_btn_process"):
            if not period_input.strip():
                st.sidebar.error("Reporting Period wajib diisi (format YYYY-MM).")
            else:
                try:
                    with st.spinner("Memproses file..."):
                        data, dq = load_sr_excel(uploaded_file)
                        if len(data) == 0:
                            raise ValueError("Tidak ada data valid di file ini.")
                        save_period_snapshot(data, period_input.strip())
                    if not dq["sheet_matched_expected"]:
                        st.sidebar.warning(f"⚠️ Nama sheet '{dq['sheet_used']}' berbeda dari contoh "
                                           "'Cybersecurity L2 only' - dipakai sheet pertama sebagai fallback, "
                                           "mohon cek datanya benar.")
                    st.sidebar.success(f"✅ Period '{period_input.strip()}' saved ({dq['total_rows']} SR).")
                except KeyError as e:
                    st.sidebar.error(f"Invalid SR input format: {e}")
                except Exception as e:
                    st.sidebar.error(f"Gagal memproses file: {e}")

    periods = list_available_periods()
    st.sidebar.markdown("**Available Data**")
    if periods:
        for p in periods:
            st.sidebar.caption(f"• {p}")
        st.sidebar.caption(f"Total: {len(periods)} period(s)")
    else:
        st.sidebar.caption("Belum ada data.")
    return periods


def render_sr_sla_dashboard():
    st.markdown(f"""
    <style>
        [data-testid="stMetric"] {{ border-left: 4px solid {COLOR_ACCENT} !important; background: #FAFBFC; border-radius: 6px; padding: 10px 14px !important; }}
    </style>
    """, unsafe_allow_html=True)

    periods = _render_sidebar()
    st.title("SLA SR Security Operations")

    if not periods:
        st.info("ℹ️ Belum ada data. Upload file Excel SR bulanan di sidebar untuk mulai.")
        return

    top1, top2, top3 = st.columns([2, 2, 3])
    with top1:
        current_period = st.selectbox("Reporting Period", periods, index=len(periods) - 1, key="sr_sla_current_period")
    idx = periods.index(current_period)
    with top2:
        compare_mode = st.selectbox("Compare", ["Previous Month", "Last 3 Months", "Last 6 Months", "None"], key="sr_sla_compare_mode")

    # prev_period BENAR-BENAR ikut rentang yang dipilih (bukan selalu "1
    # bulan lalu" apapun mode-nya - itu bug yang pernah ditemukan & sudah
    # diperbaiki di modul Cynet, diterapkan konsisten di sini dari awal).
    if compare_mode == "Previous Month":
        prev_period = periods[idx - 1] if idx > 0 else None
        trend_periods = periods[max(0, idx - 5):idx + 1]
    elif compare_mode == "Last 3 Months":
        prev_period = periods[max(0, idx - 2)] if idx > 0 else None
        trend_periods = periods[max(0, idx - 2):idx + 1]
    elif compare_mode == "Last 6 Months":
        prev_period = periods[max(0, idx - 5)] if idx > 0 else None
        trend_periods = periods[max(0, idx - 5):idx + 1]
    else:
        prev_period = None
        trend_periods = [current_period]
    if prev_period == current_period:
        prev_period = None

    with top3:
        if prev_period:
            st.caption(f"Comparing **{current_period}** vs **{prev_period}** ({compare_mode})")
        else:
            st.caption("Historical comparison is not available yet. Upload previous month data.")

    curr_data = load_period_snapshot(current_period)
    prev_data = load_period_snapshot(prev_period) if prev_period else None
    summary = build_summary(curr_data)
    prev_summary = build_summary(prev_data) if prev_data is not None else None
    tech_perf = build_technician_performance(curr_data)
    breach_detail = build_breach_detail(curr_data)

    all_data = {p: load_period_snapshot(p) for p in trend_periods}
    trend_df = build_trend(all_data) if len(trend_periods) >= 2 else None
    trend_df_full = build_trend({p: load_period_snapshot(p) for p in periods}) if len(periods) >= 2 else None

    page = st.radio("Navigation", ["Summary", "Details"], horizontal=True, key="sr_sla_page")
    st.divider()

    # =====================================================
    # SUMMARY
    # =====================================================
    if page == "Summary":
        def _delta(curr_val, prev_val):
            """Format delta vs periode pembanding - None kalau tidak ada
            pembanding atau selisihnya 0 (Streamlit tidak tampilkan delta
            kalau None). Warna delta (naik=merah/turun=hijau untuk metrik
            breach) diatur via delta_color='inverse' di parameter st.metric
            masing-masing, bukan di sini."""
            if prev_summary is None or curr_val is None or prev_val is None:
                return None
            d = round(curr_val - prev_val, 1)
            if d == 0:
                return None
            return f"{'+' if d > 0 else ''}{d}"

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total SR", f"{summary['Total_SR']:,}",
                   delta=_delta(summary["Total_SR"], prev_summary["Total_SR"]) if prev_summary else None)
        c2.metric("Response Breach", summary["Response_Breach"], help=f"{summary['Response_Breach_%']}% dari SR valid",
                   delta=_delta(summary["Response_Breach"], prev_summary["Response_Breach"]) if prev_summary else None,
                   delta_color="inverse")
        c3.metric("Resolution Breach", summary["Resolution_Breach"], help=f"{summary['Resolution_Breach_%']}% dari SR valid",
                   delta=_delta(summary["Resolution_Breach"], prev_summary["Resolution_Breach"]) if prev_summary else None,
                   delta_color="inverse")
        c4.metric("Resolution Breach %", f"{summary['Resolution_Breach_%']}%",
                   delta=_delta(summary["Resolution_Breach_%"], prev_summary["Resolution_Breach_%"]) if prev_summary else None,
                   delta_color="inverse")
        c5.metric("Avg Resolution (jam)", summary["Avg_Resolution_Hours"] if summary["Avg_Resolution_Hours"] else "-",
                   delta=_delta(summary["Avg_Resolution_Hours"], prev_summary["Avg_Resolution_Hours"]) if prev_summary and summary["Avg_Resolution_Hours"] else None,
                   delta_color="inverse")

        st.divider()

        r1c1, r1c2 = st.columns(2)
        with r1c1:
            st.markdown("##### Technician - Resolution Breach Terbanyak")
            non_unassigned = tech_perf[tech_perf["Technician"] != "Unassigned"]
            top_breach = non_unassigned[non_unassigned["Resolution_Breach"] > 0].head(10)
            if len(top_breach) > 0:
                _plot_bar_horizontal(top_breach, "Technician", "Resolution_Breach", color=COLOR_BAD)
            else:
                st.success("✓ Tidak ada breach Resolution periode ini.")
        with r1c2:
            st.markdown("##### Technician - Total SR Ditangani")
            _plot_bar_horizontal(tech_perf, "Technician", "Total_SR", color=COLOR_ACCENT)

        st.divider()
        st.markdown("##### Trend SR & Breach Rate Lintas Bulan")
        if trend_df is not None and len(trend_df) >= 2:
            tr1, tr2 = st.columns(2)
            with tr1:
                _plot_trend_line(trend_df, "Period", ["Total_SR"], color_map={"Total_SR": COLOR_ACCENT})
            with tr2:
                _plot_trend_line(trend_df, "Period", ["Resolution_Breach_%"], color_map={"Resolution_Breach_%": COLOR_BAD})
        else:
            st.info("Historical comparison is not available yet. Upload previous month data.")

        st.divider()
        st.markdown("##### Key Insights")
        insights = generate_insights(summary, tech_perf, trend_df)
        for ins in insights[:5]:
            st.markdown(f"- {ins}")

        st.markdown("##### Ringkasan Performa per Technician")
        st.dataframe(tech_perf, use_container_width=True)

    # =====================================================
    # DETAILS
    # =====================================================
    else:
        st.markdown(f"### SR Details - {current_period}")

        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            tech_opts = ["All"] + sorted(curr_data["Technician"].dropna().unique().tolist())
            f_tech = st.selectbox("Technician", tech_opts, key="sr_sla_detail_tech")
        with fc2:
            status_opts = ["All"] + sorted(curr_data["Status"].dropna().unique().tolist()) if "Status" in curr_data.columns else ["All"]
            f_status = st.selectbox("Status", status_opts, key="sr_sla_detail_status")
        with fc3:
            breach_opts = ["All", "Breach Response atau Resolution", "Breach Resolution saja", "Tidak Breach"]
            f_breach = st.selectbox("Breach Filter", breach_opts, key="sr_sla_detail_breach")

        search = st.text_input("🔍 Search SR Number / Requestor / Service", key="sr_sla_detail_search")

        filtered = curr_data.copy()
        if f_tech != "All":
            filtered = filtered[filtered["Technician"] == f_tech]
        if f_status != "All" and "Status" in filtered.columns:
            filtered = filtered[filtered["Status"] == f_status]
        if f_breach == "Breach Response atau Resolution":
            filtered = filtered[(filtered["Response Meet/Breach"] == "BREACHED") | (filtered["Resolution Meet/Breach"] == "BREACHED")]
        elif f_breach == "Breach Resolution saja":
            filtered = filtered[filtered["Resolution Meet/Breach"] == "BREACHED"]
        elif f_breach == "Tidak Breach":
            filtered = filtered[(filtered["Response Meet/Breach"] != "BREACHED") & (filtered["Resolution Meet/Breach"] != "BREACHED")]
        if search.strip():
            s = search.strip().lower()
            search_cols = [c for c in ["ServiceReqNumber", "Requestor", "Service", "ServiceRequestName"] if c in filtered.columns]
            mask = pd.Series(False, index=filtered.index)
            for c in search_cols:
                mask |= filtered[c].astype(str).str.lower().str.contains(s, na=False)
            filtered = filtered[mask]

        st.caption(f"{len(filtered):,} of {len(curr_data):,} SR")
        st.dataframe(filtered, use_container_width=True)

        csv_bytes = filtered.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export (CSV)", csv_bytes, file_name=f"SR_SLA_Details_{current_period}.csv", key="sr_sla_export")

        st.divider()
        st.markdown("##### Semua SR yang Breach (Response atau Resolution)")
        st.dataframe(breach_detail, use_container_width=True)
