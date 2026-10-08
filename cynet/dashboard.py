"""
Cynet Agent Compliance Dashboard - v2 (Simplified: Summary + Details)
=========================================================
Restrukturisasi dari versi sebelumnya (5 submenu terpisah) jadi 2 halaman
sesuai permintaan user: "Summary" (BoD/management, gaya BI eksekutif) dan
"Details" (SOC/IT, device-level). SELF-CONTAINED - tidak mengimpor apapun
dari app.py/core/ (SOC).

loader.py & processor.py TIDAK DIUBAH (business logic sudah benar & teruji
dengan 6 bulan data asli) - restrukturisasi ini murni di layer presentasi.
"""

import re

import pandas as pd
import streamlit as st

from cynet.loader import load_cynet_excel
from cynet.processor import (
    save_period_snapshot, list_available_periods, load_period_snapshot, period_exists,
    build_summary, build_os_breakdown, build_non_compliant_detail,
    build_upgrade_tracking, build_upgrade_summary,
    build_persistent_non_compliance, generate_insights,
)

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_OK = True
except ImportError:
    PLOTLY_OK = False

COLOR_GOOD = "#0F9D58"      # compliant / improvement / upgraded
COLOR_BAD = "#DB4437"       # regression / critical attention
COLOR_NEUTRAL = "#9AA0A6"   # already compliant / unchanged / missing
COLOR_ACCENT = "#4285F4"
# Warna IDENTITAS konsisten untuk Endpoint vs Server - dipakai SAMA di
# SEMUA chart (Compliance Trend, Total Device Trend, Non-Compliant by OS)
# supaya tidak membingungkan seperti sebelumnya (Server pernah merah di 1
# chart, abu-abu di chart lain).
COLOR_ENDPOINT = "#4285F4"  # biru
COLOR_SERVER = "#F57C00"    # oranye/jingga


def _chart_key(name):
    if "_cynet_v2_chart_counter" not in st.session_state:
        st.session_state["_cynet_v2_chart_counter"] = 0
    st.session_state["_cynet_v2_chart_counter"] += 1
    return f"cynetv2_{name}_{st.session_state['_cynet_v2_chart_counter']}"


def _plot_bar_horizontal(df, label_col, value_col, color=COLOR_ACCENT):
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data)")
        return
    if not PLOTLY_OK:
        st.bar_chart(df.set_index(label_col)[value_col], key=_chart_key("fallback"))
        return
    fig = px.bar(df, x=value_col, y=label_col, orientation="h", text_auto=True,
                 color_discrete_sequence=[color])
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="white",
                       paper_bgcolor="white", font=dict(size=14), showlegend=False,
                       yaxis=dict(categoryorder="total ascending"))
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
    # color_map: dict {nama_kolom: warna} - EKSPLISIT per kolom, bukan urutan
    # implisit (sebelumnya bug: Server_% kebagian warna merah cuma karena
    # urutan daftar, bukan karena memang dimaksudkan begitu).
    color_discrete_map = color_map if color_map else {}
    fig = px.line(df, x=x_col, y=y_cols, markers=True, color_discrete_map=color_discrete_map)
    fig.update_traces(line=dict(width=3), marker=dict(size=9))
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="white",
                       paper_bgcolor="white", font=dict(size=14), legend=dict(orientation="h", y=-0.2))
    fig.update_xaxes(type="category")
    st.plotly_chart(fig, use_container_width=True, key=_chart_key("trend"))


def _plot_stacked_bar_device(df, x_col, y_cols, colors, total_col=None):
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data)")
        return
    if not PLOTLY_OK:
        st.bar_chart(df.set_index(x_col)[y_cols], key=_chart_key("fallback"))
        return
    df = df.copy()
    df[x_col] = df[x_col].astype(str)
    fig = go.Figure()
    for col, color in zip(y_cols, colors):
        fig.add_trace(go.Bar(name=col, x=df[x_col], y=df[col], marker_color=color, text=df[col], textposition="inside"))
    fig.update_layout(barmode="stack", margin=dict(l=10, r=10, t=30, b=10), plot_bgcolor="white",
                       paper_bgcolor="white", font=dict(size=14), legend=dict(orientation="h", y=-0.2))
    fig.update_xaxes(type="category")
    # Label TOTAL di atas tiap bar - supaya tidak perlu jumlah manual
    # Endpoint+Server (sesuai permintaan user).
    if total_col and total_col in df.columns:
        fig.add_trace(go.Scatter(
            x=df[x_col], y=df[total_col], mode="text",
            text=[f"<b>{v:,}</b>" for v in df[total_col]],
            textposition="top center", textfont=dict(size=13, color="#202124"),
            showlegend=False, hoverinfo="skip",
        ))
        fig.update_yaxes(range=[0, df[total_col].max() * 1.15])
    st.plotly_chart(fig, use_container_width=True, key=_chart_key("stacked"))


def _upgrade_funnel(upgrade_summary):
    if not PLOTLY_OK:
        st.write(upgrade_summary)
        return
    labels = ["Upgraded", "Still Non-Compliant", "Missing", "Regression"]
    values = [upgrade_summary["Upgraded"], upgrade_summary["Still_Non_Compliant"],
              upgrade_summary["Missing_Previously_Non_Compliant"], upgrade_summary["Regression"]]
    colors = [COLOR_GOOD, COLOR_BAD, COLOR_NEUTRAL, COLOR_BAD]
    fig = go.Figure(go.Bar(x=values, y=labels, orientation="h", marker_color=colors, text=values, textposition="outside"))
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="white", paper_bgcolor="white",
                       font=dict(size=14), showlegend=False,
                       title=f"Previous Non-Compliant Basis: {upgrade_summary['Previous_Non_Compliant_Basis']} devices")
    st.plotly_chart(fig, use_container_width=True, key=_chart_key("funnel"))


# =========================================================
# UPLOAD & PERIOD GUESSING
# =========================================================

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
    st.sidebar.subheader("Cynet Agent Compliance")
    st.sidebar.markdown("**Data Upload**")
    uploaded_file = st.sidebar.file_uploader("Excel file", type=["xlsx"], key="cynet_v2_upload")

    if uploaded_file is not None:
        guessed = _guess_period_from_filename(uploaded_file.name) or ""
        period_input = st.sidebar.text_input("Reporting Period (YYYY-MM)", value=guessed, key="cynet_v2_period_input")

        already_exists = period_input.strip() and period_exists(period_input.strip())
        if already_exists:
            st.sidebar.warning(f"⚠️ Reporting period **{period_input.strip()}** already exists. "
                                "Klik 'Process / Save' lagi untuk REPLACE data yang ada.")

        if st.sidebar.button("Process / Save", type="primary", key="cynet_v2_btn_process"):
            if not period_input.strip():
                st.sidebar.error("Reporting Period wajib diisi (format YYYY-MM).")
            else:
                try:
                    with st.spinner("Memproses file..."):
                        data, dq_report = load_cynet_excel(uploaded_file)
                        if len(data) == 0:
                            raise ValueError("Tidak ada data valid (sheet Endpoints/Servers kosong/tidak ketemu).")
                        save_period_snapshot(data, period_input.strip())
                    st.sidebar.success(f"✅ Period '{period_input.strip()}' saved.")
                    st.session_state["cynet_v2_dq_report"] = dq_report
                except KeyError as e:
                    st.sidebar.error(f"Invalid Cynet input format: {e}")
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


# =========================================================
# MAIN RENDER
# =========================================================

def render_cynet_compliance_dashboard():
    st.markdown(f"""
    <style>
        [data-testid="stMetric"] {{ border-left: 4px solid {COLOR_GOOD} !important; background: #FAFBFC; border-radius: 6px; padding: 10px 14px !important; }}
    </style>
    """, unsafe_allow_html=True)

    periods = _render_sidebar()

    st.title("Cynet Agent Compliance")

    if not periods:
        st.info("ℹ️ Belum ada data. Upload file Excel Cynet bulanan di sidebar untuk mulai.")
        return

    # ---- Reporting Period + Compare selector (bagian atas, sesuai spec) ----
    top1, top2, top3 = st.columns([2, 2, 3])
    with top1:
        current_period = st.selectbox("Reporting Period", periods, index=len(periods) - 1, key="cynet_v2_current_period")
    idx = periods.index(current_period)
    with top2:
        compare_mode = st.selectbox("Compare", ["Previous Month", "Last 3 Months", "Last 6 Months", "None"], key="cynet_v2_compare_mode")

    # PENTING: prev_period (dipakai untuk KPI "Upgraded This Month",
    # "Compliant"/"Non-Compliant" delta, dan Upgrade Tracking) SEKARANG
    # BENAR-BENAR ikut berubah sesuai pilihan Compare - sebelumnya bug:
    # prev_period selalu "1 bulan sebelumnya" APAPUN pilihan Compare-nya,
    # cuma trend chart yang berubah rentangnya - bikin ambigu (user pilih
    # "Last 6 Months" tapi KPI/header tetap cuma bandingkan vs bulan lalu).
    if compare_mode == "Previous Month":
        prev_period = periods[idx - 1] if idx > 0 else None
        trend_periods = periods[max(0, idx - 5):idx + 1]  # trend chart tetap tampilkan s/d 6 bulan biar ada konteks
    elif compare_mode == "Last 3 Months":
        prev_period = periods[max(0, idx - 2)] if idx > 0 else None
        trend_periods = periods[max(0, idx - 2):idx + 1]
    elif compare_mode == "Last 6 Months":
        prev_period = periods[max(0, idx - 5)] if idx > 0 else None
        trend_periods = periods[max(0, idx - 5):idx + 1]
    else:
        prev_period = None
        trend_periods = [current_period]

    # Kalau prev_period == current_period (mis. baru ada 1 periode di
    # window yang dipilih), anggap tidak ada pembanding - jangan bandingkan
    # periode dengan dirinya sendiri.
    if prev_period == current_period:
        prev_period = None

    with top3:
        if prev_period:
            st.caption(f"Comparing **{current_period}** vs **{prev_period}** ({compare_mode})")
        else:
            st.caption("Historical comparison is not available yet. Upload previous month data.")

    curr_data = load_period_snapshot(current_period)
    prev_data = load_period_snapshot(prev_period) if prev_period else None

    summary_df, overall = build_summary(curr_data)
    os_ep = build_os_breakdown(curr_data, "Endpoint")
    os_sv = build_os_breakdown(curr_data, "Server")

    upgrade_df, upgrade_summary = None, None
    if prev_data is not None:
        upgrade_df = build_upgrade_tracking(prev_data, curr_data)
        upgrade_summary = build_upgrade_summary(upgrade_df)

    # ---- Data Quality Warning (dari upload terakhir, kalau ada) ----
    dq_report = st.session_state.get("cynet_v2_dq_report")
    if dq_report is not None and len(dq_report) > 0:
        cross_overlap = dq_report.attrs.get("cross_overlap_endpoint_server", 0)
        n_invalid = dq_report.attrs.get("n_invalid_version", 0)
        dup_total = int(dq_report["Duplikat_Hostname_Dibuang"].sum())
        if cross_overlap > 0 or n_invalid > 0 or dup_total > 0:
            msgs = []
            if dup_total > 0:
                msgs.append(f"{dup_total} duplicate hostnames detected")
            if cross_overlap > 0:
                msgs.append(f"{cross_overlap} devices appear in both Endpoint & Server")
            if n_invalid > 0:
                msgs.append(f"{n_invalid} devices have invalid Agent Version")
            st.warning("⚠️ Data Quality Warning: " + " | ".join(msgs))

    page = st.radio("Navigation", ["Summary", "Details"], horizontal=True, key="cynet_v2_page")
    st.divider()

    # =====================================================
    # SUMMARY PAGE
    # =====================================================
    if page == "Summary":
        # --- Row 1: KPI Cards ---
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Total Devices", f"{overall['Total_Devices']:,}")
        c2.metric("Endpoint", f"{overall['Total_Endpoint']:,}")
        c3.metric("Server", f"{overall['Total_Server']:,}")
        c4.metric("Compliant ≥ 4.30", f"{overall['Compliance_%']}%" if overall["Compliance_%"] is not None else "-",
                   help=f"{overall['Compliant']:,} devices")
        c5.metric("Non-Compliant", f"{overall['Non_Compliant']:,}",
                   help=f"{round(100*overall['Non_Compliant']/max(overall['Compliant']+overall['Non_Compliant'],1),1)}% of valid devices")
        if upgrade_summary is not None:
            c6.metric("Upgraded This Month", upgrade_summary["Upgraded"],
                       delta=f"{upgrade_summary['Upgrade_Rate_%']}% rate" if upgrade_summary["Upgrade_Rate_%"] is not None else None)
        else:
            c6.metric("Upgraded This Month", "-")

        st.divider()

        # --- Row 2: Compliance Trend + Total Device Trend ---
        r2c1, r2c2 = st.columns(2)
        with r2c1:
            st.markdown("##### Cynet Compliance Trend")
            trend_rows = []
            for p in trend_periods:
                d = load_period_snapshot(p)
                s_df, o = build_summary(d)
                ep_row = s_df[s_df["Category"] == "Endpoint"]
                sv_row = s_df[s_df["Category"] == "Server"]
                trend_rows.append({
                    "Month": p,
                    "Endpoint_%": ep_row["Compliance_%"].iloc[0] if len(ep_row) > 0 else None,
                    "Server_%": sv_row["Compliance_%"].iloc[0] if len(sv_row) > 0 else None,
                    "Overall_%": o["Compliance_%"],
                    "Endpoint": o["Total_Endpoint"], "Server": o["Total_Server"], "Total": o["Total_Devices"],
                })
            trend_df = pd.DataFrame(trend_rows)
            _plot_trend_line(trend_df, "Month", ["Overall_%", "Endpoint_%", "Server_%"],
                              color_map={"Overall_%": COLOR_GOOD, "Endpoint_%": COLOR_ENDPOINT, "Server_%": COLOR_SERVER})
        with r2c2:
            st.markdown("##### Total Device Trend")
            if len(trend_df) >= 1:
                _plot_stacked_bar_device(trend_df, "Month", ["Endpoint", "Server"], [COLOR_ENDPOINT, COLOR_SERVER], total_col="Total")
            else:
                st.caption("(Belum ada data)")

        st.divider()

        # --- Row 3: OS Breakdown ---
        r3c1, r3c2 = st.columns(2)
        with r3c1:
            st.markdown("##### Server – Non-Compliant by OS")
            if len(os_sv) > 0 and os_sv["Non_Compliant"].sum() > 0:
                _plot_bar_horizontal(os_sv[os_sv["Non_Compliant"] > 0], "OS", "Non_Compliant", color=COLOR_SERVER)
            else:
                st.success("✓ No non-compliant servers.")
        with r3c2:
            st.markdown("##### Endpoint – Non-Compliant by OS")
            if len(os_ep) > 0 and os_ep["Non_Compliant"].sum() > 0:
                _plot_bar_horizontal(os_ep[os_ep["Non_Compliant"] > 0], "OS", "Non_Compliant", color=COLOR_ENDPOINT)
            else:
                st.success("✓ No non-compliant endpoints.")

        st.divider()

        # --- Row 4: Upgrade Tracking + Key Insights ---
        r4c1, r4c2 = st.columns(2)
        with r4c1:
            st.markdown("##### Upgrade Tracking (SOP Progress)")
            if upgrade_summary is not None:
                _upgrade_funnel(upgrade_summary)
                rate = upgrade_summary["Upgrade_Rate_%"]
                if rate is not None:
                    if rate >= 70:
                        st.success(f"✓ {rate}% upgraded ({upgrade_summary['Upgraded']} of {upgrade_summary['Previous_Non_Compliant_Basis']}) - upgrade progress on track.")
                    elif rate >= 30:
                        st.warning(f"⚠️ {rate}% upgraded ({upgrade_summary['Upgraded']} of {upgrade_summary['Previous_Non_Compliant_Basis']}) - {upgrade_summary['Still_Non_Compliant']} devices remain below 4.30.")
                    else:
                        st.error(f"🔴 Only {rate}% upgraded - {upgrade_summary['Still_Non_Compliant']} devices remain below the minimum Cynet Agent Version 4.30.")
                if upgrade_summary["Regression"] > 0:
                    st.error(f"🔴 Regression: {upgrade_summary['Regression']} devices previously compliant are now below 4.30.")
            else:
                st.info("Historical comparison is not available yet. Upload previous month data.")
        with r4c2:
            st.markdown("##### Key Insights")
            insights = generate_insights(overall, os_ep, os_sv, upgrade_summary)
            for ins in insights[:5]:
                st.markdown(f"- {ins}")

    # =====================================================
    # DETAILS PAGE
    # =====================================================
    else:
        st.markdown(f"### Device Details - {current_period}")

        detail = curr_data.copy()
        if prev_data is not None and upgrade_df is not None:
            up_map = upgrade_df.set_index("Hostname")[["Previous_Version", "Upgrade_Status"]]
            detail = detail.merge(
                up_map, left_on="Hostname_Raw", right_index=True, how="left"
            )
        else:
            detail["Previous_Version"] = None
            detail["Upgrade_Status"] = None

        detail["Compliance_Status"] = detail["Is_Compliant_Calculated"].map(
            {True: "Compliant", False: "Non-Compliant"}
        ).fillna("Unknown")

        fc1, fc2, fc3, fc4 = st.columns(4)
        with fc1:
            cat_f = st.selectbox("Category", ["All", "Endpoint", "Server"], key="cynet_v2_detail_cat")
        with fc2:
            os_opts = ["All"] + sorted(detail["OS"].dropna().unique().tolist())
            os_f = st.selectbox("OS", os_opts, key="cynet_v2_detail_os")
        with fc3:
            comp_f = st.selectbox("Compliance Status", ["All", "Compliant", "Non-Compliant", "Unknown"], key="cynet_v2_detail_comp")
        with fc4:
            up_opts = ["All"] + sorted(detail["Upgrade_Status"].dropna().unique().tolist())
            up_f = st.selectbox("Upgrade Status", up_opts, key="cynet_v2_detail_upgrade")

        search = st.text_input("🔍 Search hostname / IP", key="cynet_v2_detail_search")

        filtered = detail.copy()
        if cat_f != "All":
            filtered = filtered[filtered["Asset_Type"] == cat_f]
        if os_f != "All":
            filtered = filtered[filtered["OS"] == os_f]
        if comp_f != "All":
            filtered = filtered[filtered["Compliance_Status"] == comp_f]
        if up_f != "All":
            filtered = filtered[filtered["Upgrade_Status"] == up_f]
        if search.strip():
            s = search.strip().lower()
            filtered = filtered[
                filtered["Hostname_Raw"].str.lower().str.contains(s, na=False) |
                filtered["IP"].astype(str).str.lower().str.contains(s, na=False)
            ]

        st.caption(f"{len(filtered):,} of {len(detail):,} devices")

        display_cols = ["Asset_Type", "Hostname_Raw", "IP", "OS", "Previous_Version",
                         "Agent_Version_Raw", "Compliance_Status", "Upgrade_Status", "First Seen", "Last Seen"]
        display_cols = [c for c in display_cols if c in filtered.columns]
        rename_map = {"Asset_Type": "Category", "Hostname_Raw": "Hostname", "Agent_Version_Raw": "Current Version"}
        st.dataframe(filtered[display_cols].rename(columns=rename_map), use_container_width=True)

        csv_bytes = filtered[display_cols].rename(columns=rename_map).to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export (CSV)", csv_bytes,
                            file_name=f"Cynet_Details_{current_period}.csv", key="cynet_v2_export")
