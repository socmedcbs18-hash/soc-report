"""
=========================================================
SOC Report Generator - Streamlit App
=========================================================
Antarmuka upload -> generate -> visualisasi interaktif -> download Excel.
Menggunakan ULANG core module yang sama dengan main.py (loader/normalizer/
validator/processor/excel_writer) - tidak ada logic yang diduplikasi, jadi
hasil dari Streamlit dan dari `python main.py` selalu konsisten.

Cara jalankan (dari folder SOC_Report_Generator, BUKAN dari folder lain):
    streamlit run app.py
=========================================================
"""

import io
from pathlib import Path

import pandas as pd
import streamlit as st

from config.settings import MASTER_RULE_FILE, DOMAIN_MAPPING_FILE
from core.loader import DataLoader
from utils.helpers import read_any_table, normalize_master_rules_columns, normalize_incident_columns
from core.normalizer import RuleNormalizer
from core.validator import Validator
from core.processor import SOCProcessor
from core.excel_writer import ExcelWriter
from core.pptx_writer import PPTXWriter
from core.mitre_killchain import (
    build_mitre_technique_summary, build_mitre_tactic_summary, build_killchain_summary,
    build_mitre_hierarchy, build_mitre_by_killchain_stage, generate_mitre_killchain_insights,
    parse_description_kv,
)

st.set_page_config(page_title="SOC Report Generator", layout="wide")

# =========================================================
# REPORT SELECTION GATE (BARU) - satu-satunya blok yang disisipkan untuk
# navigasi SOC <-> CyNET. TIDAK ADA kode SOC di bawah ini yang diubah -
# kalau selected_report == "SOC", eksekusi jatuh (fall-through) persis ke
# kode SOC existing tanpa modifikasi apapun. Kalau "CYNET", kode SOC di
# bawah TIDAK ikut jalan sama sekali (dihentikan st.stop()).
# =========================================================

if "selected_report" not in st.session_state:
    st.session_state["selected_report"] = None

if st.session_state["selected_report"] is None:
    st.markdown("""
    <style>
        .hero-title {
            font-size: 42px; font-weight: 800; color: #1F4E78; text-align: center;
            margin-top: 30px; margin-bottom: 6px;
        }
        .hero-subtitle {
            font-size: 17px; color: #5A6B85; text-align: center; margin-bottom: 40px;
        }
        .report-card {
            background: linear-gradient(145deg, #F7F9FC 0%, #EAF1FA 100%);
            border: 1px solid #E3E9F2; border-radius: 16px;
            padding: 32px 20px 18px 20px; text-align: center; height: 210px;
            box-shadow: 0 2px 8px rgba(31,78,120,0.06);
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        .report-card:hover { transform: translateY(-4px); box-shadow: 0 8px 20px rgba(31,78,120,0.15); }
        .report-icon { font-size: 52px; margin-bottom: 12px; }
        .report-name { font-size: 20px; font-weight: 700; color: #1F4E78; margin-bottom: 6px; }
        .report-desc { font-size: 13px; color: #5A6B85; line-height: 1.4; }
        div[data-testid="stButton"] button {
            border-radius: 10px !important; font-weight: 600 !important; padding: 10px !important;
            border: 1px solid #1F4E78 !important; color: #1F4E78 !important; background: white !important;
            margin-top: -8px;
        }
        div[data-testid="stButton"] button:hover { background: #1F4E78 !important; color: white !important; }
    </style>
    <div class="hero-title">🛰️ Security Reporting Dashboard</div>
    <div class="hero-subtitle">Pilih jenis laporan yang ingin dibuka</div>
    """, unsafe_allow_html=True)

    st.write("")
    c1, c2, c3, c4, c5 = st.columns(5, gap="small")
    with c1:
        st.markdown("""
        <div class="report-card">
            <div class="report-icon">🛡️</div>
            <div class="report-name">SOC Report</div>
            <div class="report-desc">Monitoring alert, insiden, SLA, MITRE ATT&CK & Cyber Kill Chain bulanan</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Buka SOC Report →", use_container_width=True, key="btn_open_soc"):
            st.session_state["selected_report"] = "SOC"
            st.rerun()
    with c2:
        st.markdown("""
        <div class="report-card">
            <div class="report-icon">🖥️</div>
            <div class="report-name">Cynet Agent Compliance</div>
            <div class="report-desc">Tracking compliance Agent Version endpoint & server, upgrade progress bulanan</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Buka Cynet Compliance →", use_container_width=True, key="btn_open_cynet"):
            st.session_state["selected_report"] = "CYNET"
            st.rerun()
    with c3:
        st.markdown("""
        <div class="report-card">
            <div class="report-icon">🔎</div>
            <div class="report-name">IOC Scoring</div>
            <div class="report-desc">Verifikasi IP dari log firewall - GitHub Threat Feed, VirusTotal, AbuseIPDB, dll</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Buka IOC Scoring →", use_container_width=True, key="btn_open_ioc"):
            st.session_state["selected_report"] = "IOC"
            st.rerun()
    with c4:
        st.markdown("""
        <div class="report-card">
            <div class="report-icon">📋</div>
            <div class="report-name">SLA SR Security Operations</div>
            <div class="report-desc">Tracking Service Request bulanan - breach SLA & performa per Technician</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Buka SLA SR →", use_container_width=True, key="btn_open_sr_sla"):
            st.session_state["selected_report"] = "SR_SLA"
            st.rerun()
    with c5:
        st.markdown("""
        <div class="report-card">
            <div class="report-icon">📊</div>
            <div class="report-name">Cybersecurity Monthly Report</div>
            <div class="report-desc">Upload raw data security device, hasilkan deck PPT bulanan otomatis (tahap 1: IPS)</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Buka Monthly Report →", use_container_width=True, key="btn_open_cybersec"):
            st.session_state["selected_report"] = "CYBERSEC"
            st.rerun()
    st.stop()

if st.sidebar.button("← Back to Report Selection"):
    st.session_state["selected_report"] = None
    st.rerun()

if st.session_state["selected_report"] == "CYNET":
    from cynet.dashboard import render_cynet_compliance_dashboard
    try:
        render_cynet_compliance_dashboard()
    except Exception as e:
        st.error(f"CyNET module mengalami error: {e}")
        st.caption("SOC Report tetap bisa diakses normal - klik '← Back to Report Selection' lalu pilih SOC Report.")
    st.stop()

if st.session_state["selected_report"] == "IOC":
    from ioc.dashboard import render_ioc_dashboard
    try:
        render_ioc_dashboard()
    except Exception as e:
        st.error(f"IOC Scoring module mengalami error: {e}")
        st.caption("SOC Report tetap bisa diakses normal - klik '← Back to Report Selection' lalu pilih SOC Report.")
    st.stop()

if st.session_state["selected_report"] == "SR_SLA":
    from sr_sla.dashboard import render_sr_sla_dashboard
    try:
        render_sr_sla_dashboard()
    except Exception as e:
        st.error(f"SLA SR module mengalami error: {e}")
        st.caption("SOC Report tetap bisa diakses normal - klik '← Back to Report Selection' lalu pilih SOC Report.")
    st.stop()

if st.session_state["selected_report"] == "CYBERSEC":
    from cybersec_report.dashboard import render_cybersec_report_dashboard
    try:
        render_cybersec_report_dashboard()
    except Exception as e:
        st.error(f"Cybersecurity Monthly Report module mengalami error: {e}")
        st.caption("Modul lain tetap bisa diakses normal - klik '← Back to Report Selection'.")
    st.stop()

# ============================================================
# SEMUA KODE DI BAWAH INI = KODE SOC EXISTING, TIDAK DIUBAH SAMA SEKALI
# ============================================================

# =========================================================
# PLOTLY (opsional) - fallback otomatis ke chart bawaan Streamlit
# kalau plotly belum ter-install, supaya app tidak crash.
# =========================================================

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_OK = True
except ImportError:
    PLOTLY_OK = False

NAVY = "#1F4E78"
PALETTE = ["#1F4E78", "#4A90D9", "#7FB3E8", "#F0B429", "#D9534F", "#5CB85C", "#9B59B6", "#95A5A6"]

# Counter global - setiap panggilan plot_*() dapat key UNIK otomatis, supaya
# tidak bentrok StreamlitDuplicateElementId kalau ada 2 chart dengan
# parameter identik (mis. 2x radar chart dengan struktur sama).
if "_chart_counter" not in st.session_state:
    st.session_state["_chart_counter"] = 0


def _next_chart_key(prefix):
    st.session_state["_chart_counter"] += 1
    return f"{prefix}_{st.session_state['_chart_counter']}"

# Palet semantic - dipakai khusus untuk kategori yang punya arti "tingkat
# bahaya" (Critical/High/Medium/Low, dst) supaya warnanya konsisten dan
# intuitif (merah = bahaya, hijau = aman) di semua chart, bukan warna acak.
SEMANTIC_COLORS = {
    "critical": "#C0392B", "p0-critical": "#C0392B", "breach - reported": "#C0392B",
    "high": "#E67E22", "p1-high": "#E67E22", "masih terbuka": "#E67E22", "🔴 masih terbuka": "#E67E22",
    "medium": "#F0B429", "p2-medium": "#F0B429", "acceptable": "#F0B429", "review": "#F0B429",
    "low": "#2E7D32", "p3-low": "#2E7D32", "healthy": "#2E7D32", "prevented": "#2E7D32",
    "sudah membaik": "#2E7D32", "✅ sudah membaik": "#2E7D32",
    "noise": "#D9534F", "dormant": "#95A5A6", "unknown": "#95A5A6", "tidak diketahui": "#95A5A6",
}

# Warna IDENTITAS/kategori Security Domain - TERPISAH dari SEMANTIC_COLORS
# di atas (yang soal tingkat bahaya) supaya tidak tercampur maknanya.
# Domain yang sama SELALU pakai warna yang sama di SEMUA chart (sesuai
# prinsip Cynet benchmark: category color konsisten, bukan random per
# urutan data). Domain yang tidak dikenal fallback ke PALETTE.
CATEGORY_COLORS = {
    "infrastructure": "#4285F4", "applications": "#F57C00", "data": "#0F9D58",
    "documents": "#AB47BC", "network": "#00ACC1", "email": "#F4B400",
    "endpoint": "#DB4437", "identity": "#5C6BC0", "cloud": "#26A69A",
    "waf": "#8D6E63", "dlp": "#7CB342", "third party": "#EC407A",
    "others": "#9AA0A6", "audit": "#78909C",
}


def semantic_color_map(categories):
    """Kalau kategori chart mengandung istilah yang punya arti tingkat bahaya
    (Critical/High/Medium/Low/dll), pakai warna semantic (merah=bahaya,
    hijau=aman) - kalau tidak dikenali, fallback ke PALETTE biasa."""
    result = {}
    fallback_idx = 0
    for cat in categories:
        key = str(cat).strip().lower()
        if key in SEMANTIC_COLORS:
            result[cat] = SEMANTIC_COLORS[key]
        else:
            result[cat] = PALETTE[fallback_idx % len(PALETTE)]
            fallback_idx += 1
    return result


def category_color_map(categories):
    """Warna IDENTITAS kategori (mis. Security_Domain) - konsisten di
    SEMUA chart untuk nama kategori yang sama, TIDAK tergantung urutan
    data seperti distinct_colors biasa (yang bisa bikin 'Infrastructure'
    kebagian warna berbeda di 2 chart berbeda kalau urutannya beda)."""
    result = {}
    fallback_idx = 0
    for cat in categories:
        key = str(cat).strip().lower()
        if key in CATEGORY_COLORS:
            result[cat] = CATEGORY_COLORS[key]
        else:
            result[cat] = PALETTE[fallback_idx % len(PALETTE)]
            fallback_idx += 1
    return result

# =========================================================
# CSS CUSTOM - kartu KPI, tab, warna aksen (mendekati mockup)
# Ukuran font BISA DIATUR lewat slider di sidebar (lihat bagian
# "🔤 Ukuran Tulisan" di bawah) - session_state diinisialisasi dulu di sini
# supaya CSS render pertama kali sudah pakai nilai yang benar.
# =========================================================

if "font_scale" not in st.session_state:
    st.session_state["font_scale"] = 19  # px, default DIPERBESAR dari sebelumnya (17px terasa masih kecil)

_fs = st.session_state["font_scale"]

st.markdown(f"""
<style>
    /* Perbesar font dasar di seluruh dashboard - diatur via slider sidebar */
    html, body, [class*="css"] {{ font-size: {_fs}px !important; }}
    p, li, span, label, div {{ font-size: {_fs - 1}px !important; }}
    .stCaption, [data-testid="stCaptionContainer"] {{ font-size: {_fs - 3}px !important; }}

    [data-testid="stMetric"] {{
        background: #F7F9FC;
        border: 1px solid #E3E9F2;
        border-left: 4px solid #1F4E78;
        border-radius: 10px;
        padding: 16px 18px 12px 18px;
    }}
    [data-testid="stMetricLabel"] {{ color: #5A6B85; font-size: {_fs - 2}px !important; font-weight: 500; }}
    [data-testid="stMetricValue"] {{ color: #1F4E78; font-weight: 700; font-size: {_fs + 13}px !important; }}
    .stTabs [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid #E3E9F2; }}
    .stTabs [data-baseweb="tab"] {{
        border-radius: 8px 8px 0 0;
        padding: 10px 18px;
        color: #5A6B85;
    }}
    .stTabs [data-baseweb="tab"] p {{ font-size: {_fs - 1}px !important; font-weight: 500; }}
    .stTabs [aria-selected="true"] {{
        background: #EAF1FA;
        color: #1F4E78 !important;
        font-weight: 700;
        border-bottom: 3px solid #1F4E78;
    }}
    [data-testid="stSidebar"] {{ background: #F7F9FC; }}
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] label {{ font-size: {_fs - 2}px !important; }}
    .stButton>button[kind="primary"] {{ background: #1F4E78; border-color: #1F4E78; font-size: {_fs - 1}px !important; }}
    div[data-testid="stExpander"] {{
        border: 1px solid #E3E9F2;
        border-radius: 10px;
    }}
    div[data-testid="stExpander"] summary p {{ font-size: {_fs - 1}px !important; font-weight: 500; }}
    /* Tabel data - font isi tabel diperbesar juga (sebelumnya kecil banget) */
    [data-testid="stDataFrame"] {{ font-size: {_fs - 2}px !important; }}
    /* Kotak info/warning/success/error diberi border kiri tebal berwarna
       supaya lebih menonjol & gampang dibedakan sekilas lihat */
    div[data-testid="stAlertContainer"] {{
        border-radius: 8px;
        border-left-width: 5px;
        border-left-style: solid;
        font-size: {_fs - 1}px !important;
    }}
    div[data-testid="stNotificationContentInfo"] {{ color: #1F4E78; }}
    /* Judul markdown (### dan ##) diberi warna navy + border bawah tipis,
       ukuran diperbesar - supaya section jelas terpisah & gampang dipindai */
    h1 {{ font-size: {_fs + 17}px !important; }}
    h2 {{ color: #1F4E78 !important; font-size: {_fs + 9}px !important; }}
    h3 {{ color: #1F4E78 !important; border-bottom: 2px solid #EAF1FA; padding-bottom: 6px; font-size: {_fs + 4}px !important; }}
    /* Divider dikasih warna gradient tipis, bukan garis abu-abu polos */
    hr {{ border-top: 2px solid #EAF1FA; }}
</style>
""", unsafe_allow_html=True)


# =========================================================
# CHART HELPERS - Plotly (halus, interaktif) dengan fallback
# ke st.bar_chart/st.line_chart kalau plotly tidak tersedia.
# =========================================================

def plot_bar(df, x_col, y_col, title=None, horizontal=False, color_col=None, semantic=False, distinct_colors=False, category=False):
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.bar_chart(df.set_index(x_col)[y_col], key=_next_chart_key("fallback"))
        return
    if semantic:
        color_map = semantic_color_map(df[x_col])
    elif category:
        color_map = category_color_map(df[x_col])
    else:
        color_map = None
    use_category_color = semantic or category or distinct_colors or (color_col is not None)
    if horizontal:
        fig = px.bar(df, x=y_col, y=x_col, orientation="h", title=title,
                     color=x_col if (semantic or category or distinct_colors) else color_col,
                     color_discrete_map=color_map, color_discrete_sequence=PALETTE, text_auto=True)
    else:
        fig = px.bar(df, x=x_col, y=y_col, title=title,
                      color=x_col if (semantic or category or distinct_colors) else color_col,
                      color_discrete_map=color_map, color_discrete_sequence=PALETTE, text_auto=True)
    layout_kwargs = dict(
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        plot_bgcolor="white", paper_bgcolor="white",
        font=dict(color="#2C3E50", size=15),
        legend=dict(font=dict(size=14)),
        showlegend=use_category_color,
    )
    if title:  # title_font cuma dikirim kalau ada title-nya - title=None + title_font
        layout_kwargs["title_font"] = dict(size=17)  # bikin Plotly render teks "undefined"
    fig.update_layout(**layout_kwargs)
    if not horizontal:
        fig.update_xaxes(tickfont=dict(size=13), title_font=dict(size=14), type="category")
    else:
        fig.update_xaxes(tickfont=dict(size=13), title_font=dict(size=14))
    fig.update_yaxes(tickfont=dict(size=13), title_font=dict(size=14))
    fig.update_traces(marker_line_width=0, textfont_size=13)
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("chart"))


def plot_bar_multi(df, x_col, y_cols, title=None):
    """Bar chart dengan beberapa series (mis. Alert vs Insiden) dikelompokkan."""
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.bar_chart(df.set_index(x_col)[y_cols], key=_next_chart_key("fallback"))
        return
    melted = df.melt(id_vars=[x_col], value_vars=y_cols, var_name="Metric", value_name="Value")
    melted[x_col] = melted[x_col].astype(str)  # paksa jadi teks - supaya label "2026-06"/"2026-07"
    # TIDAK auto-terdeteksi Plotly sebagai tanggal kalender (yang bikin sumbu-X
    # jadi "Jun 1 2026"/"Jul 1" campur aduk, bukan label bulan yang jelas)
    fig = px.bar(melted, x=x_col, y="Value", color="Metric", barmode="group",
                 title=title, color_discrete_sequence=PALETTE,
                 category_orders={x_col: df[x_col].astype(str).tolist()})
    layout_kwargs = dict(
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        plot_bgcolor="white", paper_bgcolor="white",
        font=dict(color="#2C3E50", size=15),
        legend=dict(font=dict(size=14)),
    )
    if title:
        layout_kwargs["title_font"] = dict(size=17)
    fig.update_layout(**layout_kwargs)
    fig.update_xaxes(tickfont=dict(size=13), title_font=dict(size=14), type="category")
    fig.update_yaxes(tickfont=dict(size=13), title_font=dict(size=14))
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("chart"))


def plot_pie(df, names_col, values_col, title=None, semantic=False):
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.bar_chart(df.set_index(names_col)[values_col], key=_next_chart_key("fallback"))
        return
    color_map = semantic_color_map(df[names_col]) if semantic else None
    fig = px.pie(df, names=names_col, values=values_col, title=title,
                 color=names_col if semantic else None,
                 color_discrete_map=color_map, color_discrete_sequence=PALETTE, hole=0.35)
    fig.update_traces(textposition="inside", textinfo="percent+label", textfont_size=14)
    layout_kwargs = dict(
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        font=dict(size=15),
        legend=dict(font=dict(size=14)),
    )
    if title:
        layout_kwargs["title_font"] = dict(size=17)
    fig.update_layout(**layout_kwargs)
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("chart"))


def plot_line(df, x_col, y_cols, title=None):
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.line_chart(df.set_index(x_col)[y_cols], key=_next_chart_key("fallback"))
        return
    fig = px.line(df, x=x_col, y=y_cols, title=title, markers=True,
                  color_discrete_sequence=PALETTE,
                  category_orders={x_col: df[x_col].astype(str).tolist()})
    layout_kwargs = dict(
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        plot_bgcolor="white", paper_bgcolor="white",
        font=dict(color="#2C3E50", size=15),
        legend=dict(font=dict(size=14)),
    )
    if title:
        layout_kwargs["title_font"] = dict(size=17)
    fig.update_layout(**layout_kwargs)
    fig.update_xaxes(tickfont=dict(size=13), title_font=dict(size=14), type="category")
    fig.update_yaxes(tickfont=dict(size=13), title_font=dict(size=14))
    fig.update_traces(line=dict(width=3), marker=dict(size=8))
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("chart"))


def plot_radar(df, category_col, value_cols, title=None, normalize=True):
    """Radar/spider chart - 1 baris = 1 garis di radar (mis. 1 baris per
    tier Priority), tiap sumbu = 1 metrik (mis. MTTD/MTTR/MTTRV). Kalau
    nilainya makin tinggi, garis makin menjorok keluar/lancip ke arah itu -
    gampang lihat mana yang paling menonjol/bermasalah sekilas pandang.

    normalize=True (default): tiap SUMBU dinormalisasi 0-100 secara terpisah
    sebelum digambar - PENTING kalau sumbu-sumbunya beda skala jauh (mis.
    MTTR rata-rata puluhan menit vs MTTRV rata-rata ratusan menit) - tanpa
    ini, sumbu dengan angka terbesar akan mendominasi & bikin sumbu lain
    kelihatan rata/hilang (chart jadi 1 lancip doang, bukan bentuk radar
    yang informatif). Nilai ASLI tetap ditampilkan di tabel di bawah chart."""
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.dataframe(df[[category_col] + value_cols])
        return

    df = df.reset_index(drop=True)
    raw = {c: [v if isinstance(v, (int, float)) else None for v in df[c]] for c in value_cols}

    if normalize:
        plot_vals = {}
        for c in value_cols:
            vals = [v for v in raw[c] if v is not None]
            if not vals:
                plot_vals[c] = [0] * len(df)
                continue
            lo, hi = min(vals), max(vals)
            if hi == lo:
                plot_vals[c] = [50 if v is not None else 0 for v in raw[c]]
            else:
                plot_vals[c] = [round((v - lo) / (hi - lo) * 100, 1) if v is not None else 0 for v in raw[c]]
    else:
        plot_vals = {c: [v if v is not None else 0 for v in raw[c]] for c in value_cols}

    fig = go.Figure()
    for i in range(len(df)):
        values = [plot_vals[c][i] for c in value_cols]
        values_closed = values + values[:1]
        theta_closed = value_cols + value_cols[:1]
        fig.add_trace(go.Scatterpolar(
            r=values_closed, theta=theta_closed, fill="toself",
            name=str(df[category_col].iloc[i]),
            line=dict(color=PALETTE[i % len(PALETTE)], width=2),
            opacity=0.75,
        ))

    layout_kwargs = dict(
        polar=dict(
            radialaxis=dict(visible=True, tickfont=dict(size=12), range=[0, 100] if normalize else None),
            angularaxis=dict(tickfont=dict(size=14)),
        ),
        showlegend=True,
        legend=dict(font=dict(size=14)),
        margin=dict(l=40, r=40, t=50 if title else 20, b=20),
        font=dict(size=14),
    )
    if title:  # cuma kirim title kalau memang ada isinya - title=None ke Plotly
        layout_kwargs["title"] = dict(text=title, font=dict(size=17))  # bisa render "undefined" di sebagian browser
    fig.update_layout(**layout_kwargs)
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("chart"))

    if normalize:
        st.caption("📏 Skala tiap sumbu dinormalisasi 0-100 (relatif ke nilai tertinggi/terendah di antara "
                   "garis yang dibandingkan) - supaya sumbu dengan angka besar tidak mendominasi tampilan. "
                   "Nilai ASLI:")
        st.dataframe(df[[category_col] + value_cols], use_container_width=True)

    text_cols = [c for c in value_cols if df[c].apply(lambda v: not isinstance(v, (int, float))).any()]
    if text_cols:
        st.caption(f"⚠️ Kolom {text_cols} belum ada datanya - digambar sebagai 0 di radar "
                   f"(BUKAN berarti cepat/bagus, tapi memang belum bisa dihitung).")


def plot_sunburst(df, path_cols, value_col, title=None):
    """Sunburst chart - visual 'anchor' untuk hierarki bertingkat (mis.
    Tactic -> Technique -> Sub-Technique). Lingkaran DALAM = level teratas
    (Tactic), makin ke LUAR = makin turunan (Technique, lalu Sub-Technique).
    Ukuran & warna tiap potongan proporsional ke jumlah insiden - sesuai
    arahan BoD: 'grafik anchor yang mudah dipahami' untuk turunan MITRE."""
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.dataframe(df)
        return
    fig = px.sunburst(df, path=path_cols, values=value_col, color_discrete_sequence=PALETTE)
    fig.update_traces(textinfo="label+percent parent")
    layout_kwargs = dict(margin=dict(l=10, r=10, t=40 if title else 10, b=10), font=dict(size=13))
    if title:
        layout_kwargs["title"] = title
    fig.update_layout(**layout_kwargs)
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("sunburst"))


def plot_funnel(df, stage_col, value_col, title=None):
    """Funnel chart - khusus untuk data yang SUDAH cumulative/monoton
    menurun (lihat build_killchain_funnel() di core/mitre_killchain.py).
    Visual funnel SECARA DESAIN menegaskan 'makin ke bawah/kanan makin
    kecil' - sesuai arahan BoD, bukan bar chart biasa yang bisa naik-turun."""
    if df is None or len(df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.dataframe(df)
        return
    fig = px.funnel(df, x=value_col, y=stage_col, color_discrete_sequence=[PALETTE[0]])
    layout_kwargs = dict(margin=dict(l=10, r=10, t=40 if title else 10, b=10), font=dict(size=14),
                         plot_bgcolor="white", paper_bgcolor="white")
    if title:
        layout_kwargs["title"] = title
    fig.update_layout(**layout_kwargs)
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("funnel"))


def plot_network(hier_df, left_col, right_col, value_col, title=None,
                  left_unique_n=None, right_unique_n=None):
    """Correlation/network chart - GANTI Sunburst untuk kasus Tactic<->
    Technique yang punya kategori dominan (mis. 'Tactic Tidak Diketahui'
    64%) - di Sunburst kategori itu MENELAN tampilan, di network chart
    setiap simpul tetap kelihatan proporsional TANPA saling menutupi.

    Layout: left_col di kiri (mis. Tactic), right_col di kanan (mis.
    Technique). PERBAIKAN dari versi sebelumnya:
    1. Label simpul pakai JUMLAH INSIDEN UNIK (left_unique_n/right_unique_n,
       dari build_mitre_tactic/technique_summary) - BUKAN sum(value_col) dari
       tabel pasangan, yang bisa dobel-hitung kalau 1 insiden punya >1
       Technique sekaligus (mis. 4 insiden yang SAMA masing-masing punya
       T1098 DAN T1098.003 -> sum pasangan = 8, padahal insidennya cuma 4).
    2. Tiap Tactic (kiri) dapat WARNA SENDIRI, garis ke Technique-nya ikut
       warna itu - supaya gampang ditelusuri "garis ini punya siapa".
    3. Technique (kanan) DIKELOMPOKKAN berdasarkan Tactic yang paling
       dominan menariknya - supaya Technique 1 Tactic saling berdekatan,
       MENGURANGI garis saling bersilangan (bukan dihilangkan total kalau
       memang ada Technique yang terhubung ke >1 Tactic, tapi diminimalkan)."""
    if hier_df is None or len(hier_df) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return
    if not PLOTLY_OK:
        st.dataframe(hier_df)
        return

    edge_sum_left = hier_df.groupby(left_col)[value_col].sum()
    edge_sum_right = hier_df.groupby(right_col)[value_col].sum()

    def _resolve_totals(unique_n, edge_sum):
        """Label/ukuran simpul pakai jumlah insiden UNIK (unique_n) kalau
        disediakan DAN masuk akal - fallback ke sum pasangan (edge_sum,
        SELALU valid karena berasal langsung dari data chart yang sedang
        digambar) kalau unique_n tidak ada/kosong/SEMUA NOL (mis. dari
        cache lama yang fallback ke {} lalu jadi {key: 0}).
        Ini FIX untuk bug: dict {focus_tactic: 0} lolos pengecekan
        'truthy' (dict tidak kosong), tapi ISINYA 0 - bikin max()=0 ->
        divide-by-zero -> NaN -> Plotly reject -> crash."""
        totals = pd.Series(unique_n, dtype=float) if unique_n else pd.Series(dtype=float)
        totals = totals.reindex(edge_sum.index)
        if totals.isna().all() or totals.fillna(0).sum() == 0:
            return edge_sum.astype(float)
        return totals.fillna(edge_sum)

    left_totals = _resolve_totals(left_unique_n, edge_sum_left)
    right_totals = _resolve_totals(right_unique_n, edge_sum_right)

    if len(left_totals) == 0 or len(right_totals) == 0:
        st.caption("(Tidak ada data untuk chart ini)")
        return

    left_nodes = left_totals.sort_values(ascending=False).index.tolist()

    # Kelompokkan Technique (kanan) berdasarkan Tactic (kiri) mana yang
    # PALING BANYAK menariknya (edge terbesar) - supaya Technique dari
    # Tactic yang sama posisinya berdekatan, garis lebih jarang bersilangan.
    dominant_left = hier_df.loc[hier_df.groupby(right_col)[value_col].idxmax()].set_index(right_col)[left_col]
    left_order_rank = {t: i for i, t in enumerate(left_nodes)}
    right_nodes = sorted(
        right_totals.index.tolist(),
        key=lambda t: (left_order_rank.get(dominant_left.get(t), 999), -right_totals[t])
    )

    def y_positions(n):
        if n == 1:
            return [0.5]
        return [1 - i / (n - 1) for i in range(n)]

    left_y = dict(zip(left_nodes, y_positions(len(left_nodes))))
    right_y = dict(zip(right_nodes, y_positions(len(right_nodes))))
    left_color = dict(zip(left_nodes, [PALETTE[i % len(PALETTE)] for i in range(len(left_nodes))]))
    default_color = left_color[left_nodes[0]]  # fallback aman - left_nodes DIJAMIN tidak kosong (dicek di atas)

    def _rgba(hex_color, alpha):
        hex_color = hex_color.lstrip("#")
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
        return f"rgba({r},{g},{b},{alpha:.2f})"

    def _safe_ratio(value, max_value, min_out, max_out):
        """Hitung posisi proporsional value/max_value ke rentang [min_out,
        max_out] - AMAN terhadap max_value 0/NaN/negatif dan value NaN
        (semua kasus yang sebelumnya bikin Plotly reject 'NaN size')."""
        if pd.isna(value) or pd.isna(max_value) or max_value <= 0:
            return min_out
        ratio = max(0.0, min(1.0, value / max_value))
        return min_out + (max_out - min_out) * ratio

    fig = go.Figure()

    max_edge = hier_df[value_col].max()
    for _, row in hier_df.iterrows():
        color = left_color.get(row[left_col], default_color)
        opacity = _safe_ratio(row[value_col], max_edge, 0.25, 0.85)
        width = _safe_ratio(row[value_col], max_edge, 1.5, 6.5)
        fig.add_trace(go.Scatter(
            x=[0, 1], y=[left_y[row[left_col]], right_y[row[right_col]]],
            mode="lines", line=dict(width=width, color=_rgba(color, opacity)),
            hoverinfo="text", text=f"{row[left_col]} → {row[right_col]}: {row[value_col]}", showlegend=False,
        ))

    max_left, max_right = left_totals.max(), right_totals.max()
    fig.add_trace(go.Scatter(
        x=[0] * len(left_nodes), y=[left_y[n] for n in left_nodes],
        mode="markers+text",
        text=[f"{n} ({int(left_totals[n]) if pd.notna(left_totals[n]) else 0} insiden)" for n in left_nodes],
        textposition="middle left", textfont=dict(size=12, color="#2C3E50"),
        marker=dict(size=[_safe_ratio(left_totals[n], max_left, 16, 42) for n in left_nodes],
                    color=[left_color[n] for n in left_nodes], line=dict(width=1.5, color="white")),
        hoverinfo="text", showlegend=False,
    ))
    fig.add_trace(go.Scatter(
        x=[1] * len(right_nodes), y=[right_y[n] for n in right_nodes],
        mode="markers+text",
        text=[f"{n} ({int(right_totals[n]) if pd.notna(right_totals[n]) else 0} insiden)" for n in right_nodes],
        textposition="middle right", textfont=dict(size=12, color="#2C3E50"),
        marker=dict(size=[_safe_ratio(right_totals[n], max_right, 16, 42) for n in right_nodes],
                    color=[left_color.get(dominant_left.get(n), default_color) for n in right_nodes],
                    line=dict(width=1.5, color="white")),
        hoverinfo="text", showlegend=False,
    ))

    layout_kwargs = dict(
        xaxis=dict(visible=False, range=[-0.9, 1.9]),
        yaxis=dict(visible=False, range=[-0.1, 1.1]),
        plot_bgcolor="white", paper_bgcolor="white",
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        height=max(400, 40 * max(len(left_nodes), len(right_nodes))),
    )
    if title:
        layout_kwargs["title"] = title
    fig.update_layout(**layout_kwargs)
    st.plotly_chart(fig, use_container_width=True, key=_next_chart_key("network"))


# =========================================================
# HELPERS
# =========================================================

def run_pipeline(master, domain_mapping, alert, incident, nonsplunk, period_label, task=None, cti=None):
    data = {
        "master_rule": master, "domain_mapping": domain_mapping,
        "alert": alert, "incident": incident, "nonsplunk": nonsplunk,
        "task": task if task is not None else pd.DataFrame(),
        "cti": cti if cti is not None else pd.DataFrame(),
        "week": period_label,
    }
    data = RuleNormalizer(data).run()
    data = Validator(data).run()
    report = SOCProcessor(data).run()
    for k in ["validation_summary", "mapping_quality", "alert_incident_compare",
              "unknown_rule", "missing_priority", "missing_owner",
              "missing_severity", "duplicate_master"]:
        report[k] = data[k]
    return report


def excel_bytes(report, period_label):
    writer = ExcelWriter(report=report, week=period_label)
    path = writer.export()
    with open(path, "rb") as f:
        return f.read(), Path(path).name


def pptx_bytes(report, period_label):
    writer = PPTXWriter(report=report, period_label=period_label)
    path = writer.export()
    with open(path, "rb") as f:
        return f.read(), Path(path).name


def load_nonsplunk_upload(uploaded_file):
    if uploaded_file is None:
        return pd.DataFrame()
    loader = DataLoader()
    tmp_path = Path("output") / f"_tmp_{uploaded_file.name}"
    tmp_path.parent.mkdir(exist_ok=True)
    with open(tmp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    ns = loader.load_nonsplunk_from_file(tmp_path)
    tmp_path.unlink(missing_ok=True)
    return ns


def load_task_upload(uploaded_file):
    if uploaded_file is None:
        return pd.DataFrame()
    loader = DataLoader()
    tmp_path = Path("output") / f"_tmp_{uploaded_file.name}"
    tmp_path.parent.mkdir(exist_ok=True)
    with open(tmp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    task = loader.load_task_from_file(tmp_path)
    tmp_path.unlink(missing_ok=True)
    return task


def load_cti_upload(uploaded_file):
    if uploaded_file is None:
        return pd.DataFrame()
    loader = DataLoader()
    tmp_path = Path("output") / f"_tmp_{uploaded_file.name}"
    tmp_path.parent.mkdir(exist_ok=True)
    with open(tmp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    cti = loader.load_cti_fortirecon_from_file(tmp_path)
    tmp_path.unlink(missing_ok=True)
    return cti


# =========================================================
# REPORT CACHE - simpan hasil report yang SUDAH DIPROSES (bukan file mentah)
# supaya bisa dibuka lagi TANPA upload ulang. Disimpan per period_label,
# jadi 1 file cache = 1 bulan yang sudah pernah digenerate.
# =========================================================

import pickle

CACHE_DIR = Path("database") / "report_cache"


def save_report_cache(report, period_label):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in period_label)
    with open(CACHE_DIR / f"{safe_name}.pkl", "wb") as f:
        pickle.dump({"report": report, "period_label": period_label}, f)


def list_cached_reports():
    if not CACHE_DIR.exists():
        return []
    files = sorted(CACHE_DIR.glob("*.pkl"), key=lambda f: f.stat().st_mtime, reverse=True)
    return [f.stem for f in files]


def load_report_cache(period_label):
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in period_label)
    path = CACHE_DIR / f"{safe_name}.pkl"
    if not path.exists():
        return None, None
    with open(path, "rb") as f:
        data = pickle.load(f)
    return data["report"], data["period_label"]


# =========================================================
# SIDEBAR - INPUT (fokus MONTHLY - upload data 1 bulan penuh langsung,
# TIDAK lagi menggabungkan folder mingguan. Fitur weekly disembunyikan
# sementara, bukan dihapus - main.py CLI masih mendukungnya kalau nanti
# dibutuhkan lagi.)
# =========================================================

st.sidebar.title("SOC Report Generator")
st.sidebar.caption("Fokus laporan BULANAN - upload data 1 bulan penuh sekaligus.")

# --- Pilihan laporan di dalam menu SOC Report: laporan Splunk+Ivanti (existing) ATAU laporan insiden Ivanti per era state machine.
# Default = laporan existing; kode SOC di bawah blok ini TIDAK diubah (kalau pilihan insiden, blok ini st.stop() sebelum sisanya).
_soc_views = ["Laporan Bulanan (Splunk + Ivanti)", "Insiden Bulanan Ivanti (per state machine)"]
_soc_view = st.sidebar.radio("Jenis laporan SOC", _soc_views, key="soc_view")
if _soc_view == _soc_views[1]:
    from soc_incident.dashboard import render_soc_incident_dashboard
    try:
        render_soc_incident_dashboard()
    except Exception as e:
        st.error(f"Laporan insiden mengalami error: {e}")
        st.caption("Laporan bulanan existing tetap bisa dibuka - pilih 'Laporan Bulanan (Splunk + Ivanti)' di sidebar.")
    st.stop()
st.sidebar.divider()

with st.sidebar.expander("🔤 Ukuran Tulisan", expanded=False):
    new_font_scale = st.slider(
        "Besar font (semua judul & body ikut menyesuaikan)",
        min_value=14, max_value=26, value=st.session_state["font_scale"], key="font_scale_slider"
    )
    if new_font_scale != st.session_state["font_scale"]:
        st.session_state["font_scale"] = new_font_scale
        st.rerun()

if "report" not in st.session_state:
    st.session_state["report"] = None
    st.session_state["period_label"] = None
    st.session_state["excel_cache"] = None
    st.session_state["pptx_cache"] = None

report = None
period_label = None

# ---- Bagian A: Buka laporan yang SUDAH PERNAH digenerate (tanpa upload ulang) ----
cached_periods = list_cached_reports()
st.sidebar.subheader("📂 Buka Laporan Tersimpan")
if cached_periods:
    picked_period = st.sidebar.selectbox("Pilih bulan yang sudah pernah diupload", cached_periods, key="picked_period")
    c_open, c_del = st.sidebar.columns(2)
    with c_open:
        if st.button("📖 Buka", key="btn_open_cache", use_container_width=True):
            loaded_report, loaded_label = load_report_cache(picked_period)
            if loaded_report is not None:
                st.session_state["report"] = loaded_report
                st.session_state["period_label"] = loaded_label
                st.session_state["excel_cache"] = None
                st.session_state["pptx_cache"] = None
                st.sidebar.success(f"Laporan '{loaded_label}' dimuat - TIDAK perlu upload ulang.")
    with c_del:
        if st.button("🗑️ Hapus", key="btn_del_one_cache", use_container_width=True):
            safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in picked_period)
            (CACHE_DIR / f"{safe_name}.pkl").unlink(missing_ok=True)
            st.sidebar.success(f"Laporan '{picked_period}' dihapus.")
            st.rerun()

    with st.sidebar.expander("⚠️ Hapus SEMUA data tersimpan (mulai dari nol)"):
        st.caption(
            "Menghapus SEMUA laporan cache (Juni, Juli, dst), histori tren "
            "(Monthly Comparison, Severity Trend, Attack Surface, Recurring "
            "Findings/Action Tracker, CTI Trend) - supaya tidak ada data "
            "duplikat/lama yang tercampur. TIDAK BISA DIBATALKAN."
        )
        if st.checkbox("Saya yakin ingin menghapus semua data tersimpan", key="confirm_reset_all"):
            if st.button("🗑️ HAPUS SEMUA SEKARANG", key="btn_reset_all", type="primary"):
                import shutil
                db_dir = Path("database")
                if db_dir.exists():
                    shutil.rmtree(db_dir)
                st.session_state["report"] = None
                st.session_state["period_label"] = None
                st.sidebar.success("Semua data tersimpan (laporan cache + histori tren) sudah dihapus. Silakan upload dari awal.")
                st.rerun()
else:
    st.sidebar.caption("Belum ada laporan tersimpan. Upload & generate minimal 1x dulu di bawah.")

st.sidebar.divider()
st.sidebar.subheader("➕ Upload Data Baru / Update")
st.sidebar.caption("Cuma perlu kalau ada bulan BARU yang belum pernah diupload, atau mau update data bulan yang sama.")

st.sidebar.subheader("1. Data Master")
master_up = st.sidebar.file_uploader("Master Rules Splunk (.xlsx / .csv)", type=["xlsx", "csv"], key="master")
st.sidebar.caption(
    "Wajib. Kalau tidak diupload, dicoba pakai file default di "
    f"`{MASTER_RULE_FILE}` (kalau ada)."
)
assume_all_enabled = st.sidebar.checkbox(
    "File ini SEMUA rule sudah Enabled (centang HANYA kalau file tidak punya "
    "kolom status, tapi Anda yakin file ini memang sudah difilter oleh tim "
    "Splunk untuk cuma berisi rule yang aktif)"
)
domain_up = st.sidebar.file_uploader("Domain Mapping (.xlsx / .csv) - opsional", type=["xlsx", "csv"], key="domain")

st.sidebar.subheader("2. Data Bulanan")
period_label_input = st.sidebar.text_input("Label Periode (contoh: 2026-07)", value="")
alert_up = st.sidebar.file_uploader("Alert Splunk - 1 bulan penuh (.xlsx / .csv)", type=["xlsx", "csv"], key="alert")
incident_up = st.sidebar.file_uploader("Insiden Ivanti - 1 bulan penuh (.xlsx / .csv)", type=["xlsx", "csv"], key="incident")
nonsplunk_up = st.sidebar.file_uploader("Alert NonSplunk (.xlsx saja) - opsional", type="xlsx", key="nonsplunk")
st.sidebar.caption("Alert NonSplunk WAJIB .xlsx (bukan .csv) karena butuh 3 sheet sekaligus - Akamai/CSPM/Microsoft Defender - CSV cuma bisa 1 sheet.")
task_up = st.sidebar.file_uploader("Task SOC dari Ivanti (.xlsx / .csv) - opsional", type=["xlsx", "csv"], key="task")
cti_up = st.sidebar.file_uploader("CTI FortiRecon (.xlsx / .csv) - opsional", type=["xlsx", "csv"], key="cti")
st.sidebar.caption("Kolom Password (kalau ada) TIDAK PERNAH ditampilkan mentah di laporan - "
                    "otomatis dikonversi jadi indikator ada/tidak kredensial bocor.")

if st.sidebar.button("Generate Report", type="primary"):
    if not alert_up or not incident_up:
        st.sidebar.error("Alert Splunk dan Insiden Ivanti wajib diupload.")
    elif not period_label_input.strip():
        st.sidebar.error("Isi Label Periode dulu (contoh: 2026-07).")
    elif not master_up and not MASTER_RULE_FILE.exists():
        st.sidebar.error("Master Rules Splunk wajib diupload (tidak ada file default yang bisa dipakai).")
    else:
        master = read_any_table(master_up, filename_hint=master_up.name) if master_up else pd.read_excel(MASTER_RULE_FILE)
        master = normalize_master_rules_columns(master, assume_all_enabled=assume_all_enabled)
        if domain_up:
            domain_mapping = read_any_table(domain_up, sheet_name="Keyword_Mapping", filename_hint=domain_up.name)
        elif DOMAIN_MAPPING_FILE.exists():
            domain_mapping = pd.read_excel(DOMAIN_MAPPING_FILE, sheet_name="Keyword_Mapping")
        else:
            domain_mapping = pd.DataFrame(columns=["Priority", "Keyword", "Security_Domain", "Security_Sub_Domain"])

        alert = read_any_table(alert_up, filename_hint=alert_up.name)
        incident = read_any_table(incident_up, filename_hint=incident_up.name)
        incident = normalize_incident_columns(incident)
        nonsplunk = load_nonsplunk_upload(nonsplunk_up)
        task = load_task_upload(task_up)
        cti = load_cti_upload(cti_up)

        # NonSplunk, Task, & CTI dibatasi ke rentang tanggal alert Splunk yang
        # diupload (konsisten dengan logic loader.py - kalau file mentahnya
        # kelebihan tanggal, otomatis dipotong sesuai cakupan data utama).
        if len(nonsplunk) > 0:
            alert_dates = pd.to_datetime(alert["Alert Time"], errors="coerce").dropna()
            if len(alert_dates) > 0:
                w_start, w_end = alert_dates.min().normalize(), alert_dates.max().normalize() + pd.Timedelta(days=1)
                nonsplunk = nonsplunk[nonsplunk["Alert_Time_Std"].between(w_start, w_end, inclusive="left")]
        if len(task) > 0:
            alert_dates = pd.to_datetime(alert["Alert Time"], errors="coerce").dropna()
            if len(alert_dates) > 0:
                w_start, w_end = alert_dates.min().normalize(), alert_dates.max().normalize() + pd.Timedelta(days=1)
                task = task[task["Created On"].between(w_start, w_end, inclusive="left")]
        if len(cti) > 0:
            alert_dates = pd.to_datetime(alert["Alert Time"], errors="coerce").dropna()
            if len(alert_dates) > 0:
                w_start, w_end = alert_dates.min().normalize(), alert_dates.max().normalize() + pd.Timedelta(days=1)
                cti = cti[cti["Alert_Date"].between(w_start, w_end, inclusive="left")]

        period_label = period_label_input.strip()
        with st.spinner("Memproses data..."):
            report = run_pipeline(master, domain_mapping, alert, incident, nonsplunk, period_label, task, cti)
        st.session_state["report"] = report
        st.session_state["period_label"] = period_label
        save_report_cache(report, period_label)
        st.sidebar.success(f"✅ Laporan '{period_label}' tersimpan - lain kali cukup buka dari '📂 Buka Laporan Tersimpan', tidak perlu upload ulang.")
        try:
            st.session_state["excel_cache"] = excel_bytes(report, period_label)
            st.session_state["pptx_cache"] = pptx_bytes(report, period_label)
        except Exception as e:
            st.session_state["excel_cache"] = None
            st.session_state["pptx_cache"] = None
            st.sidebar.error(f"Gagal menyiapkan file Excel/PPTX: {e}")

# =========================================================
# MAIN AREA - HASIL (struktur tab ala Tableau)
# =========================================================

st.title("SOC Monthly Report")

report = st.session_state.get("report")
period_label = st.session_state.get("period_label")

if report is None:
    st.info("Isi parameter di sidebar kiri, lalu klik **Generate Report**.")
    st.stop()

st.success(f"Report periode **{period_label}** berhasil dibuat.")

hyp = report["hypothesis_insight"]
partial_row = hyp[hyp["Hipotesis"].str.contains("PERINGATAN", na=False)]
if len(partial_row) > 0:
    st.warning(partial_row.iloc[0]["Temuan"])
    hyp = hyp[~hyp["Hipotesis"].str.contains("PERINGATAN", na=False)]


def show_metrics(df, label_col="Metric", value_col="Value", cols=4):
    c = st.columns(cols)
    for i, (_, row) in enumerate(df.iterrows()):
        with c[i % cols]:
            st.metric(row[label_col], row[value_col])


def show_insights(keywords):
    for _, row in hyp.iterrows():
        if any(k in row["Hipotesis"] for k in keywords):
            st.info(f"**{row['Hipotesis']}** — {row['Temuan']}")


def rule_insight_text(row):
    rec, dr = row["Recommendation"], row["Detection_Rate"]
    if rec == "Noise":
        action = "banyak alert tapi 0 insiden - evaluasi threshold, kandidat tuning/exclusion."
    elif rec in ["Critical Tuning", "Need Tuning", "Review"]:
        action = f"detection rate rendah ({dr}%) - perlu penyesuaian sensitivitas."
    elif rec == "Dormant":
        action = "terdaftar tapi tidak trigger - cek relevansi atau kemungkinan blind spot (kandidat threat hunting)."
    elif rec == "Acceptable":
        action = f"detection rate {dr}% - di atas ambang minimal, tapi belum tinggi. Pantau, belum perlu tuning mendesak."
    elif rec == "Healthy":
        action = f"detection rate {dr}% - baik, pertahankan konfigurasi saat ini."
    else:
        action = "di luar Master Rules - perlu direview & didaftarkan kalau valid."
    return f"{row['Alert_Count']} alert, {row['Incident_Count']} insiden, Detection Rate {dr}%. Status **{rec}** - {action}"


def apply_filter(df, col, selected):
    """Filter generik: kalau kolomnya ada di tabel dan user pilih selain 'Semua', filter. Kalau tidak, tabel dikembalikan apa adanya (tidak semua tabel punya dimensi yang sama)."""
    if df is None or len(df) == 0 or selected == "Semua" or col not in df.columns:
        return df
    return df[df[col] == selected]


exec_df = report["executive"]

# =========================================================
# FILTER (sidebar, di bawah info Generate) - filter FUNGSIONAL,
# menyaring tabel/chart yang relevan (bukan cuma dekorasi).
# =========================================================

st.sidebar.divider()
st.sidebar.subheader("Filter Tampilan")

analyst_options = ["Semua"] + sorted(report["soc_individual_kpi"]["Owner"].dropna().unique().tolist()) \
    if len(report.get("soc_individual_kpi", [])) > 0 else ["Semua"]
domain_options = ["Semua"] + sorted(report["domain"]["Security_Domain"].dropna().unique().tolist()) \
    if len(report.get("domain", [])) > 0 else ["Semua"]
priority_options = ["Semua", "P0-Critical", "P1-High", "P2-Medium", "P3-Low"]

f_analyst = st.sidebar.selectbox("Analyst", analyst_options, key="f_analyst")
f_domain = st.sidebar.selectbox("Domain", domain_options, key="f_domain")
f_priority = st.sidebar.selectbox("Priority", priority_options, key="f_priority")
st.sidebar.caption("Filter berlaku di tab KPI Analyst (Analyst), Splunk vs Ivanti & Threat Profiling (Domain), "
                    "Threat Profiling (Priority). Tab lain tidak punya dimensi itu, jadi tidak berubah.")

# =========================================================
# TAB NAVIGATION (ala Tableau - klik pindah, bukan scroll panjang)
# =========================================================

# =========================================================
# NAVIGASI HALAMAN (berbasis session_state, BUKAN st.tabs biasa) - supaya
# tombol "Lihat Detail" di Executive Summary bisa langsung LOMPAT ke halaman
# lain. st.tabs() bawaan Streamlit TIDAK BISA dikontrol dari kode (keterbatasan
# resmi Streamlit) - makanya diganti radio horizontal yang gayanya dibuat
# mirip tab lewat CSS, tapi BISA di-set programatis via session_state.
# =========================================================

SUMMARY_PAGE = "📋 Executive Summary"
DETAIL_PAGES = [
    "Overview", "📊 Perbandingan Bulanan", "Ticket", "Threat Profiling",
    "Non-Splunk & Task", "Tren", "Efektivitas", "KPI Analyst", "Help"
]
PAGES = [SUMMARY_PAGE] + DETAIL_PAGES  # dipertahankan untuk kompatibilitas internal

if "current_page" not in st.session_state:
    st.session_state["current_page"] = SUMMARY_PAGE

# PENTING: proses "pending navigation" DI SINI, SEBELUM widget dibuat -
# supaya tidak pernah mengubah session_state milik widget SETELAH widget
# itu dirender di run yang sama (StreamlitAPIException). goto_page() cuma
# set flag "_pending_page", diproses & dibersihkan di sini, lalu widget
# top-level DAN sub-page (kalau perlu) dipaksa ikut sinkron.
if "_pending_page" in st.session_state:
    _new_page = st.session_state.pop("_pending_page")
    st.session_state["current_page"] = _new_page
    st.session_state["nav_top_widget"] = "Summary" if _new_page == SUMMARY_PAGE else "Details"
    if _new_page in DETAIL_PAGES:
        st.session_state["nav_detail_widget"] = _new_page


def goto_page(page_name):
    """Dipanggil dari tombol 'Lihat Detail' - pindah halaman + reload."""
    st.session_state["_pending_page"] = page_name
    st.rerun()


# ---- Navigasi 2 tingkat: Summary / Details, lalu sub-pilihan kalau Details ----
_top_default = "Summary" if st.session_state["current_page"] == SUMMARY_PAGE else "Details"
selected_top = st.radio(
    "Navigasi", ["Summary", "Details"], index=["Summary", "Details"].index(_top_default),
    horizontal=True, label_visibility="collapsed", key="nav_top_widget"
)

if selected_top == "Summary":
    if st.session_state["current_page"] != SUMMARY_PAGE:
        st.session_state["current_page"] = SUMMARY_PAGE
        st.rerun()
else:
    _detail_default = st.session_state["current_page"] if st.session_state["current_page"] in DETAIL_PAGES else DETAIL_PAGES[0]
    selected_detail = st.selectbox(
        "Detail View", DETAIL_PAGES, index=DETAIL_PAGES.index(_detail_default), key="nav_detail_widget"
    )
    if selected_detail != st.session_state["current_page"]:
        st.session_state["current_page"] = selected_detail
        st.rerun()

current_page = st.session_state["current_page"]

st.markdown("""
<style>
    div[role="radiogroup"] { gap: 4px; border-bottom: 1px solid #E3E9F2; flex-wrap: wrap; }
    div[role="radiogroup"] label {
        border-radius: 8px 8px 0 0; padding: 8px 16px; background: transparent;
    }
    div[role="radiogroup"] label:has(input:checked) {
        background: #EAF1FA; font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# HALAMAN: EXECUTIVE SUMMARY - 1 halaman ringkas untuk manajemen, radar
# chart + angka besar saja, TANPA detail teknis. Halaman detail lain
# (Ticket, Threat Profiling, dst) TETAP ADA untuk kerja analyst - tiap
# section punya tombol "Lihat Detail" untuk lompat ke sana.
# ---------------------------------------------------------
if current_page == "📋 Executive Summary":
    st.caption("Ringkasan 1 halaman untuk manajemen - radar chart & angka kunci saja. "
               "Klik 'Lihat Detail →' di tiap bagian untuk buka halaman detailnya.")

    # =====================================================
    # STATUS RINGKAS (RAG) + DELTA VS BULAN LALU + TEMUAN UTAMA - paling atas
    # halaman, supaya manajemen langsung paham kondisi tanpa scroll/baca
    # detail. Ini yang paling sering ditanya BoD: "gimana kondisi kita?"
    # =====================================================
    # =====================================================
    # RISK SCORE STRATEGIC (BARU) - sesuai masukan management: "risk score
    # yang lebih strategic karena data perbulan". Gabungan 3 komponen
    # (bukan cuma % Breach 1 angka) supaya mencerminkan tren bulanan, bukan
    # snapshot sesaat:
    #   A. SLA Compliance (40%) - dari % Breach periode ini
    #   B. Tren Detection Rate (30%) - membaik/memburuk vs bulan lalu
    #   C. Perbaikan Isu Berulang (30%) - Action Tracker Improvement Rate
    #      (rule yang tadinya bermasalah, sekarang sudah membaik)
    # Skornya 0-100, SEMAKIN TINGGI = SEMAKIN BERISIKO (konvensi umum "Risk
    # Score"). Metodologi ditampilkan transparan (expander), bukan black-box.
    # =====================================================
    sla_df = report.get("sla_metrics")
    if sla_df is not None and len(sla_df) > 0:
        overall_row = sla_df[sla_df["Priority_Label"] == "SEMUA"].iloc[0]
        pct_breach_now = overall_row.get("%_Breach", None)

        # Komponen A: SLA Compliance
        comp_a = (100 - pct_breach_now) if pct_breach_now is not None else None

        # Komponen B: Tren Detection Rate vs bulan lalu
        mc_top = report.get("monthly_comparison")
        comp_b, delta_text = None, ""
        if mc_top is not None and len(mc_top) >= 2:
            last2 = mc_top.sort_values("Period_End").tail(2)
            prev_rate, now_rate = last2.iloc[0]["Detection_Rate_%"], last2.iloc[1]["Detection_Rate_%"]
            diff = round(now_rate - prev_rate, 2)
            arrow = "▲" if diff > 0 else ("▼" if diff < 0 else "→")
            delta_text = f" | Detection Rate vs bulan lalu: {arrow} {abs(diff)}%"
            comp_b = max(0, min(100, 50 + diff * 5))  # delta +-10% -> skor 0-100

        # Komponen C: Improvement Rate dari Action Tracker
        comp_c = None
        act_summary = report.get("action_tracker_summary")
        if act_summary is not None and len(act_summary) > 0:
            imp_row = act_summary[act_summary["Metrik"].str.contains("Improvement Rate", na=False)]
            if len(imp_row) > 0:
                comp_c = float(str(imp_row.iloc[0]["Nilai"]).replace("%", ""))

        # Rata-rata tertimbang HANYA dari komponen yang datanya tersedia -
        # supaya komponen kosong tidak dipaksa dianggap 0 (menyesatkan).
        components = [(comp_a, 0.4), (comp_b, 0.3), (comp_c, 0.3)]
        available = [(v, w) for v, w in components if v is not None]
        if available:
            total_w = sum(w for _, w in available)
            health_score = sum(v * w for v, w in available) / total_w
            risk_score = round(100 - health_score, 1)
        else:
            risk_score = None

        if risk_score is None:
            rag_color, rag_label = "#95A5A6", "Data Belum Lengkap"
        elif risk_score <= 30:
            rag_color, rag_label = "#2E7D32", f"LOW RISK ({risk_score})"
        elif risk_score <= 60:
            rag_color, rag_label = "#F0B429", f"MEDIUM RISK ({risk_score})"
        else:
            rag_color, rag_label = "#C0392B", f"HIGH RISK ({risk_score})"

        st.markdown(f"""
<div style="background:{rag_color}1A; border-left:6px solid {rag_color}; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
<span style="font-size:20px; font-weight:700; color:{rag_color};">● Cybersecurity Risk Score: {rag_label}</span>
<span style="font-size:14px; color:#5A6B85;">{delta_text}</span>
</div>
""", unsafe_allow_html=True)

        with st.expander("ℹ️ Metodologi Risk Score (klik untuk lihat rincian komponen)"):
            st.markdown(
                "Skor 0-100, **semakin TINGGI = semakin BERISIKO**. Gabungan 3 komponen "
                "(cuma dihitung dari komponen yang datanya tersedia):"
            )
            method_df = pd.DataFrame([
                ["A. SLA Compliance (40%)", f"{round(comp_a,1) if comp_a is not None else '-'}",
                 "100 - % Breach keseluruhan periode ini"],
                ["B. Tren Detection Rate (30%)", f"{round(comp_b,1) if comp_b is not None else '-'}",
                 "Membaik/memburuk vs bulan lalu (butuh >=2 periode)"],
                ["C. Perbaikan Isu Berulang (30%)", f"{round(comp_c,1) if comp_c is not None else '-'}",
                 "Action Tracker Improvement Rate - rule yang tadinya bermasalah, sekarang sudah membaik"],
            ], columns=["Komponen", "Nilai (0-100)", "Sumber"])
            st.dataframe(method_df, use_container_width=True)
            st.caption("Ambang: ≤30 Low Risk, 30-60 Medium Risk, >60 High Risk - bisa disesuaikan "
                       "kalau BoD punya standar risk appetite sendiri.")

        top_findings = hyp.head(3)
        if len(top_findings) > 0:
            with st.expander("📝 Ringkasan Temuan Utama (klik untuk lihat)", expanded=True):
                for _, row in top_findings.iterrows():
                    st.markdown(f"- **{row['Hipotesis'].split(' - ', 1)[-1]}**: {row['Temuan']}")

    st.divider()

    # --- 1. Tren Bulan ke Bulan (nomor 1 sesuai permintaan user - metrik yang
    # paling sering ditanya BoD di awal presentasi: "trennya gimana?") ---
    st.markdown("## 1️⃣ Tren Bulan ke Bulan (Month-over-Month)")
    mc = report.get("monthly_comparison")
    if mc is not None and len(mc) >= 2:
        all_periods = mc["Period"].tolist()
        st.warning(
            "⚠️ Kalau tanggal/bulan yang muncul di chart TIDAK SESUAI dugaan Anda (mis. masih ada "
            "bulan lama yang sudah dihapus), itu karena **menghapus file Excel yang Anda upload TIDAK "
            "otomatis menghapus histori tersimpan aplikasi** (`database/` folder) - itu penyimpanan "
            "terpisah. Untuk reset total: sidebar → '📂 Buka Laporan Tersimpan' → expander '⚠️ Hapus "
            "SEMUA data tersimpan' → centang konfirmasi → klik tombol hapus."
        )
        selected_periods = st.multiselect(
            "Pilih bulan yang ditampilkan/dibandingkan",
            options=all_periods, default=all_periods, key="exec_period_filter"
        )
        mc_filtered = mc[mc["Period"].isin(selected_periods)] if selected_periods else mc

        if len(mc_filtered) == 0:
            st.warning("⚠️ Pilih minimal 1 bulan untuk ditampilkan.")
        elif len(mc_filtered) == 1:
            st.info(f"Cuma 1 bulan dipilih ({mc_filtered.iloc[0]['Period']}) - centang bulan lain "
                    "juga untuk membandingkan tren.")
            show_metrics(pd.DataFrame([
                {"Metric": "Total Alert", "Value": int(mc_filtered.iloc[0]["Total_Alert"])},
                {"Metric": "Total Incident", "Value": int(mc_filtered.iloc[0]["Total_Incident"])},
            ]), cols=2)
        else:
            st.markdown("**Total Alert & Incident per Month**")
            plot_bar_multi(mc_filtered, "Period", ["Total_Alert", "Total_Incident"])
    elif mc is not None and len(mc) == 1:
        st.info(f"ℹ️ Baru 1 periode tersimpan ({mc.iloc[0]['Period']}). Upload & generate bulan lain "
                "untuk mulai melihat tren perbandingan.")
    else:
        st.warning("⚠️ Belum ada data tren bulanan.")
    if st.button("Lihat Detail Perbandingan Bulanan →", key="btn_goto_compare"):
        goto_page("📊 Perbandingan Bulanan")

    st.divider()

    # --- 2. Cybersecurity Incident Ticket Performance ---
    st.markdown("## 2️⃣ Cybersecurity Incident Ticket Performance")
    if len(report.get("sla_metrics", [])) > 0:
        overall_sla = report["sla_metrics"][report["sla_metrics"]["Priority_Label"] == "SEMUA"].iloc[0]
        # .get() dengan default - supaya kalau laporan ini dari CACHE LAMA
        # (skema sebelum kolom %_Breach/Jumlah_Breach ditambahkan), tidak
        # crash KeyError, cuma tampil "-" dan sarankan generate ulang.
        is_old_schema = "%_Breach" not in overall_sla.index
        if is_old_schema:
            st.warning("⚠️ Laporan ini dari skema versi lama (belum ada data breach per-severity) - "
                       "generate ulang periode ini untuk data terbaru.")

        c0a, c0b, c0c = st.columns(3)
        c0a.metric("Total Tiket", int(overall_sla.get("Jumlah_Tiket", 0)))
        pct_breach = overall_sla.get("%_Breach", "-")
        c0b.metric("% Breach", f"{pct_breach}%" if pct_breach != "-" else "-")
        detection_rate = exec_df[exec_df["Metric"] == "Detection Rate"]["Value"].values
        c0c.metric("Detection Rate", detection_rate[0] if len(detection_rate) else "-")

        c1, c2 = st.columns([3, 2])
        with c1:
            st.markdown("**SLA by Severity**")
            radar_df = report["sla_metrics"][report["sla_metrics"]["Priority_Label"] != "SEMUA"]
            radar_cols = [c for c in ["Avg_MTTD_menit", "Avg_MTTR_menit", "Avg_MTTC_menit", "Avg_MTTRV_menit"]
                          if c in radar_df.columns]
            if radar_cols:
                plot_radar(radar_df, "Priority_Label", radar_cols)
            if overall_sla.get("Avg_MTTD_menit") == "Belum ada data":
                st.caption("⚠️ MTTD belum ada datanya periode ini - digambar 0 di radar (BUKAN cepat).")
            st.caption("⚠️ MTTC (Contain) belum ada datanya sama sekali - menunggu kolom timestamp dari Ivanti.")
        with c2:
            st.markdown("**Meet vs Breach**")
            if "Jumlah_Breach" in overall_sla.index:
                meet_breach_df = pd.DataFrame({
                    "Status": ["Meet", "Breach"],
                    "Jumlah": [overall_sla["Jumlah_Tiket"] - overall_sla["Jumlah_Breach"], overall_sla["Jumlah_Breach"]],
                })
                plot_pie(meet_breach_df, "Status", "Jumlah", semantic=False)
            else:
                st.caption("⚠️ Data Meet vs Breach belum tersedia di laporan versi ini.")
    else:
        st.info("ℹ️ Belum ada data tiket untuk periode ini.")
    if st.button("Lihat Detail Ticket Performance →", key="btn_goto_efektivitas"):
        goto_page("Efektivitas")

    st.divider()

    # --- 3. Cybersecurity Attack Patterns ---
    st.markdown("## 3️⃣ Cybersecurity Attack Patterns")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Subject (Internal vs External) - Periode Ini**")
        if len(report.get("subject_internal_external", [])) > 0:
            plot_pie(report["subject_internal_external"], "_Subject_Origin", "Jumlah", semantic=True)
        else:
            st.warning("⚠️ Belum ada data (kolom 'Incident Type' tidak ditemukan di file yang diupload).")
    with c2:
        tbpd = report.get("threat_by_priority_domain")
        tbpd_direct = report.get("threat_by_priority_domain_direct")
        # Deteksi otomatis: keyword-mapping "gagal total" kalau cuma 1 baris
        # dan baris itu "Others" - biasanya karena 'Summary' tidak ada di
        # file (lihat CHANGELOG #88/#90). Kalau begitu DAN versi kolom
        # langsung punya data asli, tampilkan versi LANGSUNG sebagai utama.
        keyword_mapping_failed = (
            len(tbpd) > 0 and len(tbpd) == 1 and str(tbpd.iloc[0]["Security_Domain"]).strip().lower() == "others"
        ) if tbpd is not None else False
        has_direct_data = tbpd_direct is not None and len(tbpd_direct) > 0

        if keyword_mapping_failed and has_direct_data:
            st.markdown("**Object (Target) per Priority - Domain** ⚠️")
            st.warning(
                "Versi keyword-mapping (butuh kolom 'Summary') cuma menghasilkan 'Others' - kemungkinan "
                "'Summary' tidak ada di file ini. Tabel di bawah pakai kolom **'Security Domain' LANGSUNG** "
                "dari Ivanti sebagai gantinya (lebih bisa diandalkan untuk periode ini)."
            )
            st.dataframe(tbpd_direct, use_container_width=True)
        else:
            st.markdown("**Object (Target) per Priority - Domain**")
            if tbpd is not None and len(tbpd) > 0:
                st.dataframe(tbpd, use_container_width=True)
            else:
                st.warning("⚠️ Belum ada data.")
            if has_direct_data:
                with st.expander("Lihat versi dari kolom 'Security Domain' LANGSUNG (pembanding)"):
                    st.dataframe(tbpd_direct, use_container_width=True)

    # Tren Attack Pattern lintas bulan - BARU, sesuai masukan management:
    # "masukin data perbulan historical untuk melihat tren attack" (strategic
    # view, bukan cuma snapshot 1 bulan).
    st.markdown("**Tren Attack Pattern - Lintas Bulan (Strategic View)**")
    apt = report.get("attack_pattern_trend")
    if apt is not None and len(apt) >= 2:
        trend_cols = [c for c in ["Internal", "External", "Tidak Diketahui"] if c in apt.columns]
        if trend_cols:
            plot_bar_multi(apt, "Period", trend_cols)
    elif apt is not None and len(apt) == 1:
        st.info("ℹ️ Baru 1 periode tersimpan - tren Internal vs External akan muncul setelah generate bulan berikutnya.")
    else:
        st.warning("⚠️ Belum ada data tren Attack Pattern.")

    if report.get("attack_surface_trend") is not None and len(report["attack_surface_trend"]) > 0:
        with st.expander("Tren Domain (Attack Surface) Lintas Bulan - dari Keyword-Mapping Rule Name"):
            st.caption("⚠️ Sumber: pencocokan nama rule ke Master Rules (butuh kolom 'Summary' di file "
                       "insiden). Kalau 1 periode tidak punya 'Summary' (lihat warning di atas), SEMUA "
                       "insiden periode itu otomatis jatuh ke 'Others' di tabel ini - BUKAN berarti domain "
                       "asli mereka memang 'Others'.")
            st.dataframe(report["attack_surface_trend"], use_container_width=True)

    sddt = report.get("security_domain_direct_trend")
    if sddt is not None and len(sddt) > 0:
        with st.expander("Tren Security Domain Lintas Bulan - dari Kolom 'Security Domain' LANGSUNG (BARU)"):
            st.caption("Sumber TERPISAH dari tabel di atas - ini dari kolom 'Security Domain' langsung di "
                       "file Ivanti, TIDAK butuh 'Summary'/keyword-mapping sama sekali. Kalau tabel di atas "
                       "'Others' semua tapi ini terisi normal, artinya masalahnya memang di rule-mapping, "
                       "bukan di data domain itu sendiri.")
            st.dataframe(sddt, use_container_width=True)

    # TTP (MITRE ATT&CK) & Cyber Kill Chain - urutan DISUSUN ULANG sesuai
    # alur baca yang benar: Kill Chain = ANCHOR/cerita besar (di tahap mana
    # masalah terkonsentrasi - mudah dipahami siapapun), TTP = TURUNAN/detail
    # teknis DARI anchor itu (bukan sebaliknya - sebelumnya TTP keseluruhan
    # tampil duluan, bikin bingung karena belum ada konteks "TTP dari mana").
    # Triage (True Positive/False Positive) - field BARU (dikonfirmasi dari
    # Export_Data_SOC_2.xlsx). Kalau tidak ada data Triage sama sekali
    # (format lama / semua 'Unknown'), tampilkan warning gap seperti dulu.
    # Kalau ADA, kasih toggle - filter MITRE/KillChain ke True Positive
    # SAJA secara default (dikonfirmasi user), TAPI user bisa balik ke
    # semua tiket tanpa generate ulang (recompute langsung dari data mentah).
    enriched_raw = report.get("mitre_enriched_raw")
    has_triage_data = (
        enriched_raw is not None and len(enriched_raw) > 0
        and "_Triage" in enriched_raw.columns
        and (enriched_raw["_Triage"] != "Unknown").any()
    )

    if has_triage_data:
        triage_summary = report.get("triage_summary")
        tc1, tc2 = st.columns([2, 3])
        with tc1:
            filter_tp_only = st.checkbox("🎯 Filter ke True Positive saja", value=True, key="mitre_filter_tp_only")
        with tc2:
            tp_pct = triage_summary[triage_summary["Triage"] == "True Positive"]["Percent"].sum()
            fp_pct = triage_summary[triage_summary["Triage"] == "False Positive"]["Percent"].sum()
            st.caption(f"Triage keseluruhan periode ini: **{tp_pct}% True Positive**, **{fp_pct}% False Positive** "
                       f"- chart di bawah {'HANYA menghitung True Positive' if filter_tp_only else 'menghitung SEMUA tiket (termasuk False Positive)'}.")

        mitre_df = enriched_raw[enriched_raw["_Triage"] == "True Positive"] if filter_tp_only else enriched_raw
        if filter_tp_only and len(mitre_df) == 0:
            st.warning("⚠️ Tidak ada insiden True Positive di periode ini - matikan filter untuk lihat semua tiket.")
    else:
        filter_tp_only = False
        mitre_df = enriched_raw if enriched_raw is not None else pd.DataFrame()
        st.caption(
            "⚠️ **Cakupan data**: chart di bawah menghitung SEMUA tiket, TIDAK ADA filter True Positive/"
            "False Positive - file Ivanti ini belum punya kolom Triage. Ditandai ke tim Ivanti sebagai "
            "gap data yang perlu dilengkapi."
        )

    # Recompute SEMUA output MITRE/KillChain dari mitre_df (hasil filter
    # toggle di atas) - BUKAN pakai report["mitre_technique_summary"] dkk
    # yang statis (itu selalu dari SEMUA tiket, dihitung sekali saat generate).
    if len(mitre_df) > 0:
        kc_raw = build_killchain_summary(mitre_df)
        mitre_tech_live = build_mitre_technique_summary(mitre_df)
        mitre_tac_live = build_mitre_tactic_summary(mitre_df)
    else:
        kc_raw = report.get("killchain_summary")
        mitre_tech_live = report.get("mitre_technique_summary")
        mitre_tac_live = report.get("mitre_tactic_summary")

    # --- ANCHOR: Cyber Kill Chain Funnel ---
    st.markdown("### 🎯 Anchor: Di Tahap Mana Serangan Paling Sering Terkonsentrasi?")
    if kc_raw is not None and len(kc_raw) > 0 and kc_raw["Count"].sum() > 0:
        plot_bar(kc_raw, "Stage", "Count")
        st.caption("Data APA ADANYA dari tiket - 1 tiket bisa menyebut lebih dari 1 stage, jadi angkanya boleh "
                   "naik-turun (tidak dipaksa menurun ke kanan).")
    else:
        st.warning("⚠️ Belum ada data Kill Chain untuk subset yang dipilih.")

    # --- TURUNAN LANGSUNG dari anchor: korelasi Tactic->Technique via mini-Sunburst,
    # BUKAN 2 bar chart terpisah (yang tidak menunjukkan hubungan Tactic mana
    # punya Technique apa) ---
    # drilldown_map & top_stage DIHITUNG ULANG LIVE dari mitre_df (ikut
    # toggle TP/FP di atas) kalau ada data Triage - report["killchain_
    # stage_drilldown"] statis (dari SEMUA tiket) dipakai HANYA kalau
    # tidak ada Triage sama sekali (fallback, sama seperti kc_raw di atas).
    if has_triage_data and len(mitre_df) > 0 and kc_raw is not None and kc_raw["Count"].sum() > 0:
        top_stage = kc_raw.sort_values("Count", ascending=False).iloc[0]["Stage"]
        drilldown_map = {}
        for _, row in kc_raw.iterrows():
            if row["Count"] > 0:
                tech, tac, n, hier, tac_uniq, tech_uniq = build_mitre_by_killchain_stage(mitre_df, row["Stage"])
                drilldown_map[row["Stage"]] = {
                    "technique": tech, "tactic": tac, "n": n, "hierarchy": hier,
                    "tactic_unique_n": tac_uniq, "technique_unique_n": tech_uniq,
                }
    else:
        top_stage = report.get("killchain_top_stage")
        drilldown_map = report.get("killchain_stage_drilldown", {})
    if drilldown_map:
        st.markdown("### ⬇️ Turunan dari Anchor: Apa yang Terjadi di Tiap Stage?")
        available_stages = list(drilldown_map.keys())
        default_idx = available_stages.index(top_stage) if top_stage in available_stages else 0
        selected_stage = st.selectbox(
            "Pilih stage untuk dilihat detail Tactic/Technique-nya",
            available_stages, index=default_idx, key="killchain_drilldown_stage_select"
        )
        dd = drilldown_map[selected_stage]
        # Pengaman cache lama: kalau laporan ini dibuat SEBELUM field
        # tactic_unique_n/technique_unique_n ada (perbaikan sebelumnya),
        # tampilkan info jelas + fallback, JANGAN KeyError seperti yang
        # baru terjadi. Pakai .get() di SEMUA akses field dd di bawah ini.
        if "tactic_unique_n" not in dd:
            st.info("ℹ️ Laporan ini dari cache versi lama (belum ada data korelasi Tactic/Technique "
                    "terbaru) - generate ulang periode ini (upload file yang sama + klik Generate, "
                    "bukan 'Buka') untuk fitur fokus Tactic & label yang akurat.")

        st.caption(f"Stage '{selected_stage}' tercatat di {dd.get('n', 0)} insiden periode ini"
                   f"{' - PALING BANYAK dari semua stage' if selected_stage == top_stage else ''}. "
                   "Chart di bawah menunjukkan KORELASI Tactic (kiri) <-> Technique (kanan) - warna simpul & "
                   "garis dikelompokkan per Tactic (garis diminimalkan bersilangan), makin tebal/gelap "
                   "berarti pasangan itu makin sering muncul bersamaan. Label simpul = JUMLAH INSIDEN UNIK "
                   "(bukan jumlah pasangan - 1 insiden bisa punya >1 Technique sekaligus, jadi jumlah "
                   "pasangan bisa lebih besar dari jumlah insiden asli).")
        hier_full = dd.get("hierarchy")
        if hier_full is not None and len(hier_full) > 0:
            tactic_options = ["Semua Tactic"] + sorted(hier_full["Tactic"].unique().tolist())
            focus_tactic = st.selectbox(
                "🔍 Fokus ke 1 Tactic tertentu (opsional - sembunyikan Tactic lain)",
                tactic_options, index=0, key=f"tactic_focus_{selected_stage}"
            )
            tactic_unique_n = dd.get("tactic_unique_n") or {}
            technique_unique_n = dd.get("technique_unique_n") or {}
            if focus_tactic != "Semua Tactic":
                hier_view = hier_full[hier_full["Tactic"] == focus_tactic].copy()
                tac_uniq_view = {focus_tactic: tactic_unique_n.get(focus_tactic, 0)}
                tech_uniq_view = {
                    t: n for t, n in technique_unique_n.items()
                    if t in hier_view["Technique"].values
                }
                st.caption(f"🔎 Fokus: **{focus_tactic}** - Technique lain yang TIDAK berasosiasi dengan "
                           "Tactic ini disembunyikan sementara. Pilih 'Semua Tactic' lagi untuk kembali.")
            else:
                hier_view, tac_uniq_view, tech_uniq_view = hier_full, tactic_unique_n, technique_unique_n

            plot_network(hier_view, "Tactic", "Technique", "Count",
                         title=f"Tactic ↔ Technique khusus stage '{selected_stage}'",
                         left_unique_n=tac_uniq_view, right_unique_n=tech_uniq_view)
        else:
            st.warning(f"⚠️ Belum ada data MITRE untuk insiden di stage '{selected_stage}'.")

    if has_triage_data and len(mitre_df) > 0:
        mkc_insights = generate_mitre_killchain_insights(mitre_tech_live, mitre_tac_live, kc_raw, len(mitre_df))
    else:
        mkc_insights = report.get("mitre_killchain_insights")
    if mkc_insights:
        with st.expander("📝 Insight MITRE & Kill Chain", expanded=True):
            for ins in mkc_insights:
                st.markdown(f"- {ins}")

    dq = report.get("mitre_killchain_dq")
    if dq is not None and len(dq) > 0:
        st.warning(f"⚠️ **Data Quality**: {len(dq)} tiket punya nilai MITRE/KillChain yang tidak sesuai format "
                   "standar - lihat detail di halaman Threat Profiling.")

    st.warning("⚠️ **Belum tersedia**: Security Control (detector/mitigator) - menunggu klarifikasi field/sumber data.")
    if st.button("Lihat Detail Attack Patterns →", key="btn_goto_threat"):
        goto_page("Threat Profiling")

    st.divider()

    # --- 3. SOC Ticket Performance (People Performance) ---
    st.markdown("## 4️⃣ SOC Ticket Performance (People Performance)")
    if len(report.get("soc_individual_kpi", [])) > 0:
        kpi_all = report["soc_individual_kpi"].copy()

        # Rata-rata MTTR SATU TIM keseluruhan (bukan per-analyst) - angka
        # simpel untuk BoD, dihitung dari rata-rata tertimbang jumlah tiket
        # tiap analyst (bukan cuma rata-rata dari rata-rata).
        team_mttr_sec = (kpi_all["Avg_MTTR_sec"] * kpi_all["Total_Incident"]).sum() / max(kpi_all["Total_Incident"].sum(), 1)
        team_breach_rate = round(100 * kpi_all["Breach"].sum() / max(kpi_all["Total_Incident"].sum(), 1), 1)
        cA, cB, cC = st.columns(3)
        cA.metric("Rata-rata MTTR Tim (menit)", round(team_mttr_sec / 60, 1))
        cB.metric("Total Analyst Aktif", len(kpi_all))
        cC.metric("Breach Rate Tim", f"{team_breach_rate}%")

        c1, c2 = st.columns([3, 2])
        with c1:
            st.markdown(f"**Analyst Performance Radar - Top 6 of {len(kpi_all)} by Ticket Volume**")
            st.caption(
                "⚠️ Radar cuma menampilkan **Top 6 analyst dengan tiket terbanyak** (dari total "
                f"{len(kpi_all)} analyst) - kalau semua {len(kpi_all)} ditampilkan, garis-garisnya akan "
                "saling tumpuk dan tidak terbaca. Chart 'Ticket Taken per Analyst' di sebelah kanan "
                "tetap menampilkan SEMUA analyst."
            )
            top_n = kpi_all.sort_values("Total_Incident", ascending=False).head(6).copy()

            def _normalize(s, invert=False):
                lo, hi = s.min(), s.max()
                if hi == lo:
                    return pd.Series([50] * len(s), index=s.index)
                norm = (s - lo) / (hi - lo) * 100
                return (100 - norm) if invert else norm

            radar_axes = []
            axis_explanations = []
            if "Total_Incident" in top_n.columns:
                top_n["Ticket Volume Score"] = _normalize(top_n["Total_Incident"])
                radar_axes.append("Ticket Volume Score")
                axis_explanations.append("**Ticket Volume Score** = jumlah tiket yang di-take, dinormalisasi. "
                                          "Makin lebar = makin banyak tiket ditangani (BUKAN penilaian baik/buruk, "
                                          "cuma volume beban kerja).")
            if "Avg_MTTR_sec" in top_n.columns:
                top_n["Response Speed Score"] = _normalize(top_n["Avg_MTTR_sec"], invert=True)
                radar_axes.append("Response Speed Score")
                axis_explanations.append("**Response Speed Score** = kebalikan dari MTTR (Avg_MTTR_sec). "
                                          "Makin lebar = makin CEPAT merespons tiket (bukan makin lambat).")
            if "Avg_MTTRV_sec" in top_n.columns:
                top_n["Resolution Speed Score"] = _normalize(top_n["Avg_MTTRV_sec"], invert=True)
                radar_axes.append("Resolution Speed Score")
                axis_explanations.append("**Resolution Speed Score** = kebalikan dari MTTRV (Avg_MTTRV_sec). "
                                          "Makin lebar = makin CEPAT menyelesaikan tiket.")
            if "Breach_Rate_%" in top_n.columns:
                top_n["SLA Meet Rate Score"] = 100 - top_n["Breach_Rate_%"]
                radar_axes.append("SLA Meet Rate Score")
                axis_explanations.append("**SLA Meet Rate Score** = 100% dikurangi Breach Rate. "
                                          "Makin lebar = makin sedikit tiket yang breach SLA.")

            if len(radar_axes) >= 3:
                plot_radar(top_n, "Owner", radar_axes)
                with st.expander("ℹ️ Arti tiap sumbu radar ini"):
                    for exp in axis_explanations:
                        st.markdown(f"- {exp}")
            else:
                st.warning("⚠️ Data belum lengkap untuk radar (laporan versi lama) - generate ulang periode ini.")
        with c2:
            st.markdown(f"**Ticket Taken per Analyst - Semua {len(kpi_all)} Analyst**")
            plot_bar(kpi_all, "Owner", "Total_Incident", distinct_colors=True)
    else:
        st.warning("⚠️ Belum ada data analyst untuk periode ini.")

    st.markdown("**Operational Tasks (dari tim lain)**")
    if len(report.get("task_summary", [])) > 0:
        show_metrics(report["task_summary"], label_col="Metrik", value_col="Nilai")
    else:
        st.warning("⚠️ Belum ada data Task SOC diupload periode ini.")
    if st.button("Lihat Detail SOC Performance →", key="btn_goto_kpi"):
        goto_page("KPI Analyst")

    st.divider()

    st.divider()
    with st.expander("📖 Menu mana menjawab pertanyaan yang mana? (penjelasan lengkap)"):
        st.markdown("""
| Pertanyaan | Dijawab di sini (ringkas) | Detail lengkap ada di halaman |
|---|---|---|
| SLA (MTTD/MTTR/MTTC/MTTRV per severity) | Radar chart | **Efektivitas** |
| Meet vs Breach | Pie chart | **Efektivitas**, **KPI Analyst** |
| Dormant/Noisy Rules, Rule Accuracy | *(dipindah keluar - lihat kolom kanan)* | **Ticket** |
| Attack Pattern (Subject/Object/Security Control/TTP/Kill Chain) | Sebagian (Subject & Object) | **Threat Profiling** |
| Ticket Taken per person | Bar chart | **KPI Analyst** |
| Personnel SLA per orang | Radar chart | **KPI Analyst** |
| Operational Tasks | Kartu angka | **Non-Splunk & Task** |
| Tren bulan ke bulan | Bar + line chart | **📊 Perbandingan Bulanan** |
| Dasar teori/istilah | - | **Help** |
        """)

# ---------------------------------------------------------
# TAB: OVERVIEW
# ---------------------------------------------------------
if current_page == "Overview":
    with st.expander("Cara membaca laporan ini (sheet, chart, sumber data)"):
        st.dataframe(report["reading_guide"], use_container_width=True)

    # Peringatan kalau Master Rules tidak punya kolom status - supaya "Rule
    # Splunk Active: 0" tidak membingungkan (sebelumnya cuma tercatat di log
    # console yang tidak kelihatan user, sekarang eksplisit di UI).
    rs = report["rule_summary"]
    if len(rs) > 0 and rs["Rule_Status"].astype(str).eq("Unknown").all():
        st.warning(
            "⚠️ File Master Rules Splunk yang diupload TIDAK punya kolom status "
            "(Enabled/Disabled) - semua rule ditandai 'Unknown'. Itu sebabnya "
            "**'Rule Splunk Active' tertulis 0** - BUKAN berarti tidak ada rule aktif, "
            "cuma datanya tidak tersedia untuk dihitung. Kalau punya file dengan kolom "
            "status, upload ulang untuk angka yang akurat."
        )

    st.subheader("Ringkasan Angka Kunci")
    existing_groups = set(exec_df["Group"].unique())
    for group_name, group_df in exec_df.groupby("Group", sort=False):
        if group_name == "Periode":
            continue
        st.markdown(f"**{group_name}**")
        show_metrics(group_df)

    if "3. Task dari Tim Lain" not in existing_groups:
        st.markdown("**3. Task dari Tim Lain**")
        st.caption("Belum ada data task diupload periode ini.")
    if "2. Non-Splunk vs Ivanti" not in existing_groups:
        st.markdown("**2. Non-Splunk vs Ivanti**")
        st.caption("Belum ada data alert non-Splunk diupload periode ini.")

    st.subheader("Key Findings")
    for _, row in hyp.iterrows():
        st.info(f"**{row['Hipotesis']}** — {row['Temuan']}")
        if pd.notna(row.get("Sumber_Data")):
            st.caption(f"📌 {row['Sumber_Data']}")

# ---------------------------------------------------------
# TAB: PERBANDINGAN BULANAN (tracking SEMUA periode + akses laporan lama)
# ---------------------------------------------------------
if current_page == "📊 Perbandingan Bulanan":
    st.caption(
        "Tab ini menjawab: **bagaimana perbandingan antar bulan yang sudah pernah diupload?** "
        "Otomatis terisi tiap kali Anda generate report - tidak perlu upload ulang periode lama."
    )
    mc = report.get("monthly_comparison")
    if mc is None or len(mc) < 2:
        st.info(
            f"Baru {len(mc) if mc is not None else 0} periode tersimpan. Upload & generate report "
            "untuk periode lain (mis. Juni) supaya perbandingan mulai muncul di sini."
        )
    else:
        st.markdown("**Perbandingan Total Alert & Insiden**")
        plot_bar_multi(mc, "Period", ["Total_Alert", "Total_Incident"])
        st.markdown("**Detection Rate per Periode**")
        plot_line(mc, "Period", ["Detection_Rate_%"])
        st.dataframe(mc, use_container_width=True)

    sev_trend = report.get("severity_trend")
    if sev_trend is not None and len(sev_trend) >= 2:
        st.markdown("**Tren Severity (Critical/High/Medium/Low)**")
        sev_cols = [c for c in ["Critical", "High", "Medium", "Low"] if c in sev_trend.columns]
        if sev_cols:
            plot_line(sev_trend, "Period", sev_cols)

    ast = report.get("attack_surface_trend")
    if ast is not None and len(ast) > 0:
        st.markdown("**Tren Domain (Attack Surface)**")
        st.dataframe(ast, use_container_width=True)

    st.divider()
    st.markdown("**📁 Laporan Tersimpan (download ulang periode sebelumnya)**")
    output_dir = Path("output")
    if output_dir.exists():
        saved_files = sorted(
            [f for f in output_dir.glob("SOC_Report_*.xlsx")] + [f for f in output_dir.glob("SOC_Report_*.pptx")],
            key=lambda f: f.stat().st_mtime, reverse=True
        )
        if saved_files:
            for f in saved_files:
                with open(f, "rb") as fh:
                    st.download_button(f"⬇️ {f.name}", fh.read(), file_name=f.name, key=f"dl_{f.name}")
        else:
            st.caption("Belum ada laporan tersimpan di folder `output/`.")
    else:
        st.caption("Belum ada laporan tersimpan.")

# ---------------------------------------------------------
# TAB: SPLUNK VS IVANTI
# ---------------------------------------------------------
if current_page == "Ticket":
    st.caption("🎫 Menjawab: rule mana yang butuh perhatian, tiket mana yang jadi gap.")
    g = exec_df[exec_df["Group"] == "1. Ticket"]
    show_metrics(g)
    show_insights(["H4", "H1", "H3", "H6", "H-Entity"])

    st.caption(
        "**Definisi status rule**: **Noise** = alert banyak (≥20) tapi 0 insiden. "
        "**Critical/Need Tuning, Review** = detection rate rendah. "
        "**Acceptable** = 10-25%, cukup tapi belum optimal. **Healthy** = ≥25%. "
        "**Dormant** = 0 alert sama sekali periode ini."
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Top 10 Rule (by Incident Count)**")
        top10 = report["top_rule"].head(10)[["Rule_Names", "Alert_Count", "Incident_Count"]]
        plot_bar_multi(top10, "Rule_Names", ["Alert_Count", "Incident_Count"])
    with c2:
        st.markdown("**Distribusi Status Rule (%)**")
        if len(report.get("rule_recommendation_distribution", [])) > 0:
            plot_pie(report["rule_recommendation_distribution"], "Recommendation", "%", semantic=True)

    st.markdown("**Distribusi Security Domain (Incident)**")
    domain_view = apply_filter(report["domain"], "Security_Domain", f_domain)
    plot_bar(domain_view, "Security_Domain", "Incident", category=True)

    st.markdown("**Deep-dive: dampak & rekomendasi per rule (Top 10 by Incident Count)**")
    for _, row in report["top_rule"].head(10).iterrows():
        st.markdown(f"- **{row['Rule_Names']}** — {rule_insight_text(row)}")

    with st.expander("Detail: Domain x Tuning, Noise/Tuning/Dormant, Entity Multi-Vektor, Rule Summary, Rule Belum Ter-mapping"):
        st.markdown("**Domain mana paling butuh tuning**")
        st.dataframe(apply_filter(report["domain_recommendation"], "Security_Domain", f_domain), use_container_width=True)
        tab1, tab2, tab3 = st.tabs(["Noise", "Tuning", "Dormant"])
        tab1.dataframe(report["noise"], use_container_width=True)
        tab2.dataframe(report["tuning"], use_container_width=True)
        tab3.dataframe(report["dormant"], use_container_width=True)
        st.markdown("**Entity Multi-Vektor (PIC tujuan tiket, bukan SOC pengerja)**")
        st.dataframe(report["entity_correlation"], use_container_width=True)
        st.markdown("**Rule belum ter-mapping** (= rule tidak ditemukan di Master Rules)")
        st.dataframe(report["unmapped"], use_container_width=True)
        st.markdown("**Rule Summary** — tabel INDUK semua rule. Sheet Noise/Tuning/Dormant/Top Rule di atas "
                     "adalah HASIL FILTER dari tabel ini, bukan sumber data terpisah.")
        st.dataframe(apply_filter(report["rule_summary"], "Security_Domain", f_domain), use_container_width=True)

# ---------------------------------------------------------
# TAB: THREAT PROFILING & ATTACK SURFACE
# ---------------------------------------------------------
if current_page == "Threat Profiling":
    st.caption("🎯 Menjawab: ancaman apa paling sering, siapa/apa targetnya, sudah membaik atau belum.")
    st.caption(
        "⚠️ **'Asset'/'target' di sini adalah PROXY** (Security_Domain & Customer) - "
        "export Splunk/Ivanti tidak punya data inventaris aset (CMDB) sungguhan."
    )
    st.info("📊 Cari perbandingan Critical/High/Medium/Low **antar bulan**? Lihat tab **'📊 Perbandingan Bulanan'** "
            "(bagian Tren Severity) - tabel Top Threat di bawah ini snapshot 1 periode saja.")
    show_insights(["H-Threat", "H-AttackSurface"])

    if len(report.get("threat_by_priority", [])) > 0:
        st.markdown("**Top 5 Threat per Priority Tier**")
        st.dataframe(apply_filter(report["threat_by_priority"], "Priority_Label", f_priority), use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Domain (proxy asset) per Priority**")
        if len(report.get("threat_by_priority_domain", [])) > 0:
            st.dataframe(apply_filter(report["threat_by_priority_domain"], "Security_Domain", f_domain), use_container_width=True)
    with c2:
        st.markdown("**Target (proxy asset) per Priority**")
        if len(report.get("threat_by_priority_target", [])) > 0:
            st.dataframe(apply_filter(report["threat_by_priority_target"], "Priority_Label", f_priority), use_container_width=True)

    if len(report.get("attack_surface_trend", [])) > 0:
        st.markdown("**Tren Domain Lintas Periode** (butuh >=2 periode histori untuk bermakna)")
        st.dataframe(apply_filter(report["attack_surface_trend"], "Security_Domain", f_domain), use_container_width=True)

    with st.expander("Priority Insiden per Rule Splunk"):
        st.caption("Rule mana yang paling banyak menghasilkan insiden PRIORITY TINGGI, bukan cuma insiden banyak.")
        if len(report.get("priority_per_rule", [])) > 0:
            st.dataframe(report["priority_per_rule"], use_container_width=True)

    if len(report.get("recurring_findings", [])) > 0:
        st.markdown("**Temuan Berulang (Recurring Findings)**")
        st.caption("Rule yang tercatat Noise/Tuning berulang di >=3 dari 5 periode terakhir - pola berulang, bukan kejadian sekali.")
        st.dataframe(report["recurring_findings"], use_container_width=True)

    if len(report.get("action_tracker", [])) > 0:
        st.markdown("**📋 Action Tracker - Tracking Improvement**")
        st.caption(
            "Semua rule yang PERNAH ditandai bermasalah (Noise/Tuning) lintas periode - status "
            "🔴 Masih Terbuka (masih bermasalah sekarang) vs ✅ Sudah Membaik (dulu bermasalah, "
            "sekarang sudah tidak lagi) - bukti nyata tuning/tindak lanjut berjalan atau belum."
        )
        show_insights(["H-ActionTracker"])
        show_metrics(report["action_tracker_summary"], label_col="Metrik", value_col="Nilai")
        st.dataframe(report["action_tracker"], use_container_width=True)

    st.divider()
    st.markdown("## 🎯 MITRE ATT&CK & Cyber Kill Chain")
    st.caption("BARU - field 'Incident MITRE'/'Incident KillChain' dari Ivanti. Kalau kolom ini tidak ada "
               "di file yang diupload (format Ivanti lama), semua bagian di bawah otomatis kosong tanpa error.")

    mc1, mc2 = st.columns(2)
    with mc1:
        st.markdown("**MITRE ATT&CK Technique (semua)**")
        mitre_tech = report.get("mitre_technique_summary")
        if mitre_tech is not None and len(mitre_tech) > 0:
            plot_bar(mitre_tech, "Label", "Count", distinct_colors=True, horizontal=True)
            with st.expander("Data lengkap Technique"):
                st.dataframe(mitre_tech, use_container_width=True)
        else:
            st.warning("⚠️ Belum ada data (kolom 'Incident MITRE' tidak ditemukan di file).")
    with mc2:
        st.markdown("**MITRE ATT&CK Tactic**")
        mitre_tac = report.get("mitre_tactic_summary")
        if mitre_tac is not None and len(mitre_tac) > 0:
            plot_bar(mitre_tac, "Label", "Count", distinct_colors=True, horizontal=True)
        else:
            st.warning("⚠️ Belum ada data.")

    mkc_insights2 = report.get("mitre_killchain_insights")
    if mkc_insights2:
        st.markdown("**📝 Insight MITRE & Kill Chain**")
        for ins in mkc_insights2:
            st.markdown(f"- {ins}")

    st.markdown("**Cyber Kill Chain - Semua Stage yang Disebut per Tiket (non-cumulative)**")
    kc = report.get("killchain_summary")
    if kc is not None and len(kc) > 0 and kc["Count"].sum() > 0:
        plot_bar(kc, "Stage", "Count")
        st.caption("⚠️ Ini BUKAN funnel - 1 tiket bisa menyebut LEBIH DARI 1 stage (mis. tiket yang mencapai "
                   "Exploitation biasanya juga menyebut Delivery), jadi jumlahnya TIDAK harus menurun.")
    else:
        st.warning("⚠️ Belum ada data (kolom 'Incident KillChain' tidak ditemukan di file).")

    with st.expander("📐 Versi Model Kumulatif (Funnel) - BUKAN data mentah, baca disclaimer dulu"):
        st.warning(
            "⚠️ **PENTING**: chart di bawah SELALU berbentuk menurun ke kanan APAPUN isi datanya - itu "
            "properti matematis dari cara hitung 'insiden yang mencapai SETIDAKNYA stage ini' (bukan "
            "cerminan data mentah, dan BUKAN bukti bahwa serangan berhasil ditanggulangi/kill chain "
            "membaik). Kalau butuh gambaran asli tanpa transformasi, lihat chart di atas."
        )
        funnel = report.get("killchain_funnel")
        if funnel is not None and len(funnel) > 0 and funnel["Reached_At_Least"].sum() > 0:
            plot_funnel(funnel, "Stage", "Reached_At_Least")

    st.divider()
    st.markdown("**Turunan MITRE ATT&CK - SEMUA Insiden Periode Ini (Tactic → Technique → Sub-Technique)**")
    st.warning(
        "⚠️ **PENTING**: chart ini menggabungkan SEMUA 219 insiden periode ini (termasuk yang TIDAK punya "
        "Kill Chain stage sama sekali) - **BUKAN dipecah per stage Kill Chain**. Kalau mau lihat MITRE "
        "khusus 1 stage tertentu (mis. Exploitation saja), gunakan selector 'Turunan dari Anchor' di "
        "Executive Summary, bukan chart ini."
    )
    hier = report.get("mitre_hierarchy")
    if hier is not None and len(hier) > 0:
        hier_top = hier.head(15)  # dibatasi 15 dari total kombinasi - supaya tidak terlalu padat dibaca
        plot_sunburst(hier_top, ["Tactic", "Technique", "SubTechnique"], "Count")
        st.caption(
            f"Klik salah satu potongan untuk zoom. Lingkaran dalam = Tactic, tengah = Technique, "
            f"luar = Sub-Technique - dibatasi Top 15 kombinasi (dari total {len(hier)}) supaya tidak terlalu padat."
        )
        st.info(
            "ℹ️ **Soal insight untuk tuning query Splunk**: chart ini BELUM BISA menjawab 'rule Splunk "
            "mana yang perlu di-tuning' - itu butuh data PEMETAAN Rule Splunk ↔ MITRE Technique yang "
            "SAAT INI TIDAK ADA di sistem kita."
        )
    else:
        st.warning("⚠️ Belum ada data MITRE (kolom 'Incident MITRE' tidak ditemukan di file).")

    dq = report.get("mitre_killchain_dq")
    if dq is not None and len(dq) > 0:
        st.markdown("**⚠️ Data Quality - MITRE/KillChain**")
        st.warning(
            f"{len(dq)} tiket punya nilai yang TIDAK SESUAI format standar (bukan `[TXXXX]`/`[TAXXXX]` untuk "
            "MITRE, atau bukan salah satu dari 8 stage Kill Chain yang dikenal) - kemungkinan salah input "
            "manual di Ivanti. Perlu dicek/dibenarkan langsung di tiket terkait, TIDAK dihitung di chart di atas."
        )
        st.dataframe(dq, use_container_width=True)

    sdd = report.get("security_domain_direct")
    if sdd is not None and len(sdd) > 0:
        with st.expander("Security Domain - LANGSUNG dari kolom Ivanti (terpisah dari keyword-mapping di atas)"):
            st.caption("Ini sumber TERPISAH dari 'Domain mana paling butuh tuning' di atas (yang berasal dari "
                       "keyword-mapping Rule Name) - dipakai sesuai arahan: keduanya untuk tujuan berbeda.")
            plot_bar(sdd, "Security_Domain", "Jumlah", distinct_colors=True)
            st.dataframe(sdd, use_container_width=True)

    triage_sum = report.get("triage_summary")
    if triage_sum is not None and len(triage_sum) > 0 and (triage_sum["Triage"] != "Unknown").any():
        st.divider()
        st.markdown("## 🔍 Triage - True Positive / False Positive")
        st.caption("Field BARU dari Ivanti - klasifikasi analyst apakah tiket ini ancaman nyata atau false "
                   "alarm. Dipakai sebagai filter default di chart MITRE/Kill Chain Executive Summary.")
        plot_bar(triage_sum, "Triage", "Count", distinct_colors=True)
        st.dataframe(triage_sum, use_container_width=True)

    enriched_detail = report.get("mitre_enriched_raw")
    if enriched_detail is not None and len(enriched_detail) > 0 and "Description" in enriched_detail.columns:
        st.divider()
        st.markdown("## 📄 Investigasi Detail - Isi Field Description")
        st.caption(
            "Field BARU (menggantikan 'Summary') - berisi data mentah hasil Splunk (format key:value), TAPI "
            "field yang muncul BEDA-BEDA tergantung jenis alert (AWS CloudTrail vs WAF vs Windows Event, dst) "
            "- TIDAK ada skema tetap, jadi TIDAK dipakai untuk Rule Name mapping otomatis. Pilih 1 tiket di "
            "bawah untuk lihat isi key-value-nya yang sudah diparse."
        )
        ticket_options = enriched_detail["Incident"].astype(str).tolist() if "Incident" in enriched_detail.columns else []
        if ticket_options:
            selected_ticket = st.selectbox("Pilih Ticket Number", ticket_options, key="desc_viewer_ticket_select")
            row = enriched_detail[enriched_detail["Incident"].astype(str) == selected_ticket].iloc[0]
            parsed_kv = parse_description_kv(row.get("Description"))
            if parsed_kv:
                kv_df = pd.DataFrame(list(parsed_kv.items()), columns=["Field", "Value"])
                st.dataframe(kv_df, use_container_width=True, hide_index=True)
            else:
                st.caption("(Description tiket ini tidak mengikuti pola key:value - ditampilkan apa adanya di bawah)")
            with st.expander("Lihat teks Description asli (mentah)"):
                st.text(str(row.get("Description", "")))

# ---------------------------------------------------------
# TAB: NON-SPLUNK & TASK (digabung supaya tab tidak terlalu banyak)
# ---------------------------------------------------------
if current_page == "Non-Splunk & Task":
    st.caption("📧📋 Menjawab: alert dari device di luar Splunk, dan task dari tim lain tanpa tiket insiden resmi.")

    st.markdown("### Non-Splunk vs Ivanti")
    g = exec_df[exec_df["Group"] == "2. Non-Splunk vs Ivanti"]
    show_metrics(g)
    show_insights(["H2"])
    if len(report["nonsplunk_coverage"]) > 0:
        st.markdown("**Coverage per Device (%)**")
        plot_bar(report["nonsplunk_coverage"], "Source_Device", "Coverage_%", distinct_colors=True)
        st.caption("Kolom CTI_dari_N & Gap_Murni_dari_N di tabel di bawah adalah RINCIAN dari "
                   "Tidak_Jadi_Tiket - bukan kategori tambahan (jangan dijumlah lagi).")
        st.dataframe(report["nonsplunk_coverage"], use_container_width=True)
        with st.expander("Detail alert non-Splunk mentah"):
            st.dataframe(report["nonsplunk_detail"], use_container_width=True)
    else:
        st.caption("Belum ada data alert non-Splunk diupload periode ini.")

    st.divider()
    st.markdown("### Task dari Tim Lain")
    if len(report.get("task_summary", [])) > 0:
        g = exec_df[exec_df["Group"] == "3. Task dari Tim Lain"]
        show_metrics(g)
        show_insights(["H-TaskWorkload"])
        st.markdown("**Per Analyst**")
        plot_bar(apply_filter(report["task_by_owner"], "Owner", f_analyst), "Owner", "Total_Task")
        st.dataframe(apply_filter(report["task_by_owner"], "Owner", f_analyst), use_container_width=True)
        if len(report.get("task_by_requestor", [])) > 0:
            st.markdown("**Per Tim Peminta**")
            st.dataframe(report["task_by_requestor"], use_container_width=True)
        if len(report.get("lesson_learned_log", [])) > 0:
            with st.expander(f"📚 Lesson Learned Log dari Task ({len(report['lesson_learned_log'])} catatan)"):
                st.caption("Dari modul Task (bukan Incident - Incident tidak punya kolom catatan bebas).")
                st.dataframe(report["lesson_learned_log"], use_container_width=True)
    else:
        st.caption("Belum ada data task diupload periode ini - upload file Task SOC dari sidebar untuk mengisi bagian ini.")

    st.divider()
    st.markdown("### CTI FortiRecon")
    st.caption("🔒 Kolom Password dari sumber TIDAK ditampilkan mentah - hanya indikator ada/tidak kredensial bocor.")
    if len(report.get("cti_summary", [])) > 0:
        show_insights(["H-CTIFortiRecon"])
        show_metrics(report["cti_summary"], label_col="Metrik", value_col="Nilai")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Per Jenis Alert**")
            plot_bar(report["cti_by_type"], "Alert_Type", "Jumlah")
        with c2:
            st.markdown("**Per Status**")
            plot_pie(report["cti_by_status"], "Status", "Jumlah")
        if len(report.get("cti_trend", [])) >= 2:
            st.markdown("**Tren CTI Lintas Periode**")
            plot_bar_multi(report["cti_trend"], "Period", ["Total_CTI_Alert", "True_Positive"])
        with st.expander("Detail alert CTI mentah (password sudah dimasking)"):
            st.dataframe(report.get("cti_detail", pd.DataFrame()), use_container_width=True)
    else:
        st.caption("Belum ada data CTI FortiRecon diupload periode ini - upload dari sidebar untuk mengisi bagian ini.")

# ---------------------------------------------------------
# TAB: TREN
# ---------------------------------------------------------
if current_page == "Tren":
    st.caption("📈 Menjawab: **kapan** alert/insiden paling banyak terjadi - per tanggal, per jam, per hari.")
    with st.expander("ℹ️ Detail teknis & cakupan data"):
        st.write(
            "Cakupan: HANYA alert Splunk + insiden Ivanti dari Splunk (non-Splunk ada di tab tersendiri). "
            "Pola Jam & Hari = TOTAL alert dari SEMUA tanggal dalam periode, dikelompokkan per jam/hari - "
            "bukan rata-rata, dan independen dari granularitas tren (harian/mingguan) di atas."
        )
    show_insights(["H-DailyTrend", "H-TimePattern"])
    is_long = report.get("is_long_period", False)

    if is_long and len(report.get("weekly_trend", [])) > 0:
        st.markdown("**Tren Mingguan: Alert Splunk vs Insiden Ivanti**")
        tc1, tc2 = st.columns(2)
        with tc1:
            plot_bar(report["weekly_trend"], "Minggu", "Jumlah_Alert", title="Alert per Minggu")
        with tc2:
            plot_bar(report["weekly_trend"], "Minggu", "Jumlah_Insiden", title="Insiden per Minggu")
        with st.expander("Tabel & detail harian"):
            st.dataframe(
                report["weekly_trend"][["Minggu", "Tanggal_Mulai", "Tanggal_Selesai", "Jumlah_Alert",
                                         "Jumlah_Insiden", "Rule_Kontributor_Terbesar"]],
                use_container_width=True
            )
            st.dataframe(
                report["daily_trend"][["Tanggal", "Jumlah_Alert", "Jumlah_Insiden",
                                        "Rule_Kontributor_Terbesar", "%_dari_Alert_Hari_Itu"]],
                use_container_width=True
            )
    elif len(report.get("daily_trend", [])) > 0:
        st.markdown("**Tren Harian: Alert Splunk vs Insiden Ivanti**")
        tc1, tc2 = st.columns(2)
        with tc1:
            plot_bar(report["daily_trend"], "Tanggal", "Jumlah_Alert", title="Alert per Hari")
        with tc2:
            plot_bar(report["daily_trend"], "Tanggal", "Jumlah_Insiden", title="Insiden per Hari")
        with st.expander("Tabel detail"):
            st.dataframe(
                report["daily_trend"][["Tanggal", "Jumlah_Alert", "Jumlah_Insiden",
                                        "Rule_Kontributor_Terbesar", "%_dari_Alert_Hari_Itu"]],
                use_container_width=True
            )

    st.markdown("**Pola Jam & Hari**")
    c1, c2 = st.columns(2)
    with c1:
        if len(report["time_by_hour"]) > 0:
            plot_bar(report["time_by_hour"], "Jam", "Jumlah_Alert", title="Per Jam")
    with c2:
        if len(report["time_by_day"]) > 0:
            plot_bar(report["time_by_day"], "Hari", "Jumlah_Alert", title="Per Hari")

# ---------------------------------------------------------
# TAB: EFEKTIVITAS & SEVERITY
# ---------------------------------------------------------
if current_page == "Efektivitas":
    st.caption("✅ Menjawab: **seberapa efektif** SOC menangani ancaman - severity, hasil investigasi, dan akurasi prioritas.")

    if len(report.get("sla_metrics", [])) > 0:
        st.markdown("### SLA Metrics (State Machine: Logged → Active → Contained → Resolved)")
        st.warning(
            "⚠️ **MTTC (Mean Time To Contain) belum bisa dihitung** - tidak ada kolom timestamp "
            "'Contained' terpisah di data Ivanti saat ini (masih dicek ke tim Ivanti). MTTD pakai proxy "
            "Alert Time (Splunk) → Created On (Ivanti) - tolong dikonfirmasi apakah ini sesuai maksud."
        )

        st.markdown("**Response Speed by Severity (Radar Chart)**")
        st.caption("Semakin menjorok keluar/lancip ke arah 1 metrik, semakin LAMBAT di metrik itu - "
                   "bagus untuk lihat sekilas tier mana yang paling perlu perhatian.")
        radar_df = report["sla_metrics"][report["sla_metrics"]["Priority_Label"] != "SEMUA"]
        plot_radar(radar_df, "Priority_Label",
                   ["Avg_MTTD_menit", "Avg_MTTR_menit", "Avg_MTTC_menit", "Avg_MTTRV_menit"])

        st.dataframe(report["sla_metrics"], use_container_width=True)
        st.divider()

    with st.expander("ℹ️ Definisi Cause Code"):
        st.write(
            "Field diisi manual oleh analyst saat menutup tiket (disimpulkan dari nama field, "
            "perlu dikonfirmasi ke tim terkait): **Prevented** = kontrol keamanan berhasil mencegah "
            "ancaman. **Breach - Reported** = ancaman benar-benar menembus (ada bukti kompromi)."
        )
    show_insights(["H-Outcome", "H-Mismatch"])

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Distribusi Tiket per Severity**")
        if len(report.get("severity_breakdown", [])) > 0:
            plot_pie(report["severity_breakdown"], "Severity_Label", "Jumlah_Tiket", semantic=True)
    with c2:
        st.markdown("**Cause Code Breakdown** (= Total Tiket)")
        if len(report.get("cause_code_breakdown", [])) > 0:
            plot_pie(report["cause_code_breakdown"], "Cause_Code", "Jumlah_Tiket", semantic=True)
    st.caption(f"Cancelled: {int(report['status_summary'].iloc[0]['Jumlah'])} tiket (dimensi terpisah dari Cause Code).")

    st.markdown("**Root-cause**")
    rc1, rc2 = st.columns(2)
    with rc1:
        st.markdown("*Kenapa 'Belum Diklasifikasi'?*")
        st.dataframe(report["unclassified_by_status"], use_container_width=True)
        n_closed = report["closed_no_causecode_by_owner"]["Jumlah_Tiket_Closed_Tanpa_CauseCode"].sum() if len(report["closed_no_causecode_by_owner"]) > 0 else 0
        st.caption(f"⚠️ {int(n_closed)} tiket sudah Closed tapi Cause Code belum diisi.")
    with rc2:
        st.markdown("*Rule paling sering Under-Prioritized*")
        st.dataframe(report["mismatch_under_by_rule"], use_container_width=True)

    with st.expander("Detail lengkap: Cause Code per domain, per analyst, tiket mismatch"):
        st.markdown("**Cause Code per Security Domain**")
        st.dataframe(apply_filter(report["cause_code_by_domain"], "Security_Domain", f_domain), use_container_width=True)
        st.markdown("**Under-Prioritized per Analyst**")
        st.dataframe(apply_filter(report["mismatch_under_by_owner"], "Owner", f_analyst), use_container_width=True)
        st.markdown("**Semua tiket mismatch**")
        st.dataframe(apply_filter(report["severity_priority_mismatch"], "Owner", f_analyst), use_container_width=True)
        st.markdown("**Tiket Cancelled - Cause Code-nya apa**")
        st.dataframe(report["cancelled_crosstab"], use_container_width=True)

    if len(report.get("resolved_closed_stats", [])) > 0:
        st.markdown("**Resolved → Closed: Timeline & Potensi Tanpa Review**")
        show_insights(["H-ResolvedClosed"])
        st.dataframe(report["resolved_closed_stats"], use_container_width=True)

# ---------------------------------------------------------
# TAB: KPI ANALYST
# ---------------------------------------------------------
if current_page == "KPI Analyst":
    st.caption("👤 Menjawab: siapa yang paling banyak bekerja, seberapa cepat responsnya (People Performance).")
    st.info(
        "**Take** = Total_Incident/Task diambil. **MTTR** = Created On → Responded On (Logged→Active). "
        "**MTTRV** = Responded On → Resolved On (Active→Resolved). **MTTC** (Contain) belum bisa dihitung "
        "per analyst - sama seperti SLA Metrics di tab Efektivitas, menunggu kolom Contained dari Ivanti."
    )
    show_insights(["H-KPI"])
    kpi_full = report["soc_individual_kpi"]
    if len(kpi_full) > 0 and "Avg_MTTR_sec" in kpi_full.columns:
        team_mttr_sec = (kpi_full["Avg_MTTR_sec"] * kpi_full["Total_Incident"]).sum() / max(kpi_full["Total_Incident"].sum(), 1)
        st.metric("Rata-rata MTTR SELURUH TIM (menit)", round(team_mttr_sec / 60, 1),
                  help="Rata-rata tertimbang berdasarkan jumlah tiket tiap analyst - bukan cuma rata-rata dari rata-rata.")
    kpi_filtered = apply_filter(report["soc_individual_kpi"], "Owner", f_analyst)
    st.markdown("**Total Workload per Analyst (Insiden + Task)**")
    plot_bar(kpi_filtered, "Owner", "Total_Workload (Insiden+Task)")
    st.markdown("**Tabel lengkap seluruh analyst (People Performance)**")
    # Ambil kolom yang MEMANG ADA saja - supaya kalau buka laporan cache LAMA
    # (skema kolom beda dari versi kode terbaru), tidak crash KeyError, cuma
    # kolom itu tidak muncul (lebih baik daripada aplikasi berhenti total).
    wanted_cols = ["Owner", "Total_Incident", "Total_Task", "Total_Workload (Insiden+Task)",
                   "Avg_MTTR_sec", "Avg_MTTRV_sec", "Avg_MTTC_sec", "Breach", "Breach_Rate_%", "Within_SLA_MTTR"]
    available_cols = [c for c in wanted_cols if c in kpi_filtered.columns]
    missing_cols = [c for c in wanted_cols if c not in kpi_filtered.columns]
    if missing_cols:
        st.caption(f"⚠️ Kolom {missing_cols} tidak ada di laporan ini (kemungkinan laporan lama dari "
                   f"skema versi sebelumnya) - generate ulang laporan ini untuk data terbaru.")
    kpi_display = kpi_filtered[available_cols].rename(
        columns={"Breach": "Jumlah_Tiket_Breach", "Total_Incident": "Take_Incident", "Total_Task": "Take_Task"}
    )
    st.dataframe(kpi_display, use_container_width=True)

# ---------------------------------------------------------
# TAB: HELP (glossary A-Z dari Reading Guide)
# ---------------------------------------------------------
if current_page == "Help":
    st.caption("Daftar semua sheet/menu di laporan ini, diurutkan A-Z. Cari cepat pakai Ctrl+F.")
    rg = report["reading_guide"].sort_values("Sheet / Chart").reset_index(drop=True)
    for _, row in rg.iterrows():
        st.markdown(f"**{row['Sheet / Chart']}**")
        st.markdown(f"{row['Penjelasan']}")
        st.caption(f"Sumber & cara hitung: {row['Sumber & Cara Hitung']}")
        st.caption(f"Menjawab: {row['Menjawab Pertanyaan']}")
        st.divider()

# =========================================================
# DOWNLOAD
# =========================================================

st.divider()
st.subheader("Download")

if st.session_state.get("excel_cache") is None:
    with st.spinner("Menyiapkan file Excel..."):
        try:
            st.session_state["excel_cache"] = excel_bytes(report, period_label)
        except Exception as e:
            st.error(
                f"Gagal membuat file Excel untuk didownload: {e}\n\n"
                "File mentahnya kemungkinan tetap tersimpan di folder `output/` "
                "(cek langsung dari File Explorer sebagai jalan pintas)."
            )
            st.stop()

xlsx_bytes, filename = st.session_state["excel_cache"]

st.download_button(
    label=f"Download {filename}",
    data=xlsx_bytes,
    file_name=filename,
    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    key="download_btn",
)
st.caption(f"Kalau tombol Download tidak merespons di browser, file yang sama juga otomatis "
           f"tersimpan di folder `output/{filename}` - bisa diambil langsung dari situ.")

if st.session_state.get("pptx_cache") is None:
    with st.spinner("Menyiapkan file PPT..."):
        try:
            st.session_state["pptx_cache"] = pptx_bytes(report, period_label)
        except Exception as e:
            st.error(f"Gagal membuat file PPT: {e}")
            st.stop()

pptx_data, pptx_filename = st.session_state["pptx_cache"]
st.download_button(
    label=f"Download {pptx_filename}",
    data=pptx_data,
    file_name=pptx_filename,
    mime="application/vnd.openxmlformats-officedocument.presentationml.presentation",
    key="download_pptx_btn",
)
st.caption("PPT ini mengonsumsi data yang SAMA PERSIS dengan Excel di atas (bukan hitung ulang) - "
           "chart & angka dijamin konsisten. Kalau tombol tidak merespons, cek folder `output/`.")
