"""
SOC Report - Dash Pilot (Executive Summary)
=========================================================
Entry point BARU untuk migrasi Streamlit -> Plotly Dash. TIDAK MENYENTUH
app.py (Streamlit) sama sekali - dijalankan terpisah:

    python dash_app.py

Scope pilot ini: HALAMAN EXECUTIVE SUMMARY SAJA (paling sering dipakai,
manfaat terbesar - sesuai kesepakatan). 9 halaman Details lain BELUM
di-port - masih perlu dibuka lewat app.py Streamlit untuk sementara.

Business logic (core/loader.py, core/processor.py, dll) 100% REUSE dari
SOC Streamlit - TIDAK ditulis ulang, cuma layer tampilan yang beda.
"""

import base64
import io

import dash
from dash import dcc, html, Input, Output, State, callback_context
import pandas as pd

from utils.helpers import read_any_table, normalize_master_rules_columns, normalize_incident_columns
from core.normalizer import RuleNormalizer
from core.validator import Validator
from core.processor import SOCProcessor
from dash_components.charts import fig_bar, fig_bar_multi, fig_pie, fig_radar

app = dash.Dash(__name__, title="SOC Report (Dash Pilot)")

# Cache report di server (sederhana - cukup untuk internal tool 1-beberapa
# user, BUKAN arsitektur multi-tenant production-grade). Kalau nanti dipakai
# banyak user bersamaan, perlu di-upgrade ke session-keyed cache.
_REPORT_CACHE = {"report": None}


# =========================================================
# LAYOUT
# =========================================================

def _upload_box(id_, label):
    return html.Div([
        html.Label(label, style={"fontSize": "13px", "color": "#5A6B85", "marginBottom": "4px", "display": "block"}),
        dcc.Upload(
            id=id_,
            children=html.Div(["Drag & Drop atau ", html.A("pilih file")]),
            style={
                "width": "100%", "height": "50px", "lineHeight": "50px", "borderWidth": "1px",
                "borderStyle": "dashed", "borderRadius": "8px", "textAlign": "center",
                "fontSize": "12px", "marginBottom": "12px", "borderColor": "#E3E9F2",
            },
            multiple=False,
        ),
        html.Div(id=f"{id_}-filename", style={"fontSize": "11px", "color": "#0F9D58", "marginBottom": "8px"}),
    ])


app.layout = html.Div([
    html.Div([  # Sidebar
        html.H3("SOC Report", style={"color": "#1F4E78"}),
        html.P("Dash Pilot - Executive Summary", style={"fontSize": "12px", "color": "#5A6B85"}),
        html.Hr(),
        dcc.Input(id="period-input", type="text", placeholder="Label Periode (mis. 2026-08)",
                   style={"width": "100%", "marginBottom": "12px", "padding": "6px"}),
        _upload_box("upload-master", "Master Rules Splunk (.xlsx/.csv)"),
        dcc.Checklist(id="assume-enabled", options=[{"label": " File ini semua rule sudah Enabled", "value": "yes"}],
                      value=[], style={"fontSize": "12px", "marginBottom": "12px"}),
        _upload_box("upload-alert", "Alert Splunk (.xlsx/.csv)"),
        _upload_box("upload-incident", "Insiden Ivanti (.xlsx/.csv)"),
        html.Button("Generate Report", id="btn-generate", n_clicks=0, style={
            "width": "100%", "background": "#1F4E78", "color": "white", "border": "none",
            "padding": "10px", "borderRadius": "6px", "cursor": "pointer", "fontWeight": "600",
        }),
        html.Div(id="generate-status", style={"marginTop": "12px", "fontSize": "13px"}),
    ], style={
        "width": "280px", "padding": "20px", "background": "#F7F9FC", "height": "100vh",
        "position": "fixed", "overflowY": "auto", "borderRight": "1px solid #E3E9F2",
    }),

    html.Div(id="main-content", style={"marginLeft": "300px", "padding": "24px"}, children=[
        html.Div("⬅️ Upload data di sidebar, lalu klik Generate Report.", style={"color": "#5A6B85"})
    ]),
])


# =========================================================
# HELPER: decode file upload Dash (base64) -> file-like object
# =========================================================

def _decode_upload(contents, filename):
    if contents is None:
        return None
    _, content_string = contents.split(",")
    decoded = base64.b64decode(content_string)
    buf = io.BytesIO(decoded)
    buf.name = filename  # read_any_table butuh atribut .name buat deteksi ekstensi
    return buf


@app.callback(
    Output("upload-master-filename", "children"),
    Input("upload-master", "filename"),
)
def _show_master_filename(filename):
    return f"✓ {filename}" if filename else ""


@app.callback(
    Output("upload-alert-filename", "children"),
    Input("upload-alert", "filename"),
)
def _show_alert_filename(filename):
    return f"✓ {filename}" if filename else ""


@app.callback(
    Output("upload-incident-filename", "children"),
    Input("upload-incident", "filename"),
)
def _show_incident_filename(filename):
    return f"✓ {filename}" if filename else ""


# =========================================================
# CALLBACK UTAMA: Generate Report
# =========================================================

@app.callback(
    Output("main-content", "children"),
    Output("generate-status", "children"),
    Input("btn-generate", "n_clicks"),
    State("period-input", "value"),
    State("upload-master", "contents"), State("upload-master", "filename"),
    State("upload-alert", "contents"), State("upload-alert", "filename"),
    State("upload-incident", "contents"), State("upload-incident", "filename"),
    State("assume-enabled", "value"),
    prevent_initial_call=True,
)
def generate_report(n_clicks, period_label, master_c, master_f, alert_c, alert_f,
                     incident_c, incident_f, assume_enabled_val):
    if not period_label or not period_label.strip():
        return dash.no_update, html.Div("❌ Isi Label Periode dulu.", style={"color": "#DB4437"})
    if alert_c is None or incident_c is None:
        return dash.no_update, html.Div("❌ Alert Splunk dan Insiden Ivanti wajib diupload.", style={"color": "#DB4437"})

    try:
        master_buf = _decode_upload(master_c, master_f)
        alert_buf = _decode_upload(alert_c, alert_f)
        incident_buf = _decode_upload(incident_c, incident_f)

        master = read_any_table(master_buf, filename_hint=master_f) if master_buf else None
        if master is None:
            return dash.no_update, html.Div("❌ Master Rules wajib diupload (pilot ini belum ada fallback file default).", style={"color": "#DB4437"})
        master = normalize_master_rules_columns(master, assume_all_enabled=("yes" in (assume_enabled_val or [])))

        alert = read_any_table(alert_buf, filename_hint=alert_f)
        incident = read_any_table(incident_buf, filename_hint=incident_f)
        incident = normalize_incident_columns(incident)
        domain_mapping = pd.DataFrame(columns=["Priority", "Keyword", "Security_Domain", "Security_Sub_Domain"])

        data = {
            "master_rule": master, "domain_mapping": domain_mapping, "alert": alert, "incident": incident,
            "nonsplunk": pd.DataFrame(), "task": pd.DataFrame(), "cti": pd.DataFrame(),
            "week": period_label.strip(),
        }
        data = RuleNormalizer(data).run()
        data = Validator(data).run()
        report = SOCProcessor(data).run()

        _REPORT_CACHE["report"] = report
        content = _build_executive_summary(report)
        status = html.Div(f"✅ Laporan '{period_label.strip()}' berhasil dibuat.", style={"color": "#0F9D58"})
        return content, status
    except KeyError as e:
        return dash.no_update, html.Div(f"❌ Format data tidak sesuai: {e}", style={"color": "#DB4437"})
    except Exception as e:
        return dash.no_update, html.Div(f"❌ Gagal memproses: {e}", style={"color": "#DB4437"})


# =========================================================
# RENDER: Executive Summary content (dari report dict)
# =========================================================

def _kpi_card(label, value):
    return html.Div([
        html.Div(label, style={"fontSize": "13px", "color": "#5A6B85"}),
        html.Div(str(value), style={"fontSize": "26px", "fontWeight": "700", "color": "#1F4E78"}),
    ], style={
        "background": "#F7F9FC", "borderLeft": "4px solid #1F4E78", "borderRadius": "8px",
        "padding": "14px 16px", "flex": "1", "minWidth": "160px",
    })


def _build_executive_summary(report):
    sla_df = report.get("sla_metrics")
    overall_sla = sla_df[sla_df["Priority_Label"] == "SEMUA"].iloc[0] if sla_df is not None and len(sla_df) > 0 else None

    sections = [html.H2("📋 Executive Summary", style={"color": "#1F4E78"})]

    # --- 1. Ticket Performance KPI + Radar + Meet/Breach ---
    sections.append(html.H4("1️⃣ Cybersecurity Incident Ticket Performance"))
    if overall_sla is not None:
        pct_breach = overall_sla.get("%_Breach", "-")
        sections.append(html.Div([
            _kpi_card("Total Tiket", int(overall_sla.get("Jumlah_Tiket", 0))),
            _kpi_card("% Breach", f"{pct_breach}%" if pct_breach != "-" else "-"),
        ], style={"display": "flex", "gap": "12px", "marginBottom": "16px"}))

        radar_df = sla_df[sla_df["Priority_Label"] != "SEMUA"]
        radar_cols = [c for c in ["Avg_MTTD_menit", "Avg_MTTR_menit", "Avg_MTTC_menit", "Avg_MTTRV_menit"] if c in radar_df.columns]
        meet_breach_df = pd.DataFrame({
            "Status": ["Meet", "Breach"],
            "Jumlah": [overall_sla.get("Jumlah_Tiket", 0) - overall_sla.get("Jumlah_Breach", 0), overall_sla.get("Jumlah_Breach", 0)],
        }) if "Jumlah_Breach" in overall_sla.index else None

        row = [dcc.Graph(figure=fig_radar(radar_df, "Priority_Label", radar_cols, title="SLA by Severity"))]
        if meet_breach_df is not None:
            row.append(dcc.Graph(figure=fig_pie(meet_breach_df, "Status", "Jumlah", title="Meet vs Breach")))
        sections.append(html.Div(row, style={"display": "grid", "gridTemplateColumns": "3fr 2fr", "gap": "16px"}))
    else:
        sections.append(html.Div("Belum ada data tiket."))

    # --- 2. Attack Pattern ---
    sections.append(html.H4("2️⃣ Cybersecurity Attack Patterns", style={"marginTop": "24px"}))
    sub_int_ext = report.get("subject_internal_external")
    if sub_int_ext is not None and len(sub_int_ext) > 0:
        sections.append(dcc.Graph(figure=fig_pie(sub_int_ext, "_Subject_Origin", "Jumlah", title="Subject (Internal vs External)")))
    else:
        sections.append(html.Div("⚠️ Belum ada data Subject Internal/External."))

    # --- 3. Domain Distribution ---
    sections.append(html.H4("3️⃣ Security Domain Distribution", style={"marginTop": "24px"}))
    domain_df = report.get("domain")
    if domain_df is not None and len(domain_df) > 0:
        sections.append(dcc.Graph(figure=fig_bar(domain_df, "Security_Domain", "Incident", category=True)))

    # --- 4. Key Insights ---
    sections.append(html.H4("📝 Key Insights", style={"marginTop": "24px"}))
    hyp = report.get("hypothesis_insight")
    if hyp is not None and len(hyp) > 0:
        insight_items = []
        for _, row in hyp.head(5).iterrows():
            insight_items.append(html.Li([
                html.B(row["Hipotesis"].split(" - ", 1)[-1] + ": "), row["Temuan"]
            ], style={"marginBottom": "6px"}))
        sections.append(html.Ul(insight_items))

    return sections


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)
