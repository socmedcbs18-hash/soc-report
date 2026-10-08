"""
Chart builder untuk Dash - fungsi-fungsi ini RETURN objek plotly.graph_objects.Figure
(bukan panggil st.plotly_chart seperti versi Streamlit), supaya bisa dipasang
langsung ke dcc.Graph(figure=...) di layout Dash.

Logic warna & style DIPORT dari app.py Streamlit (plot_bar/plot_pie/plot_radar)
tapi ditulis ulang untuk API Dash - bukan copy-paste, karena wrapper
render-nya beda total (st.plotly_chart vs dcc.Graph).
"""

import plotly.express as px
import plotly.graph_objects as go

from dash_components.colors import PALETTE, semantic_color_map, category_color_map


def fig_bar(df, x_col, y_col, title=None, semantic=False, category=False):
    if df is None or len(df) == 0:
        return go.Figure().add_annotation(text="Tidak ada data", showarrow=False)
    color_map = None
    if semantic:
        color_map = semantic_color_map(df[x_col])
    elif category:
        color_map = category_color_map(df[x_col])
    fig = px.bar(df, x=x_col, y=y_col, title=title,
                 color=x_col if (semantic or category) else None,
                 color_discrete_map=color_map, color_discrete_sequence=PALETTE, text_auto=True)
    fig.update_layout(margin=dict(l=10, r=10, t=40 if title else 10, b=10),
                       plot_bgcolor="white", paper_bgcolor="white", font=dict(size=14),
                       showlegend=(semantic or category))
    fig.update_xaxes(type="category")
    return fig


def fig_bar_multi(df, x_col, y_cols, title=None):
    if df is None or len(df) == 0:
        return go.Figure().add_annotation(text="Tidak ada data", showarrow=False)
    melted = df.melt(id_vars=[x_col], value_vars=y_cols, var_name="Metric", value_name="Value")
    melted[x_col] = melted[x_col].astype(str)
    fig = px.bar(melted, x=x_col, y="Value", color="Metric", barmode="group",
                 title=title, color_discrete_sequence=PALETTE)
    fig.update_layout(margin=dict(l=10, r=10, t=40 if title else 10, b=10),
                       plot_bgcolor="white", paper_bgcolor="white", font=dict(size=14))
    fig.update_xaxes(type="category")
    return fig


def fig_pie(df, names_col, values_col, title=None, semantic=False):
    if df is None or len(df) == 0:
        return go.Figure().add_annotation(text="Tidak ada data", showarrow=False)
    color_map = semantic_color_map(df[names_col]) if semantic else None
    fig = px.pie(df, names=names_col, values=values_col, title=title,
                 color=names_col if semantic else None,
                 color_discrete_map=color_map, color_discrete_sequence=PALETTE, hole=0.35)
    fig.update_traces(textposition="inside", textinfo="percent+label")
    fig.update_layout(margin=dict(l=10, r=10, t=40 if title else 10, b=10), font=dict(size=14))
    return fig


def fig_radar(df, category_col, value_cols, title=None, normalize=True):
    """Diport dari plot_radar() Streamlit - termasuk normalisasi 0-100 per
    sumbu (fix bug 'radar cuma nunjuk 1 arah' yang pernah ditemukan)."""
    if df is None or len(df) == 0:
        return go.Figure().add_annotation(text="Tidak ada data", showarrow=False)
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
            line=dict(color=PALETTE[i % len(PALETTE)], width=2), opacity=0.75,
        ))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100] if normalize else None)),
        showlegend=True, margin=dict(l=40, r=40, t=50 if title else 20, b=20),
        title=title if title else None, font=dict(size=14),
    )
    return fig
