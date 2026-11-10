"""Tema tampilan dashboard: kartu KPI, tab, tabel, dan caption ringkas.

- inject_css(): CSS global (aman, hanya styling).
- install_compact_captions(): caption panjang ditampilkan 1 kalimat pendek + ikon (i); teks lengkap muncul
  saat kursor diarahkan (tooltip `help`). Tidak ada teks yang dihapus. Bila versi Streamlit tidak mendukung
  `help` pada st.caption, caption ditampilkan seperti semula.
"""
import re

CSS = """
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1500px;}
h1 {font-weight: 800; letter-spacing: -0.5px;}
h2, h3 {font-weight: 700; letter-spacing: -0.3px; margin-top: 1.2rem;}
div[data-testid="stMetric"] {
  background: linear-gradient(135deg, #ffffff 0%, #f3f7fc 100%);
  border: 1px solid #dbe6f3; border-left: 5px solid #1F4E79; border-radius: 12px;
  padding: 14px 16px; box-shadow: 0 1px 4px rgba(31,78,121,.08);
}
div[data-testid="stMetricLabel"] p {font-size: .78rem; text-transform: uppercase; letter-spacing: .6px; color: #5b6b7d;}
div[data-testid="stMetricValue"] {font-size: 1.9rem; font-weight: 800; color: #1F4E79;}
button[data-baseweb="tab"] {font-weight: 600; padding: 8px 14px;}
button[data-baseweb="tab"][aria-selected="true"] {color: #1F4E79; border-bottom: 3px solid #1F4E79;}
div[data-testid="stExpander"] {border: 1px solid #dbe6f3; border-radius: 10px;}
div[data-testid="stDataFrame"] {border: 1px solid #e3eaf3; border-radius: 10px; overflow: hidden;}
div[data-testid="stCaptionContainer"] {color: #6b7a8c; font-size: .82rem; line-height: 1.3;}
div[data-testid="stAlert"] {border-radius: 10px; padding: .6rem .9rem;}
hr {margin: 1.2rem 0;}
@media (prefers-color-scheme: dark) {
  div[data-testid="stMetric"] {background: #172233; border-color: #2a3a52; border-left-color: #5aa0e6;}
  div[data-testid="stMetricValue"] {color: #8cc4ff;}
  div[data-testid="stMetricLabel"] p {color: #9fb0c4;}
}
</style>
"""

_PATCHED = False


def inject_css(st):
    st.markdown(CSS, unsafe_allow_html=True)


def short_text(text, limit=110):
    """Ambil kalimat pertama; bila terlalu panjang, potong di batas kata."""
    t = re.sub(r"\s+", " ", str(text)).strip()
    if len(t) <= limit:
        return t
    m = re.match(r"(.{20,%d}?[.!?])(\s|$)" % limit, t)
    if m:
        return m.group(1)
    cut = t[:limit].rsplit(" ", 1)[0]
    return cut + "…"


def install_compact_captions(st, limit=110):
    global _PATCHED
    if _PATCHED:
        return
    orig = st.caption

    def caption(body, *a, **k):
        try:
            if isinstance(body, str) and len(body) > limit and "help" not in k and not a:
                s = short_text(body, limit)
                return orig(s + "  ⓘ", help=body, **k)
        except TypeError:
            pass
        return orig(body, *a, **k)

    st.caption = caption
    _PATCHED = True
