"""Komponen visual HTML murni (tanpa Plotly, tanpa CSS eksternal) untuk dashboard.
Semua gaya inline + warna netral (rgba/inherit) agar terbaca di tema terang MAUPUN gelap Streamlit.
Fungsi murni -> mengembalikan string HTML, bisa diuji tanpa Streamlit."""
from html import escape

ACCENT = "#3987e5"        # satu hue untuk magnitudo (bar Dest/Country/Source IP)
OTHERS = "#8b929a"        # 'Others' / kategori sisa = abu-abu (konteks, bukan fokus)
TRACK = "rgba(128,128,128,.18)"
BORDER = "rgba(128,128,128,.28)"
MUTED = "opacity:.68"
# Severity = skala ordinal: satu hue merah, gelap -> terang menurun; Low = abu (volume terbesar tapi paling tak mendesak).
SEV_COLORS = {"Critical": "#a61b1b", "High": "#e34948", "Medium": "#f0a3a2", "Low": "#8b929a", "Info": "#b8bec6", "Unknown": "#b8bec6"}
RISK_COLORS = {"Critical": "#a61b1b", "High": "#e34948", "Medium": "#e0a100", "Guarded": "#3987e5", "Low": "#1f9d6b"}
FONT = "font-family:inherit;"


def _num(x, loc="id"):
    s = f"{int(round(float(x))):,}"
    return s.replace(",", ".") if loc == "id" else s


def _pct(x, d=1, loc="id"):
    s = f"{float(x):.{d}f}"
    return (s.replace(".", ",") if loc == "id" else s) + "%"


def css_reset():
    """Satu-satunya blok <style>: hanya merapikan jarak. Bila Streamlit menghapusnya, tampilan tetap utuh (semua inline)."""
    return ("<style>div[data-testid='stMarkdownContainer'] table{margin:0}"
            "div[data-testid='stMarkdownContainer'] td,div[data-testid='stMarkdownContainer'] th{border:none!important}</style>")


def badge(text, color, fg="#fff"):
    return (f'<span style="display:inline-block;padding:1px 8px;border-radius:999px;background:{color};color:{fg};'
            f'font-size:.72rem;font-weight:600;line-height:1.5;letter-spacing:.02em">{escape(str(text))}</span>')


def kpi_cards(cards):
    """cards: [(label, value, sub, accent_or_None)] -> baris stat tile."""
    out = []
    for label, value, sub, accent in cards:
        bar = f"border-left:4px solid {accent};" if accent else ""
        fs = "1.75rem" if len(str(value)) <= 9 else "1.2rem"   # nilai teks panjang (mis. nama negara) tidak boleh membungkus
        out.append(
            f'<div style="border:1px solid {BORDER};{bar}border-radius:10px;padding:12px 14px;min-width:0">'
            f'<div style="font-size:.76rem;{MUTED};text-transform:uppercase;letter-spacing:.04em">{escape(label)}</div>'
            f'<div style="font-size:{fs};font-weight:700;line-height:1.35;font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="{escape(str(value))}">{escape(str(value))}</div>'
            + (f'<div style="font-size:.78rem;{MUTED};margin-top:2px">{escape(str(sub))}</div>' if sub else "") + "</div>")
    return ('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:4px 0 16px 0">'
            + "".join(out) + "</div>")


def section_title(text, sub=None):
    return (f'<div style="margin:18px 0 8px 0"><div style="font-size:1.02rem;font-weight:700">{text}</div>'
            + (f'<div style="font-size:.78rem;{MUTED}">{sub}</div>' if sub else "") + "</div>")


def hbar_list(items, color=ACCENT, loc="id", empty="Tidak ada data", max_label_chars=None):
    """items: [(label, count, pct)] (urutan sudah final, 'Others' di akhir). Label di atas bar -> nama panjang
    (mis. signature IPS) tidak terpotong. Panjang bar relatif terhadap nilai terbesar; angka & % selalu tertulis."""
    items = [i for i in items if i[1] is not None]
    if not items:
        return f'<div style="font-size:.85rem;{MUTED};padding:8px 0">{escape(empty)}</div>'
    peak = max(float(c) for _, c, _ in items) or 1.0
    rows = []
    for label, count, pct in items:
        is_other = str(label) == "Others"
        col = OTHERS if is_other else color
        w = max(float(count) / peak * 100.0, 1.5)
        tip = escape(f"{label}: {_num(count, loc)} ({_pct(pct, 2, loc)})")
        rows.append(
            f'<div title="{tip}" style="margin:0 0 11px 0">'
            f'<div style="display:flex;justify-content:space-between;align-items:baseline;gap:12px;font-size:.84rem;line-height:1.3">'
            f'<span style="min-width:0;overflow-wrap:anywhere;{"opacity:.75;font-style:italic" if is_other else ""}">{escape(str(label))}</span>'
            f'<span style="white-space:nowrap;font-variant-numeric:tabular-nums"><b>{_num(count, loc)}</b>'
            f'<span style="{MUTED};margin-left:6px">{_pct(pct, 1, loc)}</span></span></div>'
            f'<div style="height:7px;background:{TRACK};border-radius:4px;margin-top:4px">'
            f'<div style="width:{w:.2f}%;height:100%;background:{col};border-radius:4px"></div></div></div>')
    return "".join(rows)


def donut(items, center_value, center_label, size=190, loc="id"):
    """items: [(label, count, pct, color, description)] -> donut + legenda dengan nilai (identitas tidak bergantung warna)."""
    items = [i for i in items if i[1] > 0]
    total = sum(i[1] for i in items) or 1.0
    stops, acc = [], 0.0
    for _, c, _, color, _ in items:
        nxt = acc + c / total * 100.0
        stops.append(f"{color} {acc:.3f}% {nxt:.3f}%")
        acc = nxt
    ring = (f"background:conic-gradient({', '.join(stops)});-webkit-mask:radial-gradient(circle,transparent 56%,#000 57%);"
            f"mask:radial-gradient(circle,transparent 56%,#000 57%)")
    legend = []
    for label, c, pct, color, desc in items:
        legend.append(
            f'<div title="{escape(desc or label)}" style="display:flex;gap:10px;align-items:flex-start;margin:0 0 9px 0">'
            f'<span style="flex:none;width:12px;height:12px;border-radius:3px;background:{color};margin-top:3px"></span>'
            f'<div style="min-width:0;flex:1"><div style="display:flex;justify-content:space-between;gap:10px;font-size:.86rem">'
            f'<b>{escape(label)}</b><span style="font-variant-numeric:tabular-nums"><b>{_num(c, loc)}</b>'
            f'<span style="{MUTED};margin-left:6px">{_pct(pct, 1, loc)}</span></span></div>'
            + (f'<div style="font-size:.74rem;{MUTED};line-height:1.3">{escape(desc)}</div>' if desc else "") + "</div></div>")
    return (f'<div style="position:relative;width:{size}px;height:{size}px;margin:6px auto 16px auto">'
            f'<div style="width:100%;height:100%;border-radius:50%;{ring}"></div>'
            f'<div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">'
            f'<div style="font-size:1.9rem;font-weight:700;line-height:1;font-variant-numeric:tabular-nums">{escape(str(center_value))}</div>'
            f'<div style="font-size:.74rem;{MUTED};margin-top:4px">{escape(center_label)}</div></div></div>'
            + "".join(legend))


def stacked_bar(items, loc="id", height=14):
    """Satu bar 100% bersegmen (ringkasan komposisi). items: [(label, count, color)]. Jarak 2px antar segmen."""
    items = [i for i in items if i[1] > 0]
    total = sum(i[1] for i in items) or 1.0
    segs = "".join(f'<div title="{escape(l)}: {_num(c, loc)} ({_pct(c / total * 100, 1, loc)})" '
                   f'style="flex:{c / total * 100:.3f} 1 0;background:{col};min-width:3px"></div>' for l, c, col in items)
    return f'<div style="display:flex;gap:2px;height:{height}px;border-radius:4px;overflow:hidden">{segs}</div>'


def compare_bars(rows, label_a, label_b, loc="id", empty="Tidak ada data"):
    """rows: [(label, a, b)]. Dua bar per baris: A = abu-abu (pembanding), B = aksen (periode yang dilihat). Angka & selisih tertulis."""
    if not rows:
        return f'<div style="font-size:.85rem;{MUTED};padding:8px 0">{escape(empty)}</div>'
    peak = max(max(float(a), float(b)) for _, a, b in rows) or 1.0
    head = (f'<div style="display:flex;gap:16px;font-size:.76rem;{MUTED};margin:0 0 8px 0">'
            f'<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{OTHERS};margin-right:5px"></span>A · {escape(label_a)}</span>'
            f'<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{ACCENT};margin-right:5px"></span>B · {escape(label_b)}</span></div>')
    out = []
    for label, a, b in rows:
        a, b = float(a), float(b)
        d = b - a
        pct = f" ({'+' if d > 0 else ''}{_pct(d / a * 100, 1, loc)})" if a else (" (baru)" if b else "")
        arrow = "▲" if d > 0 else ("▼" if d < 0 else "▬")
        out.append(
            f'<div title="{escape(str(label))}: A {_num(a, loc)} → B {_num(b, loc)}" style="margin:0 0 12px 0">'
            f'<div style="display:flex;justify-content:space-between;align-items:baseline;gap:12px;font-size:.84rem;line-height:1.3">'
            f'<span style="min-width:0;overflow-wrap:anywhere">{escape(str(label))}</span>'
            f'<span style="white-space:nowrap;font-variant-numeric:tabular-nums"><span style="{MUTED}">{_num(a, loc)} →</span> <b>{_num(b, loc)}</b>'
            f'<span style="{MUTED};margin-left:6px">{arrow} {("+" if d > 0 else "")}{_num(d, loc)}{pct}</span></span></div>'
            f'<div style="height:6px;background:{TRACK};border-radius:3px;margin-top:4px"><div style="width:{max(a / peak * 100, 0.8 if a else 0):.2f}%;height:100%;background:{OTHERS};border-radius:3px"></div></div>'
            f'<div style="height:6px;background:{TRACK};border-radius:3px;margin-top:2px"><div style="width:{max(b / peak * 100, 0.8 if b else 0):.2f}%;height:100%;background:{ACCENT};border-radius:3px"></div></div></div>')
    return head + "".join(out)
