"""Komponen HTML murni (inline style, warna netral untuk tema terang/gelap). Fungsi murni -> string; bisa diuji tanpa Streamlit."""
from html import escape

from soc_incident import fmt

ACCENT = "#3987e5"     # era baru / fokus
OLD = "#8b929a"        # era lama / pembanding
WARN = "#e0a100"
BAD = "#e34948"
TRACK = "rgba(128,128,128,.18)"
BORDER = "rgba(128,128,128,.28)"
MUTED = "opacity:.68"
LEVEL = {"watch": ("Perlu diperhatikan", WARN), "limit": ("Keterbatasan data", OLD), "info": ("Informasi", ACCENT)}
PRIO_COLORS = {1: "#a61b1b", 2: "#e34948", 3: "#8b929a"}


def kpi_cards(cards):
    """cards: [(label, value, sub, accent)]"""
    out = []
    for label, value, sub, accent in cards:
        bar = f"border-left:4px solid {accent};" if accent else ""
        fs = "1.7rem" if len(str(value)) <= 9 else "1.2rem"
        out.append(f'<div style="border:1px solid {BORDER};{bar}border-radius:10px;padding:12px 14px;min-width:0">'
                   f'<div style="font-size:.74rem;{MUTED};text-transform:uppercase;letter-spacing:.04em">{escape(label)}</div>'
                   f'<div style="font-size:{fs};font-weight:700;line-height:1.35;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="{escape(str(value))}">{escape(str(value))}</div>'
                   + (f'<div style="font-size:.76rem;{MUTED};margin-top:2px;line-height:1.35">{escape(str(sub))}</div>' if sub else "") + "</div>")
    return ('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:4px 0 16px 0">' + "".join(out) + "</div>")


def section_title(text, sub=None):
    return (f'<div style="margin:18px 0 8px 0"><div style="font-size:1.02rem;font-weight:700">{escape(text)}</div>'
            + (f'<div style="font-size:.78rem;{MUTED}">{escape(sub)}</div>' if sub else "") + "</div>")


def legend(items):
    return ('<div style="display:flex;gap:16px;flex-wrap:wrap;font-size:.76rem;margin:0 0 6px 0">' + "".join(
        f'<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{c};margin-right:5px"></span>{escape(l)}</span>' for l, c in items) + "</div>")


def column_chart(cols, height=130, label_every=1):
    """cols: [(label, [(value, color)] bawah->atas, tooltip, marker_or_None)]. Bar bertumpuk; skala bersama; angka total di tooltip."""
    peak = max((sum(v for v, _ in segs) for _, segs, _, _ in cols), default=0) or 1
    out = []
    for i, (label, segs, tip, marker) in enumerate(cols):
        tot = sum(v for v, _ in segs)
        h = tot / peak * height
        parts = "".join(f'<div style="height:{v / tot * 100:.2f}%;background:{c}"></div>' for v, c in reversed(segs) if v > 0) if tot else ""
        bar = (f'<div style="height:{max(h, 2 if tot else 0):.1f}px;display:flex;flex-direction:column;border-radius:3px 3px 0 0;overflow:hidden">{parts}</div>')
        lab = escape(str(label)) if i % label_every == 0 else "&nbsp;"
        mk = f'<div style="color:{ACCENT};font-size:.7rem;line-height:1">{marker}</div>' if marker else '<div style="height:.7rem"></div>'
        out.append(f'<div title="{escape(tip)}" style="flex:1 1 0;min-width:0;display:flex;flex-direction:column;justify-content:flex-end;align-items:stretch;height:{height + 38}px">'
                   f'<div style="font-size:.6rem;text-align:center;{MUTED};white-space:nowrap">{fmt.num(tot) if tot else ""}</div>{bar}'
                   f'<div style="font-size:.62rem;text-align:center;{MUTED};margin-top:3px;white-space:nowrap;overflow:hidden">{lab}</div>{mk}</div>')
    return f'<div style="display:flex;gap:2px;align-items:flex-end;margin:4px 0 8px 0;overflow:hidden">{"".join(out)}</div>'


def daily_timeline(daily, eras, cutover):
    """Tiket per hari, bertumpuk per era (lama = abu-abu, baru = biru); tanda ▲ pada hari cutover."""
    colors = {"old": OLD, "new": ACCENT, "all": ACCENT}
    cols = []
    for day, r in daily.iterrows():
        segs = [(int(r[e]), colors[e]) for e in eras]
        mark = "▲" if cutover is not None and day.normalize() == cutover.normalize() else None
        tip = f"{day:%d %b %Y}: {fmt.num(r['Total'])} tiket · P1 {fmt.num(r['P1'])} · P2 {fmt.num(r['P2'])} · P3 {fmt.num(r['P3'])} · melewati batas respons {fmt.num(r['Breach'])}"
        cols.append((f"{day:%d}", segs, tip, mark))
    return column_chart(cols, 130)


def hourly_chart(hourly, eras):
    colors = {"old": OLD, "new": ACCENT, "all": ACCENT}
    cols = [(f"{h:02d}", [(int(r[e]), colors[e]) for e in eras], f"Jam {h:02d}:00 – {fmt.num(r['Total'])} tiket", None) for h, r in hourly.iterrows()]
    return column_chart(cols, 90, label_every=2)


def hbar_list(items, color=ACCENT, empty="Tidak ada data"):
    """items: [(label, value, share_pct)]"""
    if not items:
        return f'<div style="font-size:.85rem;{MUTED};padding:8px 0">{escape(empty)}</div>'
    peak = max(float(v) for _, v, _ in items) or 1
    rows = []
    for label, v, share in items:
        rows.append(f'<div style="margin:0 0 10px 0"><div style="display:flex;justify-content:space-between;gap:12px;font-size:.84rem">'
                    f'<span style="min-width:0;overflow-wrap:anywhere">{escape(str(label))}</span>'
                    f'<span style="white-space:nowrap"><b>{fmt.num(v)}</b><span style="{MUTED};margin-left:6px">{fmt.pct(share)}</span></span></div>'
                    f'<div style="height:7px;background:{TRACK};border-radius:4px;margin-top:4px"><div style="width:{max(float(v) / peak * 100, 1.5):.2f}%;height:100%;background:{color};border-radius:4px"></div></div></div>')
    return "".join(rows)


def stacked_share(items):
    """items: [(label, value, color)] -> satu bar 100% + angka di legenda."""
    items = [i for i in items if i[1] > 0]
    tot = sum(i[1] for i in items) or 1
    segs = "".join(f'<div title="{escape(l)}: {fmt.num(v)} ({fmt.pct(v / tot * 100)})" style="flex:{v / tot * 100:.3f} 1 0;background:{c};min-width:3px"></div>' for l, v, c in items)
    lg = "".join(f'<span style="margin-right:14px"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{c};margin-right:4px"></span>{escape(l)} <b>{fmt.num(v)}</b> <span style="{MUTED}">{fmt.pct(v / tot * 100)}</span></span>' for l, v, c in items)
    return f'<div style="display:flex;gap:2px;height:14px;border-radius:4px;overflow:hidden">{segs}</div><div style="font-size:.78rem;margin-top:6px">{lg}</div>'


def era_table(headers, rows):
    """rows: [(label, [str,...])] -> tabel HTML ringkas."""
    th = "".join(f'<th style="text-align:right;padding:6px 8px;font-size:.78rem;{MUTED};font-weight:600">{escape(h)}</th>' for h in headers)
    body = "".join(f'<tr style="border-top:1px solid {BORDER}"><td style="padding:6px 8px;font-size:.84rem">{escape(l)}</td>'
                   + "".join(f'<td style="padding:6px 8px;text-align:right;font-size:.84rem;font-variant-numeric:tabular-nums">{escape(v)}</td>' for v in vals) + "</tr>" for l, vals in rows)
    return (f'<table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:6px 8px;font-size:.78rem;{MUTED};font-weight:600">Metrik</th>{th}</tr></thead>'
            f'<tbody>{body}</tbody></table>')


def insight_blocks(insights):
    out = []
    for lvl in ("watch", "limit", "info"):
        items = [i for i in insights if i["level"] == lvl]
        if not items:
            continue
        name, color = LEVEL[lvl]
        lis = "".join(f'<li style="margin:0 0 7px 0;line-height:1.45"><b>{escape(i["topic"])}.</b> {escape(i["text"])}</li>' for i in items)
        out.append(f'<div style="border-left:4px solid {color};padding:2px 0 2px 12px;margin:0 0 14px 0"><div style="font-size:.78rem;font-weight:700;color:{color};text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px">{name}</div>'
                   f'<ul style="margin:0;padding-left:18px;font-size:.88rem">{lis}</ul></div>')
    return "".join(out)


def state_flow(states):
    """states: [(state, metric_label, status_text, ok)] -> alur horizontal; ok True=hijau, False=abu, None=kuning (parsial)."""
    col = {True: "#1f9d6b", False: OLD, None: WARN}
    cells = []
    for i, (st_, metric, text, ok) in enumerate(states):
        cells.append(f'<div style="flex:1 1 0;min-width:120px;border:1px solid {BORDER};border-top:4px solid {col[ok]};border-radius:8px;padding:8px 10px">'
                     f'<div style="font-weight:700;font-size:.86rem">{escape(st_)}</div>'
                     f'<div style="font-size:.74rem;{MUTED};margin-top:2px">{escape(metric)}</div>'
                     f'<div style="font-size:.78rem;margin-top:4px;color:{col[ok]};font-weight:600">{escape(text)}</div></div>')
        if i < len(states) - 1:
            cells.append(f'<div style="align-self:center;{MUTED}">→</div>')
    return f'<div style="display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 14px 0">{"".join(cells)}</div>'


def compare_rows(rows, label_a, label_b):
    """rows: [(metrik, str_a, str_b, str_delta, arah)] arah: up/down/flat/None"""
    head = [label_a, label_b, "Δ"]
    body = []
    for m, a, b, d, arrow in rows:
        sym = {"up": "▲", "down": "▼", "flat": "▬"}.get(arrow, "")
        body.append((m, [a, b, f"{sym} {d}".strip()]))
    return era_table(head, body)
