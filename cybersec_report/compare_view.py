"""Tampilan perbandingan dua snapshot IPS (mis. September vs Oktober, hostname sama atau berbeda)."""
import pandas as pd
import streamlit as st

from cybersec_report import ui_components as U
from cybersec_report.core.compare import SEV_ORDER, compare_sections
from cybersec_report.core.fmt import fmt_int, fmt_pct


def _summary_lines(c, label_a, label_b, loc):
    k = c["kpi"].set_index("Metric")
    t = k.loc["Total events"]
    lines = []
    if t["A"]:
        d = (t["B"] - t["A"]) / t["A"] * 100
        word = "naik" if d > 0 else "turun" if d < 0 else "tidak berubah"
        lines.append(f"Total event {word} dari {fmt_int(t['A'], loc)} ({label_a}) menjadi {fmt_int(t['B'], loc)} ({label_b})"
                     + (f", {fmt_pct(abs(d), 1, loc)}." if d else "."))
    for s in ("Critical", "High"):
        r = k.loc[s]
        if r["A"] != r["B"]:
            lines.append(f"Event {s}: {fmt_int(r['A'], loc)} → {fmt_int(r['B'], loc)}.")
    att = c["attacks"]
    new, gone = att[att["Trend"] == "★ New"], att[att["Trend"] == "✕ Gone"]
    if len(new):
        lines.append(f"{len(new)} signature baru muncul di {label_b} (mis. {', '.join(new.sort_values('B', ascending=False)['Attack'].head(3))}).")
    if len(gone):
        lines.append(f"{len(gone)} signature yang ada di {label_a} tidak terlihat di {label_b}.")
    ips = c["source_ips"]
    pers = ips[ips["Status"].str.startswith("Persisten")]
    lines.append(f"{len(pers)} source IP muncul di kedua periode; {int((ips['Status'] == 'Baru di B').sum())} IP baru di {label_b}.")
    return lines


def render_compare(vm_a, a, vm_b, b, label_a, label_b, stable_pct=5.0, loc="id", key="cs_cmp"):
    c = compare_sections(a, b, stable_pct)
    for w in c["warnings"]:
        st.warning(w)
    if vm_a["period"]["start_date"] and vm_b["period"]["start_date"]:
        la = (vm_a["period"]["end_date"] - vm_a["period"]["start_date"]).days
        lb = (vm_b["period"]["end_date"] - vm_b["period"]["start_date"]).days
        if abs(la - lb) > 3:
            st.caption(f"ℹ️ Panjang periode berbeda ({la + 1} vs {lb + 1} hari); bandingkan tren, bukan hanya selisih angka.")
    k = c["kpi"].set_index("Metric")

    def card(metric, accent=None):
        r = k.loc[metric]
        d = r["B"] - r["A"]
        sub = f"A {fmt_int(r['A'], loc)} · {'▲' if d > 0 else '▼' if d < 0 else '▬'} {fmt_int(abs(d), loc)}" + \
              (f" ({fmt_pct(abs(r['Δ%']), 1, loc)})" if pd.notna(r["Δ%"]) and d else "")
        return (metric, fmt_int(r["B"], loc), sub, accent)
    st.markdown(U.kpi_cards([card("Total events"), card("Critical", U.SEV_COLORS["Critical"]), card("High", U.SEV_COLORS["High"]),
                             card("Unique source IP"), card("Unique attack")]), unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(U.section_title("Ringkasan perubahan (otomatis dari data)"), unsafe_allow_html=True)
        for line in _summary_lines(c, label_a, label_b, loc):
            st.markdown(f"- {line}")
    t = st.tabs(["Severity", "Attack Name", "Source IP", "Source Country"])
    with t[0]:
        rows = [(m, k.loc[m, "A"], k.loc[m, "B"]) for m in SEV_ORDER]
        with st.container(border=True):
            st.markdown(U.compare_bars(rows, label_a, label_b, loc), unsafe_allow_html=True)
        st.dataframe(c["kpi"], use_container_width=True, hide_index=True)
    with t[1]:
        att = c["attacks"]
        movers = att.assign(_abs=att["Δ"].abs()).sort_values("_abs", ascending=False).head(10)
        with st.container(border=True):
            st.markdown(U.section_title("Perubahan terbesar (Top 10)", "Diurutkan berdasarkan selisih mutlak"), unsafe_allow_html=True)
            st.markdown(U.compare_bars([(f"{r['Attack']}", r["A"], r["B"]) for _, r in movers.iterrows()], label_a, label_b, loc), unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**★ Signature baru**")
            st.dataframe(att[att["Trend"] == "★ New"][["Attack", "Severity", "B"]].rename(columns={"B": label_b}), use_container_width=True, hide_index=True)
        with c2:
            st.markdown("**✕ Tidak terlihat lagi**")
            st.dataframe(att[att["Trend"] == "✕ Gone"][["Attack", "Severity", "A"]].rename(columns={"A": label_a}), use_container_width=True, hide_index=True)
        with st.expander("Semua signature"):
            st.dataframe(att, use_container_width=True, hide_index=True)
    with t[2]:
        ips = c["source_ips"]
        s1, s2, s3 = st.columns(3)
        s1.metric("Persisten (kedua periode)", int(ips["Status"].str.startswith("Persisten").sum()))
        s2.metric(f"Baru di {label_b}", int((ips["Status"] == "Baru di B").sum()))
        s3.metric(f"Hilang di {label_b}", int((ips["Status"] == "Hilang di B").sum()))
        st.markdown("**Source IP yang muncul di kedua periode** (berulang)")
        st.dataframe(ips[ips["Status"].str.startswith("Persisten")].head(50), use_container_width=True, hide_index=True)
        with st.expander("IP baru dan IP yang hilang"):
            st.dataframe(ips[~ips["Status"].str.startswith("Persisten")].head(100), use_container_width=True, hide_index=True)
        st.caption("IP persisten berarti sumber yang sama muncul lagi; ini indikasi, bukan bukti bahwa serangan berasal dari pihak yang sama.")
    with t[3]:
        ct = c["countries"].head(8)
        with st.container(border=True):
            st.markdown(U.compare_bars([(r["Country"], r["A"], r["B"]) for _, r in ct.iterrows()], label_a, label_b, loc), unsafe_allow_html=True)
        with st.expander("Semua negara"):
            st.dataframe(c["countries"], use_container_width=True, hide_index=True)
