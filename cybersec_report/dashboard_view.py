"""Dashboard IPS di dalam aplikasi (tanpa perlu membuat PPT/Excel). Layout mengikuti slide contoh:
pie, tabel severity + Description, tabel Attack Name (Critical/High/...), Dest, Source Country,
semua Top-5 + Others + By%. Data berasal dari view-model (upload langsung ATAU snapshot tersimpan)."""
from html import escape

import pandas as pd
import streamlit as st

from cybersec_report import ui_components as U
from cybersec_report.core.config_loader import load_scoring

from cybersec_report.core.fmt import fmt_int, fmt_pct

HEADER_BG, BAND_BG, TEXT = "#156082", "#C0E6F5", "#1B2A38"
SEV_COLORS, RISK_COLORS = U.SEV_COLORS, U.RISK_COLORS


def html_table(headers, rows, total=None, title=None, aligns=None, col_widths=None):
    """Tabel bergaya PPT: header biru tua, baris berselang-seling biru muda, baris Total tebal."""
    aligns = aligns or ["left"] + ["right"] * (len(headers) - 1)
    th = "".join(f'<th style="text-align:{a};padding:5px 8px;background:{HEADER_BG};color:#fff;font-weight:600">{h}</th>'
                 for h, a in zip(headers, aligns))
    body = []
    for i, r in enumerate(rows):
        bg = BAND_BG if i % 2 == 0 else "#FFFFFF"
        tds = "".join(f'<td style="text-align:{a};padding:4px 8px;background:{bg};color:{TEXT}">{escape(str(c))}</td>'
                      for c, a in zip(r, aligns))
        body.append(f"<tr>{tds}</tr>")
    if total:
        tds = "".join(f'<td style="text-align:{a};padding:5px 8px;background:{BAND_BG};color:{TEXT};font-weight:700">{escape(str(c))}</td>'
                      for c, a in zip(total, aligns))
        body.append(f"<tr>{tds}</tr>")
    cap = f'<div style="font-weight:600;margin:6px 0 2px 0">{title}</div>' if title else ""
    cg = "".join(f'<col style="width:{w}">' for w in col_widths) if col_widths else ""
    layout = "table-layout:fixed;" if col_widths else ""
    return (f'{cap}<table style="width:100%;{layout}border-collapse:collapse;font-size:0.85rem;margin-bottom:14px">'
            f'<colgroup>{cg}</colgroup><thead><tr>{th}</tr></thead><tbody>{"".join(body)}</tbody></table>')


def _top_table_html(df, label_col, loc, title=None, label_header=None):
    if df is None or df.empty:
        return f"<i>{title or label_col}: tidak ada data</i>"
    rows = [[r[label_col], fmt_int(r["Count"], loc), fmt_pct(r["Percent"], 2, loc)] for _, r in df.iterrows()]
    total = ["Total", fmt_int(df["Count"].sum(), loc), fmt_pct(df["Percent"].sum(), 2, loc)]
    return html_table([label_header or label_col, "Count", "By%"], rows, total, title)


def _sev_title(label, sev):
    return f'{label} (<span style="color:{SEV_COLORS.get(sev, TEXT)}">{sev}</span>)'


def _items(df, label_col):
    return [(r[label_col], r["Count"], r["Percent"]) for _, r in df.iterrows()] if df is not None and len(df) else []


def _card(html_inner, title=None, sub=None):
    with st.container(border=True):
        if title:
            st.markdown(U.section_title(title, sub).replace("margin:18px 0 8px 0", "margin:0 0 8px 0"), unsafe_allow_html=True)
        st.markdown(html_inner, unsafe_allow_html=True)


def _checked(prof):
    return prof[prof["TI Status"].isin(["CHECKED", "PARTIAL"])] if "TI Status" in prof else prof.iloc[0:0]


def _score_explainer():
    cfg = load_scoring()
    w, vt, ab = cfg["weights"], cfg["vt"], cfg["abuse"]
    bands = " · ".join(f"**{n}** {lo}–{hi}" for lo, hi, n in cfg["bands"])
    st.markdown(
        "**Internal Normalized Threat Score (0–100)** - skor internal, *bukan* skor resmi vendor. Dihitung hanya dari provider yang benar-benar "
        "dipanggil; bobot dinormalisasi ulang atas komponen yang tersedia.\n\n"
        f"| Komponen | Bobot | Cara hitung |\n|---|---|---|\n"
        f"| VirusTotal malicious | {w['vt_malicious']:.0%} | (engine *malicious* + {vt['suspicious_weight']} × *suspicious*) ÷ {vt['malicious_saturation_engines']} engine, maksimum 100% |\n"
        f"| AbuseIPDB confidence | {w['abuse_confidence']:.0%} | Abuse Confidence Score ÷ 100 |\n"
        f"| AbuseIPDB jumlah laporan | {w['abuse_reports']:.0%} | laporan ÷ {ab['reports_saturation']}, maksimum 100% |\n"
        f"| Recency laporan | {w['recency']:.0%} | ≤7 hari 100% · ≤30 hari 50% · ≤90 hari 25% |\n\n"
        f"Band: {bands}.\n\n"
        "Contoh bila hanya VirusTotal yang terpakai (strategi failover): skor = (malicious + 0,5 × suspicious) ÷ 10 × 100, "
        "jadi 2 engine malicious = 20 (*Guarded*), 6 = 60 (*High*), ≥10 = 100 (*Critical*). "
        "Skor 0 berarti tidak ada engine yang menandai IP itu, **bukan jaminan IP aman** (mis. scanner baru sering belum terdaftar). "
        "Skor adalah indikator berbasis bukti dari provider, bukan bukti kompromi.")


def _rep_table(prof, n=10, only_flagged=False):
    chk = _checked(prof)
    if only_flagged:
        chk = chk[chk["Risk Level"] != "Low"]
    cols = [c for c in ["Source IP", "Country", "Attack Count", "Risk Level", "Threat Score", "Interpretation", "Evidence", "AS / ISP", "TI Source"]
            if c in chk.columns]
    view = chk.sort_values(["Threat Score", "Attack Count"], ascending=False).head(n)[cols]
    cfg = {}
    try:
        cfg = {"Threat Score": st.column_config.ProgressColumn("Threat Score", min_value=0, max_value=100, format="%d"),
               "Attack Count": st.column_config.NumberColumn("Events", format="%d"),
               "Evidence": st.column_config.TextColumn("Bukti dari provider", width="large")}
    except Exception:
        pass

    def _risk_style(v):
        return f"background-color:{U.RISK_COLORS[v]};color:white;font-weight:600" if v in U.RISK_COLORS else ""
    try:
        data = view.style.map(_risk_style, subset=["Risk Level"])
        st.dataframe(data, use_container_width=True, hide_index=True, column_config=cfg, height=min(38 * (len(view) + 1), 460))
    except Exception:
        st.dataframe(view, use_container_width=True, hide_index=True)
    return len(view)


def _reputation_block(a, rep, loc):
    """Ringkasan reputasi di Overview: cakupan, jumlah per risk level, IP dengan skor tertinggi + bukti, cara membaca skor."""
    prof = rep["profile"]
    chk = _checked(prof)
    with st.container(border=True):
        st.markdown(U.section_title("Threat Intelligence · reputasi source IP",
                                    "Menjawab: IP mana yang menurut provider benar-benar bermasalah, dan berdasarkan skor berapa"
                                    ).replace("margin:18px 0 8px 0", "margin:0 0 8px 0"), unsafe_allow_html=True)
        if chk.empty:
            st.info("Belum ada hasil reputasi untuk section ini. Jalankan **Run Reputation Check** di tab 3 · Threat Intelligence. "
                    "'Not assessed' berarti belum dicek, bukan berarti aman.")
            with st.expander("Bagaimana skor reputasi dihitung?"):
                _score_explainer()
            return
        public_n = int((~prof["TI Status"].isin(["PRIVATE_IP", "INVALID_IP"])).sum())
        tot_ev = float(prof["Attack Count"].sum()) or 1.0
        cov = float(chk["Attack Count"].sum()) / tot_ev * 100
        lv = chk["Risk Level"].value_counts()
        src = ", ".join(sorted(set(chk["TI Source"]) - {"-"})) or "-"
        st.markdown(U.kpi_cards([("IP dicek", f"{fmt_int(len(chk), loc)} / {fmt_int(public_n, loc)}",
                                  f"mewakili {fmt_pct(cov, 1, loc)} dari event · provider: {src}", None)] +
                                [(k, fmt_int(lv.get(k, 0), loc), "source IP", U.RISK_COLORS[k]) for k in ("Critical", "High", "Medium", "Guarded", "Low")]),
                    unsafe_allow_html=True)
        flagged = chk[chk["Risk Level"] != "Low"]
        if flagged.empty:
            st.success("Dari IP yang dicek, tidak ada yang di atas band Low menurut provider yang dipakai. "
                       "Ini bukan jaminan aman: IP yang belum dicek tetap 'Not assessed'.")
            _rep_table(prof, 5)
        else:
            st.markdown(f"**{len(flagged)} IP di atas band Low** (diurutkan berdasarkan Threat Score):")
            _rep_table(prof, 10, only_flagged=True)
        if len(chk) < public_n:
            st.caption(f"{fmt_int(public_n - len(chk), loc)} IP publik lain belum dicek (batas **Maks. IP** di sidebar; hasil lama dipakai ulang dari cache, "
                       "jadi menaikkan batas hanya memakai token untuk IP baru).")
        with st.expander("Bagaimana skor reputasi dihitung?"):
            _score_explainer()


def _action_card(a, loc):
    ab = a.get("action_breakdown")
    if ab is None or ab.empty:
        _card('<div style="font-size:.85rem;opacity:.68">Kolom action tidak tersedia pada data ini.</div>', "Tindakan perangkat (action)")
        return
    its = [(f"{r['Action']} · {'dihitung' if r['Counted'] else 'TIDAK dihitung'}", r["Events"], r["Percent"]) for _, r in ab.iterrows()]
    only = ab["Counted"].all()
    note = ("Semua event di file berstatus blocking (dropped/blocked/denied), jadi tidak ada event 'detected-only' yang dikeluarkan."
            if only else "Event 'detected'/passthrough tidak dihitung ke total serangan terblokir; jumlahnya tetap ditampilkan di sini.")
    _card(U.hbar_list(its, color=U.ACCENT, loc=loc), "Tindakan perangkat (action)", note)


def _tab_overview(a, rep, vm, loc):
    sev = a["severity"].set_index("Severity")
    total = a["total_events"]
    crit, high = sev["Count"].get("Critical", 0), sev["Count"].get("High", 0)
    ch_pct = (crit + high) / total * 100 if total else 0
    cc = a["top_country"]
    top_c = cc[cc["Source Country"] != "Others"].head(1)
    conc = a["concentration"]
    st.markdown(U.kpi_cards([
        ("Total events", fmt_int(total, loc), f"{fmt_int(a['reconciliation']['raw_records_in_file'], loc)} raw records", None),
        ("Critical + High", fmt_int(crit + high, loc), f"{fmt_pct(ch_pct, 1, loc)} dari total · Critical {fmt_int(crit, loc)}", U.SEV_COLORS["Critical"]),
        ("Unique source IP", fmt_int(a["unique"]["source_ip"], loc), f"IP teratas = {fmt_pct(conc['top1_source_ip_pct'], 1, loc)} dari event", None),
        ("Unique attack", fmt_int(a["unique"]["attack"], loc), f"{fmt_int(a['unique']['destination'], loc)} destination IP", None),
        ("Top source country", top_c.iloc[0]["Source Country"] if len(top_c) else "-",
         fmt_pct(top_c.iloc[0]["Percent"], 1, loc) + " dari event" if len(top_c) else None, None)]), unsafe_allow_html=True)
    if a["reconciliation"]["events_excluded_by_action"]:
        st.caption(f"ℹ️ {fmt_int(a['reconciliation']['events_excluded_by_action'], loc)} event berstatus non-blocking tidak dihitung ({vm.get('filter') or a['filter']}).")
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        items = [(r["Severity"], r["Count"], r["Percent"], U.SEV_COLORS.get(r["Severity"], U.OTHERS), r["Description"])
                 for _, r in a["severity"].iterrows() if r["Count"] > 0]
        _card(U.donut(items, fmt_int(total, loc), "total events", loc=loc), "Distribusi severity",
              "Hover pada baris untuk deskripsi. Skala merah gelap → terang = Critical → Medium; abu-abu = Low.")
    with c2:
        _card(U.hbar_list(_items(a["top_country"], "Source Country"), loc=loc), "Source country", "Top 5 + Others · % terhadap total event")
        _action_card(a, loc)
    c3, c4 = st.columns(2, gap="medium")
    with c3:
        _card(U.hbar_list(_items(a["top_destination"], "Dest"), loc=loc), "Destination", "Top 5 + Others · % terhadap total event")
    with c4:
        p = a["source_profile"].head(8)
        its = [(f"{r['Source IP']} · {r['Country']}", r["Attack Count"], r["Attack Count"] / total * 100 if total else 0) for _, r in p.iterrows()]
        _card(U.hbar_list(its, loc=loc), "Top source IP", "8 IP dengan event terbanyak · % terhadap total event")
    _reputation_block(a, rep, loc)


def _tab_attacks(a, loc):
    st.markdown(U.stacked_bar([(r["Severity"], r["Count"], U.SEV_COLORS.get(r["Severity"], U.OTHERS)) for _, r in a["severity"].iterrows()], loc), unsafe_allow_html=True)
    st.caption("Komposisi severity. Di bawah: Top-5 + Others per severity, % terhadap total severity tersebut (bukan total semua event).")
    _card(U.hbar_list(_items(a["top_attacks"], "Attack Name"), loc=loc), "Semua severity", "Top 5 + Others · % terhadap total event")
    sevs = ["Critical", "High", "Medium", "Low"] + [s for s in a["top_by_severity"] if s not in ("Critical", "High", "Medium", "Low")]
    for i in range(0, len(sevs), 2):
        cols = st.columns(2, gap="medium")
        for col, sv in zip(cols, sevs[i:i + 2]):
            with col:
                n = a["severity"].set_index("Severity")["Count"].get(sv, 0)
                title = f'{U.badge(sv, U.SEV_COLORS.get(sv, U.OTHERS), "#fff" if sv != "Medium" else "#4a1514")} &nbsp; Attack Name · {fmt_int(n, loc)} event'
                _card(U.hbar_list(_items(a["top_by_severity"].get(sv), "Attack Name"), color=U.SEV_COLORS.get(sv, U.OTHERS), loc=loc,
                                  empty=f"Tidak ada serangan {sv}"), title)


def _tab_sources(a, rep, loc):
    prof = rep["profile"]
    if _checked(prof).empty:
        st.info("Reputasi belum dicek. Jalankan **Run Reputation Check** di tab 3 · Threat Intelligence. "
                "'Not assessed' berarti belum dicek, bukan berarti aman.")
    else:
        st.markdown("**IP yang sudah dicek reputasinya** (urut Threat Score)")
        _rep_table(prof, 100)
    with st.expander("Semua top source IP (termasuk yang belum dicek)", expanded=_checked(prof).empty):
        cols = [c for c in ["Source IP", "Country", "Attack Count", "Unique Attack", "Critical", "High", "Top Attack", "Threat Score",
                            "Risk Level", "TI Status"] if c in prof.columns]
        st.dataframe(prof[cols].head(50), use_container_width=True, hide_index=True)
    with st.expander("Bagaimana skor reputasi dihitung?"):
        _score_explainer()
    st.caption("IP privat tidak dikirim ke provider. Threat Score = Internal Normalized Threat Score (0–100), bukan skor vendor.")


def _tab_insights(findings, mom):
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    fs = sorted(findings, key=lambda f: rank.get(str(f["severity"]).upper(), 9))
    col = {"CRITICAL": U.SEV_COLORS["Critical"], "HIGH": U.SEV_COLORS["High"], "MEDIUM": U.SEV_COLORS["Medium"], "LOW": U.OTHERS, "INFO": U.OTHERS}
    st.caption("Narasi berbasis data yang teramati; tidak menyimpulkan kompromi tanpa bukti.")
    for f in fs:
        sv = str(f["severity"]).upper()
        with st.container(border=True):
            st.markdown(U.badge(sv, col.get(sv, U.OTHERS), "#4a1514" if sv == "MEDIUM" else "#fff") +
                        f' &nbsp; <b>{f["finding"]}</b>', unsafe_allow_html=True)
            for d in f.get("details", []):
                st.markdown(f"- {d}")
            cols = st.columns(2)
            items = [(lbl, f[lbl]) for lbl in ("impact", "recommendation", "action", "prevention") if f.get(lbl)]
            for i, (lbl, txt) in enumerate(items):
                cols[i % 2].markdown(f"**{lbl.title()}**  \n{txt}")
    if mom:
        st.markdown(U.section_title("Month-over-month"), unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(mom), use_container_width=True, hide_index=True)
    else:
        st.caption("Perbandingan bulan lalu tidak ditampilkan: snapshot bulan sebelumnya belum tersimpan.")


def _tab_tables(a, loc):
    st.caption("Tabel gaya slide PowerPoint (Top 5 + Others, By%) - angka sama dengan grafik.")
    sev = a["severity"]
    rows = [[s, d, fmt_int(c, loc), fmt_pct(p, 2, loc)] for s, d, c, p in zip(sev["Severity"], sev["Description"], sev["Count"], sev["Percent"])]
    st.markdown(html_table(["Severity", "Description", "Count", "By%"], rows,
                           ["Total", "", fmt_int(sev["Count"].sum(), loc), fmt_pct(sev["Percent"].sum(), 2, loc)],
                           aligns=["left", "left", "right", "right"], col_widths=["14%", "58%", "12%", "16%"]), unsafe_allow_html=True)
    sevs = list(a["top_by_severity"])
    for i in range(0, len(sevs), 2):
        cols = st.columns(2, gap="medium")
        for col, sv in zip(cols, sevs[i:i + 2]):
            col.markdown(_top_table_html(a["top_by_severity"][sv], "Attack Name", loc, _sev_title("Attack Name", sv)), unsafe_allow_html=True)
    d1, d2 = st.columns(2, gap="medium")
    d1.markdown(_top_table_html(a["top_destination"], "Dest", loc, "Destination"), unsafe_allow_html=True)
    d2.markdown(_top_table_html(a["top_country"], "Source Country", loc, "Source Country"), unsafe_allow_html=True)


def _render_section(a, rep, findings, mom, vm, loc, key):
    t = st.tabs(["Overview", "Attack Analysis", "Source IP & Reputation", "Insights", "Data Tables"])
    with t[0]:
        _tab_overview(a, rep, vm, loc)
    with t[1]:
        _tab_attacks(a, loc)
    with t[2]:
        _tab_sources(a, rep, loc)
    with t[3]:
        _tab_insights(findings, mom)
    with t[4]:
        _tab_tables(a, loc)


def _reputation_usage(vm):
    run = vm.get("reputation_run")
    if not run:
        return
    stt = run["stats"]
    with st.expander("Penggunaan provider reputasi (failover)"):
        st.write(f"Strategi: **{stt.get('strategy', '-')}** · urutan: {' → '.join(stt.get('order', []))}")
        rows = [{"Provider": n, "Request API (token terpakai)": v.get("api_calls", 0), "Berhasil": v["ok"],
                 "Dari cache": v["cached"], "Gagal": v["failed"], "Status": v["state"]} for n, v in stt["providers"].items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        for sw in stt.get("switches", []):
            st.info(f"Beralih {sw['from']} → {sw['to']} setelah {sw['after_api_calls']} request.")
        for line in run.get("log", [])[:10]:
            st.caption(line)


def render_ips_dashboard(vm, key="cs_dash"):
    """vm: view-model (lihat IPSPipeline.view_model)."""
    loc = "id"
    p = vm["period"]
    st.markdown(U.css_reset(), unsafe_allow_html=True)
    chips = [f"Sumber: {vm['source_file']}", f"Periode {p['start_date']} s/d {p['end_date']}"]
    if vm.get("saved_at"):
        chips.append(f"Snapshot {vm['saved_at'][:16].replace('T', ' ')}")
    for label, val in (("Data validation", vm.get("validation_overall")), ("Cross validation", vm.get("cross_overall"))):
        if val:
            chips.append(f"{ {'PASS': '✅', 'WARNING': '⚠️', 'FAIL': '❌'}.get(val, '') } {label}: {val}")
    st.markdown(f'<div style="font-size:1.35rem;font-weight:700;margin:2px 0 2px 0">Intrusion Prevention System · {p["month_name"]} {p["report_year"]}</div>'
                f'<div style="font-size:.8rem;opacity:.68;margin-bottom:10px">{" &nbsp;·&nbsp; ".join(str(c) for c in chips)}</div>', unsafe_allow_html=True)
    names = [a["name"] for a in vm["sections"]]
    if len(names) > 1:
        sel = st.radio("Environment", names, horizontal=True, key=f"{key}_env")
    else:
        sel = names[0]
    a = next(x for x in vm["sections"] if x["name"] == sel)
    _render_section(a, vm["rep"][sel], vm["findings"][sel], vm["mom"].get(sel), vm, loc, f"{key}_{sel}")
    _reputation_usage(vm)
