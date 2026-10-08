"""Halaman Akamai (Cloud WAF / Anti-DDoS / Anti-BOT) di Cybersecurity Monthly Report - pola SAMA dengan IPS:
sidebar (pilih sumber + upload) -> tab Dashboard | Compare | Upload & Mapping | Validation | Generate / Export,
dashboard berisi Overview | Attack Analysis | Insights | Data Tables (kartu, donut, bar, tabel gaya slide).
Angka hanya dari file yang di-upload."""
import io
from datetime import date
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

from cybersec_report import ui_components as ui
from cybersec_report.core.config_loader import output_dir
from cybersec_report.core.fmt import fmt_int, fmt_pct
from cybersec_report.core.period import month_name, period_from_filename
from cybersec_report.dashboard_view import _card, html_table
from cybersec_report.sources import akamai as ak
from cybersec_report.sources import akamai_store as store

LEVEL_STYLE = {"watch": ("PERLU DIPANTAU", "#e0a100"), "info": ("INFO", "#3987e5")}
CHECK_ICON = {"ok": "✅", "warn": "⚠️", "error": "❌"}


def clear_upload_cb():
    """Hapus file dari sesi saja (snapshot tersimpan tetap)."""
    for k in ("cs_ak_parsed", "cs_ak_sig", "cs_ak_period_ok"):
        st.session_state.pop(k, None)
    st.session_state["cs_ak_up_n"] = st.session_state.get("cs_ak_up_n", 0) + 1


def sidebar_upload():
    """Dipanggil dari sidebar dashboard: uploader Akamai (selalu tampil agar file tidak hilang saat pindah sumber)."""
    st.sidebar.markdown("**UPLOAD AKAMAI**")
    up = st.sidebar.file_uploader("Akamai WAF report (XLSX)", type=["xlsx"], key=f"cs_ak_upload_{st.session_state.get('cs_ak_up_n', 0)}",
                                  help="Export bulanan dari tim Akamai. Sheet dibaca: WAF Attack, BOT Attack, Bad Reputation, DOS.")
    if up is not None:
        st.sidebar.button("🗑️ Hapus file Akamai ini", key="cs_ak_clear", on_click=clear_upload_cb,
                          help="Hanya menghapus file dari sesi. Snapshot bulanan yang sudah disimpan tetap ada.")
    return up


def _delete_cb(path):
    try:
        ok = store.delete_snapshot(path)
        st.session_state["cs_ak_del_msg"] = ("ok", "Snapshot Akamai dihapus." if ok else "File snapshot sudah tidak ada.")
    except Exception as e:
        st.session_state["cs_ak_del_msg"] = ("err", f"Gagal menghapus: {e}")
    st.session_state.pop("cs_ak_dash_source", None)
    st.session_state.pop("cs_ak_del_confirm", None)


def _load(up):
    """Parse hanya bila file berubah; kegagalan ditampilkan, tidak menjatuhkan halaman."""
    if up is None:
        st.session_state.pop("cs_ak_parsed", None)
        st.session_state.pop("cs_ak_sig", None)
        return None
    sig = (up.name, getattr(up, "size", None))
    if st.session_state.get("cs_ak_sig") != sig or "cs_ak_parsed" not in st.session_state:
        try:
            up.seek(0)
            st.session_state["cs_ak_parsed"] = ak.parse_workbook(io.BytesIO(up.read()), up.name)
            st.session_state["cs_ak_sig"] = sig
            st.session_state.pop("cs_ak_period_ok", None)
        except ak.AkamaiError as e:
            st.session_state.pop("cs_ak_parsed", None)
            st.session_state.pop("cs_ak_sig", None)
            st.error(f"File Akamai tidak dapat dibaca: {e}")
            return None
    return st.session_state.get("cs_ak_parsed")


def _period_inputs(parsed):
    guess = period_from_filename(parsed.get("filename", ""))
    today = date.today()
    dm, dy = guess or (today.month, today.year)
    c1, c2, c3 = st.columns([2, 1, 3])
    month = c1.selectbox("Bulan laporan", list(range(1, 13)), index=dm - 1, format_func=month_name, key="cs_ak_month")
    year = c2.number_input("Tahun", min_value=2020, max_value=2100, value=int(dy), step=1, key="cs_ak_year")
    c3.caption(("Terdeteksi dari NAMA FILE. " if guess else "Nama file tidak memuat bulan; nilai awal hanya tebakan. ") +
               "File Akamai tidak memuat rentang tanggal, jadi bulan wajib dikonfirmasi.")
    ok = st.checkbox(f"Periode {month_name(month)} {int(year)} sudah benar", key="cs_ak_period_ok")
    return int(month), int(year), bool(ok)


def render_checks(checks):
    n = {k: sum(1 for c in checks if c["level"] == k) for k in CHECK_ICON}
    if n["error"]:
        st.error(f"{n['error']} pemeriksaan gagal, {n['warn']} peringatan. Dashboard tetap ditampilkan; angka yang bermasalah ditandai di bawah.")
    elif n["warn"]:
        st.warning(f"Lolos dengan {n['warn']} peringatan.")
    else:
        st.success("Semua pemeriksaan lolos (jumlah item = Total di setiap tabel).")
    for c in sorted(checks, key=lambda c: ["error", "warn", "ok"].index(c["level"])):
        if c["level"] != "ok":
            st.markdown(f"{CHECK_ICON[c['level']]} {c['msg']}")
    with st.expander("Semua pemeriksaan"):
        for c in checks:
            st.markdown(f"{CHECK_ICON[c['level']]} {c['msg']}")


def _insight_card(i):
    label, color = LEVEL_STYLE.get(i["level"], LEVEL_STYLE["info"])
    with st.container(border=True):
        st.markdown(ui.badge(label, color) + f' &nbsp; <b>{escape(i["title"])}</b>', unsafe_allow_html=True)
        st.markdown(i["text"])


def _items(sec, dim):
    return ak.table_rows(sec, dim)


def _tab_overview(parsed, summary, loc="id"):
    secs = parsed["sections"]
    cards = [("Total hit (4 kategori)", fmt_int(summary["grand_total"], loc), "penjumlahan; kemungkinan ada overlap", None)]
    for k in summary["order"]:
        cards.append((ak.SECTION_TITLE[k], fmt_int(summary["totals"][k], loc), fmt_pct(summary["shares"][k], 1, loc) + " dari total", ak.SECTION_COLOR[k]))
    st.markdown(ui.kpi_cards(cards), unsafe_allow_html=True)
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        items = [(ak.SECTION_TITLE[k], summary["totals"][k], summary["shares"][k], ak.SECTION_COLOR[k], ak.SECTION_DESC[k]) for k in summary["order"]]
        _card(ui.donut(items, fmt_int(summary["grand_total"], loc), "total hit", loc=loc), "Traffic by attack type",
              "Hover pada baris untuk deskripsi. Persentase terhadap total hit semua kategori di file.")
    with c2:
        hosts = [(h["host"], h["total"], h["total"] / summary["grand_total"] * 100 if summary["grand_total"] else 0) for h in
                 sorted(summary["hosts"], key=lambda x: -x["total"])[:8]]
        _card(ui.hbar_list(hosts, loc=loc), "Top host tujuan (gabungan kategori)",
              "Jumlah dari top 5 host tiap kategori; host di luar top 5 tidak terlihat · % terhadap total hit")
    c3, c4 = st.columns(2, gap="medium")
    watch = [i for i in ak.build_insights(parsed, summary) if i["level"] == "watch"]
    with c3:
        _card(ui.stacked_bar([(ak.SECTION_TITLE[k], summary["totals"][k], ak.SECTION_COLOR[k]) for k in summary["order"]], loc) +
              '<div style="font-size:.78rem;opacity:.68;margin-top:6px">Komposisi hit per kategori.</div>', "Komposisi")
    with c4:
        st.markdown(f"**{len(watch)} hal perlu dipantau** (detail di tab Insights)" if watch else "Tidak ada insight level 'perlu dipantau'.")
        for i in watch[:3]:
            st.markdown(f"- **{i['title']}** — {i['text'].split('. ')[0]}.")


def _tab_attacks(parsed, summary, loc="id"):
    secs = parsed["sections"]
    for k in summary["order"]:
        st.markdown(ui.section_title(f'{ui.badge(ak.SECTION_TITLE[k], ak.SECTION_COLOR[k])} &nbsp; {fmt_int(summary["totals"][k], loc)} hit',
                                     ak.SECTION_DESC[k]), unsafe_allow_html=True)
        dims = [d for d in ak.DIM_ORDER if d in secs[k]["tables"]]
        for i in range(0, len(dims), 2):
            cols = st.columns(2, gap="medium")
            for col, d in zip(cols, dims[i:i + 2]):
                with col:
                    _card(ui.hbar_list(_items(secs[k], d), color=ak.SECTION_COLOR[k], loc=loc), secs[k]["tables"][d]["header"],
                          "Top 5 + Others · % terhadap total kategori ini")
    st.markdown(ui.section_title("Eksposur host lintas kategori", "Dari top 5 host tiap kategori; sel kosong = tidak masuk top 5 (bukan nol)"), unsafe_allow_html=True)
    rows = [{"Host": h["host"], **{ak.SECTION_TITLE[k]: h["by"].get(k) for k in summary["order"]}, "Total (top 5)": h["total"], "Jumlah kategori": h["n_sections"]}
            for h in summary["hosts"]]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _tab_insights(parsed, summary):
    st.caption("Narasi berbasis data yang teramati; tidak menyimpulkan kompromi tanpa bukti.")
    ins = ak.build_insights(parsed, summary)
    for i in sorted(ins, key=lambda x: 0 if x["level"] == "watch" else 1):
        _insight_card(i)


def _tab_tables(parsed, summary, loc="id"):
    st.caption("Tabel gaya slide PowerPoint (Top 5 + Others, By%) - angka sama dengan grafik. By% dihitung ulang dari Total Hits.")
    gt = summary["grand_total"]
    rows = [[ak.SECTION_TITLE[k], fmt_int(summary["totals"][k], loc), fmt_pct(summary["shares"][k], 1, loc)] for k in summary["order"]]
    st.markdown(html_table(["Attack Type", "Total Hits", "By %"], rows, ["Total", fmt_int(gt, loc), fmt_pct(100 if gt else 0, 0, loc)],
                           title="Traffic by Attack Type", col_widths=["50%", "28%", "22%"]), unsafe_allow_html=True)
    for k in summary["order"]:
        st.markdown(ui.section_title(ak.SECTION_TITLE[k]), unsafe_allow_html=True)
        dims = [d for d in ak.DIM_ORDER if d in parsed["sections"][k]["tables"]]
        cols = st.columns(len(dims), gap="medium")
        for col, d in zip(cols, dims):
            t = parsed["sections"][k]["tables"][d]
            rr = [[lab, fmt_int(h, loc), fmt_pct(p, 1, loc)] for lab, h, p in ak.table_rows(parsed["sections"][k], d)]
            col.markdown(html_table([t["header"], "Total Hits", "By %"], rr, ["Total", fmt_int(t["total"], loc), fmt_pct(100, 0, loc)]), unsafe_allow_html=True)


def render_akamai_dashboard(parsed, label, meta=None, key="cs_ak"):
    """parsed: hasil parse_workbook atau snapshot. Pola sama dengan render_ips_dashboard."""
    loc = "id"
    summary = ak.summarize(parsed)
    st.markdown(ui.css_reset(), unsafe_allow_html=True)
    chips = [f"Sumber: {parsed.get('filename') or '-'}"] + list(meta or [])
    errs = [c for c in parsed.get("checks", []) if c["level"] == "error"]
    warns = [c for c in parsed.get("checks", []) if c["level"] == "warn"]
    chips.append("❌ Data validation: FAIL" if errs else ("⚠️ Data validation: WARNING" if warns else "✅ Data validation: PASS"))
    st.markdown(f'<div style="font-size:1.35rem;font-weight:700;margin:2px 0 2px 0">Akamai WAF / Anti-DDoS / Anti-BOT · {escape(label)}</div>'
                f'<div style="font-size:.8rem;opacity:.68;margin-bottom:10px">{" &nbsp;·&nbsp; ".join(escape(str(c)) for c in chips)}</div>', unsafe_allow_html=True)
    if errs:
        st.warning("File sumber punya ketidakcocokan angka (detail di tab 2 · Validation): " + " | ".join(c["msg"] for c in errs[:3]))
    t = st.tabs(["Overview", "Attack Analysis", "Insights", "Data Tables"])
    with t[0]:
        _tab_overview(parsed, summary, loc)
    with t[1]:
        _tab_attacks(parsed, summary, loc)
    with t[2]:
        _tab_insights(parsed, summary)
    with t[3]:
        _tab_tables(parsed, summary, loc)


def _tab_mapping(parsed):
    if parsed is None:
        st.info("Upload file Akamai (XLSX) di sidebar bagian UPLOAD AKAMAI untuk memulai.")
        return
    st.caption(f"File: {parsed['filename']} — tabel dikenali dari header 'Total Hits' (bukan posisi sel tetap).")
    rows = []
    for k in ak.SECTION_ORDER:
        sec = parsed["sections"].get(k)
        if not sec:
            rows.append({"Sheet": ak.SHEET_NAMES[k], "Dipakai sebagai": ak.SECTION_TITLE[k], "Tabel": "—", "Baris data": None, "Total di file": None, "Status": "sheet tidak ada"})
            continue
        for d in ak.DIM_ORDER:
            tb = sec["tables"].get(d)
            rows.append({"Sheet": ak.SHEET_NAMES[k], "Dipakai sebagai": ak.SECTION_TITLE[k], "Tabel": f"{ak.DIM_LABEL[d]} (header '{tb['header']}')" if tb else ak.DIM_LABEL[d],
                         "Baris data": len(tb["items"]) if tb else None, "Total di file": tb["total"] if tb else None, "Status": "terbaca" if tb else "tidak ditemukan"})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _tab_validation(parsed):
    if parsed is None:
        st.info("Upload file Akamai di sidebar untuk melihat hasil validasi.")
        return
    render_checks(parsed["checks"])


def _tab_export(parsed):
    if parsed is None:
        st.info("Upload file Akamai di sidebar. Setelah itu konfirmasi periode, simpan snapshot, dan (opsional) unduh Excel.")
        return
    month, year, ok = _period_inputs(parsed)
    exists = {(s["year"], s["month"]) for s in store.list_snapshots()}
    again = (year, month) in exists
    if st.button(f"💾 {'Perbarui' if again else 'Simpan'} snapshot {month_name(month)} {year}", key="cs_ak_save", disabled=not ok):
        p = store.save_snapshot(parsed, month, year)
        st.success(f"Tersimpan: {p.name}. Bisa dibuka lagi di tab Dashboard dan dibandingkan tanpa upload ulang.")
    st.caption("Satu snapshot per bulan di folder database/. " + ("Bulan ini sudah ada; tombol akan menimpanya." if again else "Centang konfirmasi periode untuk mengaktifkan tombol."))
    st.markdown("**Export Excel (opsional)**")
    try:
        path = Path(output_dir()) / f"AKAMAI_{year}-{month:02d}_summary.xlsx"
        ak.to_excel(parsed, path)
        st.download_button("⬇️ Excel Summary Akamai", data=path.read_bytes(), file_name=path.name, key="cs_ak_dl",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        st.caption(f"File juga tersimpan di: `{path.parent}`")
    except Exception as e:
        st.error(f"Export Excel gagal: {e}")


def _tab_dashboard(parsed):
    msg = st.session_state.pop("cs_ak_del_msg", None)
    if msg:
        (st.success if msg[0] == "ok" else st.error)(msg[1])
    snaps = store.list_snapshots()
    options = (["live"] if parsed else []) + [s["path"] for s in snaps]
    if not options:
        st.info("Belum ada data Akamai. Upload file di sidebar (UPLOAD AKAMAI), atau simpan sebuah periode agar bisa dibuka lagi di sini.")
        return
    labels = {"live": f"Upload saat ini — {parsed['filename']}" if parsed else ""}
    labels.update({s["path"]: f"{s['label']} (tersimpan {s['saved_at'][:16].replace('T', ' ')})" for s in snaps})
    choice = st.selectbox("Tampilkan data", options, format_func=lambda o: labels[o], key="cs_ak_dash_source")
    if choice == "live":
        shown, label, meta = parsed, "upload saat ini", []
        if st.session_state.get("cs_ak_period_ok") and "cs_ak_month" in st.session_state:
            p = (int(st.session_state["cs_ak_month"]), int(st.session_state["cs_ak_year"]))
            meta = ["Periode dikonfirmasi user"]
        else:
            p = period_from_filename(parsed.get("filename", ""))
            meta = ["Periode dari nama file (belum dikonfirmasi)"] if p else ["Periode belum ditentukan"]
        if p:
            label = f"{month_name(p[0])} {p[1]}"
    else:
        try:
            shown = store.load_snapshot(choice)
        except Exception as e:
            st.error(f"Snapshot tidak dapat dibuka: {e}")
            return
        label = f"{month_name(shown['period']['month'])} {shown['period']['year']}"
        meta = [f"Snapshot {shown['saved_at'][:16].replace('T', ' ')}"]
        with st.expander("🗑️ Hapus dashboard Akamai tersimpan ini"):
            st.caption(f"Menghapus snapshot **{labels[choice]}** dari folder database/. File upload asli dan snapshot IPS tidak terpengaruh.")
            ok = st.checkbox("Ya, hapus snapshot ini", key="cs_ak_del_confirm")
            st.button("Hapus snapshot", key="cs_ak_del", disabled=not ok, on_click=_delete_cb, args=(choice,))
    render_akamai_dashboard(shown, label, meta)


def _tab_compare():
    snaps = store.list_snapshots()
    if len(snaps) < 2:
        st.info(f"Perbandingan butuh minimal 2 snapshot Akamai (bulan berbeda). Saat ini tersimpan: {len(snaps)}. Simpan snapshot dari tab 3 · Generate / Export.")
        return
    labels = {s["path"]: s["label"] for s in snaps}
    paths = list(labels)
    c1, c2 = st.columns(2)
    pa = c1.selectbox("Periode A (pembanding / lebih lama)", paths, index=min(1, len(paths) - 1), format_func=labels.get, key="cs_ak_cmp_a")
    pb = c2.selectbox("Periode B (yang dianalisis / lebih baru)", paths, index=0, format_func=labels.get, key="cs_ak_cmp_b")
    if pa == pb:
        st.info("Pilih dua snapshot yang berbeda.")
        return
    try:
        res = store.compare(store.load_snapshot(pa), store.load_snapshot(pb))
    except Exception as e:
        st.error(f"Snapshot tidak dapat dibandingkan: {e}")
        return
    la, lb = labels[pa], labels[pb]
    for n in res["notes"]:
        st.caption("ℹ️ " + n)
    st.markdown(ui.section_title("Total hit per kategori"), unsafe_allow_html=True)
    st.markdown(ui.compare_bars(res["totals"] + [("Total", *res["grand"])], la, lb), unsafe_allow_html=True)
    for k, dims in res["sections"].items():
        st.markdown(ui.section_title(ak.SECTION_TITLE[k]), unsafe_allow_html=True)
        for d, r in dims.items():
            st.markdown(f"**{ak.DIM_LABEL[d]}**")
            st.markdown(ui.compare_bars(r["both"], la, lb, empty="Tidak ada label yang muncul di kedua periode"), unsafe_allow_html=True)
            if r["only_a"] or r["only_b"]:
                st.caption("Hanya di top 5 salah satu periode (bukan berarti 0 di periode lain): "
                           + (f"A saja: {', '.join(r['only_a'])}. " if r["only_a"] else "") + (f"B saja: {', '.join(r['only_b'])}." if r["only_b"] else ""))


def render_akamai(up):
    """up = file dari sidebar (UPLOAD AKAMAI). Tab mengikuti pola IPS."""
    parsed = _load(up)
    tabs = st.tabs(["📊 Dashboard", "🔀 Compare", "1 · Upload & Mapping", "2 · Validation", "3 · Generate / Export"])
    with tabs[0]:
        _tab_dashboard(parsed)
    with tabs[1]:
        _tab_compare()
    with tabs[2]:
        _tab_mapping(parsed)
    with tabs[3]:
        _tab_validation(parsed)
    with tabs[4]:
        _tab_export(parsed)
