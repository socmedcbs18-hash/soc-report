"""SOC Incident Report (bulanan) - UI Streamlit. SELF-CONTAINED: hanya mengimpor paket soc_incident.
Alur: upload export Ivanti -> deteksi cutover state machine -> dashboard per era -> snapshot bulanan -> bandingkan bulan -> export Excel (opsional)."""
import tempfile
from datetime import datetime, time
from pathlib import Path

import pandas as pd
import streamlit as st

from soc_incident import fmt, snapshot as snap, ui
from soc_incident.loader import LoaderError, detect_mapping, normalize, read_table
from soc_incident.processor import ERA_LABEL, ERA_METRICS, analyze, detect_cutover, executive_headlines, fmt_metric, to_excel

KEYS = ("si_raw", "si_df", "si_notes", "si_file_key", "si_res", "si_sig", "si_xlsx")
MIME_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _clear_cb():
    """Hapus file dari sesi. Snapshot di database/ TIDAK disentuh."""
    for k in list(st.session_state.keys()):
        if k in KEYS or str(k).startswith("si_cut_"):
            del st.session_state[k]
    st.session_state["si_up_n"] = st.session_state.get("si_up_n", 0) + 1


def _load(up):
    key = (up.name, up.size) if up is not None else None
    if st.session_state.get("si_file_key") != key:
        for k in KEYS:
            st.session_state.pop(k, None)
        st.session_state["si_file_key"] = key
        if up is not None:
            try:
                raw, meta = read_table(up, up.name)
                df, notes = normalize(raw, detect_mapping(raw.columns))
                st.session_state.update({"si_raw": meta, "si_df": df, "si_notes": notes})
            except LoaderError as e:
                st.error(f"❌ {e}")
    return st.session_state.get("si_df")


def _sidebar_options(df):
    """Pengaturan cutover. Default = deteksi otomatis dari data."""
    det = detect_cutover(df)
    st.sidebar.markdown("**STATE MACHINE**")
    mode = st.sidebar.radio("Cutover state machine", ["auto", "manual", "none"], key="si_cut_mode",
                            format_func={"auto": "Otomatis dari data", "manual": "Atur manual", "none": "Tidak ada (satu era)"}.get,
                            help="Cutover = saat tiket mulai memakai state machine baru. Otomatis: terdeteksi dari field yang berhenti terisi.")
    cut, single = "auto", "all"
    if det["cutover"] is not None:
        st.sidebar.caption(f"Terdeteksi: {det['cutover']:%d %b %Y %H:%M:%S} (tiket {det['first_ticket']}; tiket lama terakhir {det['last_old_ticket']}).")
    else:
        st.sidebar.caption(f"Tidak terdeteksi: {det['reason']}")
    if mode == "manual":
        base = det["cutover"] or df["created"].min() + pd.Timedelta(days=1)
        d = st.sidebar.date_input("Tanggal cutover", value=base.date(), key="si_cut_date")
        t = st.sidebar.time_input("Jam cutover", value=base.time().replace(microsecond=0), key="si_cut_time")
        cut = pd.Timestamp(datetime.combine(d, t if isinstance(t, time) else time(0, 0)))
    elif mode == "none":
        cut = None
    if cut is None or (isinstance(cut, str) and det["cutover"] is None):
        single = st.sidebar.radio("Seluruh bulan memakai state machine", ["all", "new", "old"], key="si_cut_single",
                                  format_func={"all": "Tidak diketahui", "new": "Baru", "old": "Lama"}.get,
                                  help="Pilih 'Baru' untuk bulan setelah cutover (mis. Oktober) agar bisa dibandingkan apel-ke-apel dengan era baru September.")
    return cut, single


def _cards(res):
    S, T, eras = res["stats"], res["total"], res["eras"]
    two = eras == ["old", "new"]
    if two:
        o, n = S["old"], S["new"]
        return [("Total tiket", fmt.num(T["tickets"]), f"lama {fmt.num(o['tickets'])} · baru {fmt.num(n['tickets'])}", None),
                ("Tiket per hari", f"{fmt.num(o['per_day'], 1)} → {fmt.num(n['per_day'], 1)}", "lama → baru", ui.ACCENT),
                ("P1 (High)", f"{fmt.num(o['p1'])} → {fmt.num(n['p1'])}", f"porsi {fmt.pct(o['p1_share'])} → {fmt.pct(n['p1_share'])}", ui.PRIO_COLORS[1]),
                ("Melewati batas respons", f"{fmt.num(T['breach_n'])}", f"lama {fmt.pct(o['breach_rate'])} · baru {fmt.pct(n['breach_rate'])}", ui.WARN),
                ("Median ke Active", f"{fmt.minutes(o['resp_median'])} → {fmt.minutes(n['resp_median'])}", "MTTR (Created→Active)", None),
                ("Punya waktu Resolved", f"{fmt.pct(o['resolved_cov'], 0)} → {fmt.pct(n['resolved_cov'], 0)}", "lama → baru", None)]
    return [("Total tiket", fmt.num(T["tickets"]), f"{fmt.num(T['per_day'], 1)} tiket/hari", None),
            ("P1 (High)", fmt.num(T["p1"]), f"porsi {fmt.pct(T['p1_share'])}", ui.PRIO_COLORS[1]),
            ("Melewati batas respons", fmt.num(T["breach_n"]), fmt.pct(T["breach_rate"]), ui.WARN),
            ("Median ke Active", fmt.minutes(T["resp_median"]), "MTTR (Created→Active)", None),
            ("Punya waktu Resolved", fmt.pct(T["resolved_cov"], 0), f"Closed tanpa Resolved: {fmt.num(T['closed_no_resolve'])}", None)]


def _tab_summary(res):
    two = res["eras"] == ["old", "new"]
    if two:
        st.info(f"Bulan ini memuat **dua state machine**. Perpindahan terdeteksi **{res['cutover']:%d %b %Y %H:%M}** "
                f"({'diatur manual' if res['cutover_manual'] else 'otomatis dari data'}). Angka dilaporkan per era; jangan dijumlahkan atau dibandingkan langsung tanpa membaca catatan.")
    with st.container(border=True):
        st.markdown(ui.section_title("Ringkasan untuk manajemen"), unsafe_allow_html=True)
        for line in executive_headlines(res):
            st.markdown(f"- {line}")
    st.markdown(ui.kpi_cards(_cards(res)), unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(ui.section_title("Tiket per hari", "Abu-abu = state machine lama · Biru = state machine baru · ▲ = hari cutover" if two else None), unsafe_allow_html=True)
        st.markdown(ui.daily_timeline(res["daily"], res["eras"], res["cutover"]), unsafe_allow_html=True)
    if two:
        with st.container(border=True):
            st.markdown(ui.section_title("Perbandingan per era", "Metrik dihitung dari data yang tersedia di masing-masing era"), unsafe_allow_html=True)
            rows = [(lab, [fmt_metric(res["stats"][e].get(k), kind) for e in res["eras"]]) for k, lab, kind in ERA_METRICS]
            st.markdown(ui.era_table([ERA_LABEL[e] for e in res["eras"]], rows), unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(ui.section_title("Insight otomatis", "Dibuat dari angka di dashboard; bersifat indikatif, bukan kesimpulan akhir"), unsafe_allow_html=True)
        st.markdown(ui.insight_blocks(res["insights"]), unsafe_allow_html=True)
    for n in res["notes"]:
        st.warning(n)


def _tab_sla(res):
    S = res["stats"]
    st.markdown(ui.section_title("Metrik state machine (Logged → Active → Contained → Resolved → Closed)", "Hijau = tersedia · Kuning = sebagian tiket · Abu-abu = tidak ada data"), unsafe_allow_html=True)
    cov = res["total"]["resolved_cov"]
    st.markdown(ui.state_flow([
        ("Logged", "Created On", "Tersedia", True),
        ("Active", "MTTR = Created→Active", "Tersedia", True),
        ("Contained", "MTTC = Active→Contained", "Tidak ada timestamp", False),
        ("Resolved", "Created→Resolved (bukan MTRV)", f"Terisi {fmt.pct(cov, 0)} tiket", None if cov < 99 else True),
        ("Closed", "Created→Closed", "Tersedia", True)]), unsafe_allow_html=True)
    th = res["threshold"]
    if th["consistent"]:
        st.caption(f"Pengamatan: tiket dengan waktu ke Active ≤ {fmt.num(th['max_met'])} mnt berstatus MET dan ≥ {fmt.num(th['min_breached'])} mnt BREACHED pada flag Ivanti "
                   "(batas tersirat dari data, bukan aturan yang ditetapkan modul ini).")
    st.markdown("**Respons SLA per prioritas**")
    sp = res["sla_priority"].copy()
    sp["Median_mnt"], sp["P90_mnt"] = sp["Median_mnt"].round(1), sp["P90_mnt"].round(1)
    st.dataframe(sp.rename(columns={"Median_mnt": "Median (mnt)", "P90_mnt": "P90 (mnt)"}), use_container_width=True, hide_index=True)
    st.markdown("**Tiket yang melewati batas respons**" + f" ({fmt.num(len(res['breaches']))})")
    if len(res["breaches"]):
        st.dataframe(res["breaches"].head(25), use_container_width=True, hide_index=True)
        with st.expander("Semua tiket yang melewati batas respons"):
            st.dataframe(res["breaches"], use_container_width=True, hide_index=True)
    else:
        st.caption("Tidak ada tiket yang melewati batas respons.")
    st.markdown("**Kelengkapan resolusi**")
    rows = [(ERA_LABEL[e], [fmt.num(S[e]["tickets"]), fmt.pct(S[e]["resolved_cov"]), fmt.minutes(S[e]["resolved_median"]),
                            fmt.num(S[e]["closed_no_resolve"]), fmt.minutes(S[e]["closed_median"])]) for e in res["eras"]]
    st.markdown(ui.era_table(["Tiket", "Punya Resolved", "Created→Resolved (median)", "Closed tanpa Resolved", "Created→Closed (median)"], rows).replace("Metrik", "Era"), unsafe_allow_html=True)
    st.caption("Created→Resolved dihitung hanya dari tiket yang punya waktu Resolved, sehingga era dengan cakupan rendah tidak bisa dibandingkan langsung. "
               "Resolution SLA breach pada data = " + (fmt.num(res["total"]["reso_breach_n"]) if res["total"]["reso_breach_n"] is not None else "tidak tersedia") + " tiket.")


def _tab_workload(res):
    eras = res["eras"]
    st.markdown(ui.section_title("Ringkasan mingguan (Minggu–Sabtu)", "Pekan pertama/terakhir bisa sebagian dari bulan"), unsafe_allow_html=True)
    st.dataframe(res["weekly"], use_container_width=True, hide_index=True)
    c1, c2 = st.columns(2)
    with c1, st.container(border=True):
        st.markdown(ui.section_title("Beban tiket per analis", "Jumlah tiket, bukan penilaian kinerja"), unsafe_allow_html=True)
        o = res["owners"]
        st.markdown(ui.hbar_list([(i, r["Total"], r["Total"] / o["Total"].sum() * 100) for i, r in o.iterrows()]), unsafe_allow_html=True)
    with c2, st.container(border=True):
        st.markdown(ui.section_title("Komposisi prioritas"), unsafe_allow_html=True)
        pr = res["priority"]
        for e in eras:
            st.caption(ERA_LABEL[e])
            colors = [ui.PRIO_COLORS.get(3 if "P3" in i else 2 if "P2" in i else 1, ui.OLD) for i in pr.index]
            st.markdown(ui.stacked_share([(i, int(pr.loc[i, e]), c) for i, c in zip(pr.index, colors)]), unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(ui.section_title("Jam pembuatan tiket", "Berdasarkan Created On"), unsafe_allow_html=True)
        st.markdown(ui.legend([(ERA_LABEL[e], ui.OLD if e == "old" else ui.ACCENT) for e in eras]) if len(eras) > 1 else "", unsafe_allow_html=True)
        st.markdown(ui.hourly_chart(res["hourly"], eras), unsafe_allow_html=True)
    c3, c4 = st.columns(2)
    with c3:
        st.markdown("**Sumber tiket**")
        st.dataframe(res["sources"].reset_index(), use_container_width=True, hide_index=True)
    with c4:
        st.markdown("**Tipe insiden**")
        st.dataframe(res["incident_type"].reset_index(), use_container_width=True, hide_index=True)
    st.markdown("**Status akhir tiket**")
    st.dataframe(res["status"].reset_index(), use_container_width=True, hide_index=True)


def _tab_data(res, meta):
    st.markdown(ui.section_title("Perubahan skema yang terdeteksi", "Persentase tiket yang field-nya terisi, per era"), unsafe_allow_html=True)
    sc = res["schema"].copy()
    st.dataframe(sc, use_container_width=True, hide_index=True)
    d = res["detection"]
    st.caption(f"Deteksi otomatis: {d['reason']}" + (f" Tiket skema baru pertama {d['first_ticket']} ({res['cutover']:%d %b %Y %H:%M:%S}); tiket skema lama terakhir {d['last_old_ticket']}." if d["cutover"] is not None else "")
               + " Field Cause Code berhenti terisi sedikit setelah cutover; lihat kolom 'Terakhir terisi'.")
    st.markdown(ui.section_title("Kategori insiden (hanya era lama / skema lama)", "Sub_Issue dan Cause Code tidak lagi terisi pada skema baru"), unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        s = res["sub_issue"]
        st.markdown(ui.hbar_list([(r["Sub_Issue"], r["Tiket"], r["Tiket"] / s["Tiket"].sum() * 100) for _, r in s.head(10).iterrows()]), unsafe_allow_html=True)
    with c2:
        st.dataframe(res["cause_code"], use_container_width=True, hide_index=True)
        st.caption("Cause Code ditampilkan sebagaimana dicatat Ivanti; nilainya tidak otomatis berarti insiden terkonfirmasi.")
    st.markdown(ui.section_title("Kualitas data"), unsafe_allow_html=True)
    p = res["period"]
    st.markdown(f"- File: **{meta['filename']}** — {fmt.num(meta['rows'])} baris, {len(meta['columns'])} kolom\n"
                f"- Periode (bulan terbanyak): **{fmt.month_name(p['month'])} {p['year']}**; tiket pertama {p['first_ticket_at']:%d %b %H:%M}, terakhir {p['last_ticket_at']:%d %b %H:%M}\n"
                f"- Tiket ditandai maintenance: {fmt.num(res['maintenance'])}")


def _tab_compare():
    snaps = snap.list_snapshots()
    if not snaps:
        st.info("Belum ada snapshot. Simpan snapshot bulan ini dari tab 💾 Simpan & Export; setelah ada minimal dua bulan, perbandingan muncul di sini.")
        return
    labels = {x["path"]: x["label"] for x in snaps}
    paths = list(labels)
    with st.expander("Lihat ringkasan snapshot tersimpan"):
        one = st.selectbox("Snapshot", paths, format_func=labels.get, key="si_view_snap")
        v = snap.load_snapshot(one)
        for h in v.get("headlines", []):
            st.markdown(f"- {h}")
        st.markdown(ui.insight_blocks(v.get("insights", [])), unsafe_allow_html=True)
    if len(snaps) < 2:
        st.info("Perbandingan butuh minimal 2 snapshot bulan berbeda.")
        return
    c1, c2 = st.columns(2)
    pa = c1.selectbox("Bulan A (pembanding)", paths, index=min(1, len(paths) - 1), format_func=labels.get, key="si_cmp_a")
    pb = c2.selectbox("Bulan B (dilihat)", paths, index=0, format_func=labels.get, key="si_cmp_b")
    if pa == pb:
        st.info("Pilih dua bulan yang berbeda.")
        return
    basis = st.radio("Dasar perbandingan", ["latest", "total"], horizontal=True, key="si_cmp_basis",
                     format_func={"latest": "Era state machine terbaru saja (disarankan)", "total": "Total bulan"}.get)
    a, b = snap.load_snapshot(pa), snap.load_snapshot(pb)
    c = snap.compare_months(a, b, basis)
    for n in c["notes"]:
        st.warning(n)
    rows = []
    for r in c["table"]:
        d = r["Δ"]
        rows.append((r["Metrik"], fmt_metric(r["A"], r["kind"]), fmt_metric(r["B"], r["kind"]),
                     "–" if d is None else (fmt_metric(abs(d), r["kind"]) if r["kind"] != "pct" else fmt.num(abs(d), 1) + " poin"),
                     None if d is None else ("up" if d > 0 else "down" if d < 0 else "flat")))
    with st.container(border=True):
        st.markdown(ui.section_title(f"{labels[pa]} → {labels[pb]}", f"A: {c['label_a']} · B: {c['label_b']}"), unsafe_allow_html=True)
        st.markdown(ui.compare_rows(rows, "A", "B"), unsafe_allow_html=True)
    st.caption("Arah ▲/▼ menunjukkan perubahan angka, bukan baik/buruk. Perubahan prioritas dan kelengkapan resolusi sebaiknya dibaca bersama catatan perubahan state machine.")


def _tab_save(res, meta):
    snaps = snap.list_snapshots()
    p = res["period"]
    exists = any(s["year"] == p["year"] and s["month"] == p["month"] for s in snaps)
    c1, c2 = st.columns([1, 2])
    if c1.button(("🔄 Perbarui" if exists else "💾 Simpan") + f" snapshot {fmt.month_name(p['month'])} {p['year']}", key="si_save_snap"):
        path = snap.save_snapshot(res, meta["filename"], executive_headlines(res))
        st.success(f"Tersimpan: {path.name}. Bisa dibandingkan dengan bulan lain tanpa upload ulang.")
        st.rerun()
    c2.caption("Snapshot hanya berisi angka agregat (tanpa nama customer/tiket) di folder database/soc_incident/snapshots/. " + ("Sudah ada untuk bulan ini; tombol memperbarui." if exists else "Belum tersimpan."))
    st.markdown("**Export Excel (opsional)**")
    if st.button("Siapkan Excel", key="si_make_xlsx"):
        out = Path(tempfile.mkdtemp(prefix="soc_incident_")) / f"SOC_Incident_Report_{p['year']}_{p['month']:02d}.xlsx"
        to_excel(res, out)
        st.session_state["si_xlsx"] = (out.name, out.read_bytes())
    if st.session_state.get("si_xlsx"):
        name, data = st.session_state["si_xlsx"]
        kw = dict(file_name=name, mime=MIME_XLSX, key="si_dl_xlsx")
        try:
            major, minor = (int(x) for x in st.__version__.split(".")[:2])
            ign = (major, minor) >= (1, 43)
        except (ValueError, AttributeError):
            ign = False
        st.download_button("⬇️ Unduh Excel", data, on_click="ignore", **kw) if ign else st.download_button("⬇️ Unduh Excel", data, **kw)
        st.caption("Excel tidak memuat kolom nama customer.")
    if snaps:
        st.markdown("**Hapus snapshot tersimpan**")
        labels = {x["path"]: x["label"] for x in snaps}
        pick = st.selectbox("Snapshot", list(labels), format_func=labels.get, key="si_del_pick")
        ok = st.checkbox("Ya, hapus snapshot ini", key="si_del_confirm")
        st.button("Hapus snapshot", key="si_del_snap", disabled=not ok, on_click=_delete_cb, args=(pick,))
    msg = st.session_state.pop("si_del_msg", None)
    if msg:
        st.success(msg)


def _delete_cb(path):
    try:
        snap.delete_snapshot(path)
        st.session_state["si_del_msg"] = "Snapshot dihapus."
    except (OSError, ValueError) as e:
        st.session_state["si_del_msg"] = f"Gagal menghapus: {e}"
    st.session_state.pop("si_del_confirm", None)


def render_soc_incident_dashboard():
    st.title("SOC Insiden Bulanan (Ivanti)")
    st.caption("Export tiket insiden Ivanti → deteksi perpindahan state machine → dashboard per era → snapshot bulanan untuk perbandingan. Angka selalu dari file yang di-upload.")
    st.sidebar.subheader("Insiden Bulanan Ivanti")
    up = st.sidebar.file_uploader("Export insiden Ivanti (XLSX / CSV)", type=["xlsx", "xls", "csv"], key=f"si_upload_{st.session_state.get('si_up_n', 0)}",
                                  help="Satu file = satu bulan penuh.")
    if up is not None:
        st.sidebar.button("🗑️ Hapus file ini (upload file lain)", key="si_clear", on_click=_clear_cb,
                          help="Hanya menghapus file dari sesi. Snapshot bulanan yang sudah disimpan tetap ada.")
    df = _load(up)
    tabs = st.tabs(["📌 Ringkasan Eksekutif", "⏱️ SLA & State Machine", "👥 Beban Kerja & Pola", "🧩 Skema & Kualitas Data", "🔀 Bandingkan Bulan", "💾 Simpan & Export"])
    if df is None:
        with tabs[0]:
            st.info("Upload export insiden Ivanti satu bulan penuh di sidebar. Snapshot bulan sebelumnya (jika ada) tetap bisa dibandingkan di tab 🔀.")
        with tabs[4]:
            _tab_compare()
        return
    cut, single = _sidebar_options(df)
    sig = (st.session_state["si_file_key"], str(cut), single)
    if st.session_state.get("si_sig") != sig:
        st.session_state["si_res"] = analyze(df, cutover=cut, single_era=single)
        st.session_state["si_sig"] = sig
    res, meta = st.session_state["si_res"], st.session_state["si_raw"]
    for n in st.session_state.get("si_notes", []):
        st.warning(n)
    with tabs[0]:
        _tab_summary(res)
    with tabs[1]:
        _tab_sla(res)
    with tabs[2]:
        _tab_workload(res)
    with tabs[3]:
        _tab_data(res, meta)
    with tabs[4]:
        _tab_compare()
    with tabs[5]:
        _tab_save(res, meta)
