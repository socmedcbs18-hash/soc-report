"""Cybersecurity Monthly Report - Report Control Center (Streamlit).
Alur: Dashboard (live/tersimpan) | Upload & Mapping -> Validation -> Threat Intelligence -> Generate (opsional).
Modul SELF-CONTAINED: tidak mengimpor apa pun dari core/cynet/ioc/sr_sla milik modul lain."""
from datetime import date

import pandas as pd
import streamlit as st

from pathlib import Path

from cybersec_report.core import reputation as rep_mod
from cybersec_report.core import snapshot as snapshot_mod
from cybersec_report.core.config_loader import (KEY_NAMES, cache_dir, data_dir, find_api_key, load_device_environment,
                                                load_report_structure, load_settings, mask_key, save_device_environment,
                                                save_env_keys)
from cybersec_report.compare_view import render_compare
from cybersec_report.core.compare import pick_section
from cybersec_report.dashboard_view import render_ips_dashboard
from cybersec_report.sources_view import menu_entries, render_source_placeholder
from cybersec_report.akamai_view import render_akamai, sidebar_upload as akamai_sidebar_upload
from cybersec_report.core.fmt import fmt_int, fmt_pct
from cybersec_report.core.ingestion import IngestionError
from cybersec_report.core.period import MONTH_ID
from cybersec_report.pipeline import IPSPipeline, build_providers
from cybersec_report.threat_intel import PLANNED_PROVIDERS, PROVIDERS

ICON = {"PASS": "✅", "WARNING": "⚠️", "FAIL": "❌"}
NO_MAP = "-- tidak dipetakan --"


def _status_banner(status, text):
    {"PASS": st.success, "WARNING": st.warning, "FAIL": st.error}[status](f"{ICON[status]} {status} — {text}")


def _checks_table(res):
    df = pd.DataFrame(res["checks"])
    df.insert(0, "", df["status"].map(ICON))
    st.dataframe(df[["", "status", "check", "detail"]], use_container_width=True, hide_index=True)


def _api_overrides():
    return {env: st.session_state.get(f"cs_key_{name}", "").strip() for name, env in KEY_NAMES.items()
            if st.session_state.get(f"cs_key_{name}", "").strip()}


def _key_status(name):
    key, src = find_api_key(PROVIDERS[name].env_key, _api_overrides())
    return key, src


def _api_key_panel():
    with st.sidebar.expander("🔑 API Key (VirusTotal / AbuseIPDB)"):
        st.caption(f"Disimpan di: `{data_dir() / '.env'}` (folder database/ tidak ikut terhapus saat kode diganti). "
                   "Key tidak pernah dikirim ke mana pun selain ke provider masing-masing.")
        labels = {"virustotal": "VirusTotal API key", "abuseipdb": "AbuseIPDB API key"}
        for name, label in labels.items():
            key, src = _key_status(name)
            st.text_input(label, type="password", key=f"cs_key_{name}", placeholder="kosong = pakai yang sudah tersimpan",
                          help="Isi lalu klik Simpan. Kolom dikosongkan tidak akan menghapus key yang tersimpan.")
            st.caption(f"{'✅ terdeteksi ' + mask_key(key) + ' — ' + str(src) if key else '⚠️ belum diisi'}")
        st.button("Simpan ke .env", key="cs_save_keys", on_click=_save_keys_cb)
        msg = st.session_state.pop("cs_key_msg", None)
        if msg:
            (st.success if msg[0] == "ok" else st.info)(msg[1])


def _save_keys_cb():
    """Callback (jalan SEBELUM widget dibuat ulang) agar kolom input boleh dikosongkan setelah simpan."""
    typed = {env: st.session_state.get(f"cs_key_{n}", "") for n, env in KEY_NAMES.items()}
    if any(v.strip() for v in typed.values()):
        path = save_env_keys(typed)
        for n in KEY_NAMES:
            st.session_state[f"cs_key_{n}"] = ""
        st.session_state["cs_key_msg"] = ("ok", f"Tersimpan di {path}")
    else:
        st.session_state["cs_key_msg"] = ("info", "Tidak ada key baru yang diisi.")


def _sidebar():
    s = load_settings()
    st.sidebar.subheader("Cybersecurity Monthly Report")
    st.sidebar.markdown("**SUMBER DATA**")
    entries = menu_entries()
    ids = [i for i, _ in entries]
    by_id = dict(entries)
    source = st.sidebar.radio("Pilih sumber", ids, key="cs_source",
                              format_func=lambda i: ("✅ " if by_id[i].get("implemented") else "⏳ ") + by_id[i]["title"])
    st.sidebar.caption("✅ = sudah bisa dari data upload · ⏳ = menu aktif, menunggu data mentah dari tim terkait (halaman berisi contoh dari deck referensi).")
    st.sidebar.markdown("**UPLOAD IPS**")
    up = st.sidebar.file_uploader("IPS / Firewall (CSV, XLSX, XLS)", type=["csv", "xlsx", "xls"],
                                  key=f"cs_upload_ips_{st.session_state.get('cs_up_n', 0)}",
                                  help="Boleh berisi beberapa hostname sekaligus; otomatis dipisah per hostname.")
    if up is not None:
        st.sidebar.button("🗑️ Hapus file ini (upload file lain)", key="cs_clear_upload", on_click=_clear_upload_cb,
                          help="Hanya menghapus file dari sesi. Cache reputasi IP, snapshot bulanan, dan API key TETAP tersimpan.")
    ak_up = akamai_sidebar_upload()
    st.sidebar.markdown("**THREAT INTELLIGENCE**")
    _api_key_panel()
    enabled = {}
    for name, cls in PROVIDERS.items():
        has_key = bool(_key_status(name)[0])
        enabled[name] = st.sidebar.checkbox(f"Enable {name} " + ("(key terdeteksi)" if has_key else "(API key belum diisi)"),
                                            value=True, key=f"cs_en_{name}")
    for name in PLANNED_PROVIDERS:
        st.sidebar.checkbox(f"Enable {name} (belum tersedia)", value=False, disabled=True, key=f"cs_en_{name}")
    rep = s["reputation"]
    strat = st.sidebar.radio("Strategi lookup", ["failover", "all"], index=0 if rep.get("strategy", "failover") == "failover" else 1,
                             format_func=lambda x: {"failover": "Failover — satu provider sampai kuota habis, lalu pindah (hemat token)",
                                                    "all": "Semua provider untuk setiap IP (boros token)"}[x], key="cs_strategy")
    default_order = rep.get("provider_order", list(PROVIDERS))
    first = st.sidebar.selectbox("Provider pertama dipakai", default_order, index=0, key="cs_first_provider",
                                 disabled=strat != "failover")
    order = [first] + [n for n in default_order if n != first]
    max_ips = st.sidebar.number_input("Maks. IP yang dicek (0 = semua IP publik)", min_value=0, value=rep["max_ips_default"],
                                      step=10, key="cs_max_ips")
    ttl = st.sidebar.number_input("Umur cache reputasi (jam)", min_value=1, value=int(rep["cache_ttl_hours"]), step=24, key="cs_ttl",
                                  help="IP yang sudah dicek dalam rentang ini dipakai ulang dari cache tanpa memakai token (default 168 jam = 7 hari).")
    s["reputation"]["cache_ttl_hours"] = int(ttl)
    return up, enabled, int(max_ips), s, {"strategy": strat, "provider_order": order, "cache_ttl_hours": int(ttl)}, source, ak_up


def _clear_upload_cb():
    """Callback tombol hapus: reset sesi upload saja. Folder database/ (cache reputasi, snapshot, .env) tidak disentuh."""
    for k in list(st.session_state.keys()):
        if k in ("cs_pl", "cs_sig", "cs_result", "cs_manual", "cs_file_key", "cs_split") or str(k).startswith(("cs_map_", "cs_env_")):
            del st.session_state[k]
    st.session_state["cs_up_n"] = st.session_state.get("cs_up_n", 0) + 1  # key uploader baru = uploader kosong


SPLIT_LABEL = {"device": "Per hostname (disarankan) — satu dashboard & satu snapshot per hostname",
               "none": "Gabungan semua hostname — satu section",
               "environment": "Per environment (butuh mapping device → environment)"}


def _load_pipeline(up):
    """Pipeline dibuat ulang hanya bila file berubah."""
    key = (up.name, up.size) if up is not None else None
    if st.session_state.get("cs_file_key") != key:
        for k in ("cs_pl", "cs_sig", "cs_result", "cs_manual"):
            st.session_state.pop(k, None)
        st.session_state["cs_file_key"] = key
        if up is not None:
            pl = IPSPipeline()
            try:
                pl.ingest(up, up.name)
                st.session_state["cs_pl"] = pl
            except IngestionError as e:
                st.error(f"❌ {e}")
    return st.session_state.get("cs_pl")


def _tab_upload(pl):
    m = pl.meta
    st.success(f"✓ File loaded: **{m['filename']}** — {m['rows']:,} record, {len(m['columns'])} kolom"
               + (f", delimiter `{m['delimiter']}`" if m.get("delimiter") else ""))
    sch = pl.schema
    st.markdown("**Column mapping (otomatis, hanya kecocokan persis)**")
    st.dataframe(pd.DataFrame([{"Canonical field": k, "Kolom raw": v, "Confidence": "high"} for k, v in sch["mapping"].items()]),
                 use_container_width=True, hide_index=True)
    manual = st.session_state.setdefault("cs_manual", {})
    need = list(dict.fromkeys(sch["missing_required"] + list(sch["conflicts"]) + sch["missing_recommended"]))
    if need:
        st.warning("Sistem TIDAK menebak kolom yang tidak dikenali. Petakan manual bila kolomnya ada di file:")
        for canon in need:
            opts = [NO_MAP] + list(dict.fromkeys(sch["conflicts"].get(canon, []) + sch["unmapped_columns"]))
            hint = ", ".join(f"{c} ({sc})" for c, sc in sch["suggestions"].get(canon, [])[:3])
            choice = st.selectbox(f"{canon}" + (" — WAJIB" if canon in sch["required"] else ""), opts, key=f"cs_map_{canon}",
                                  help=f"Saran kemiripan (tidak dipakai otomatis): {hint}" if hint else None)
            if choice != NO_MAP:
                manual[canon] = choice
            else:
                manual.pop(canon, None)
    dcol = pl.schema["mapping"].get("device")
    if dcol:
        st.markdown("**Hostname di file ini**")
        g = pl.norm.groupby("device", dropna=False).agg(Records=("count", "size"), Events=("count", "sum")).reset_index()
        g["Events"] = g["Events"].astype(int)
        st.dataframe(g.rename(columns={"device": "Hostname"}), use_container_width=True, hide_index=True)
        st.caption("Satu file boleh berisi banyak hostname — tidak perlu upload satu per satu. Tiap hostname menjadi dashboard dan snapshot bulanan sendiri "
                   "(mis. P1FWX0209-IPS-September-2026) sehingga bisa dibandingkan dengan bulan lain.")
    st.radio("Pemisahan data", list(SPLIT_LABEL), format_func=SPLIT_LABEL.get, key="cs_split",
             index=list(SPLIT_LABEL).index(pl.settings["ips"].get("split_by", "device")))
    st.markdown("**Label environment per hostname (opsional)**")
    st.caption("Kolom device hanya berisi kode (mis. P1FWX0209), bukan environment. Isi mis. DCI / NTT / GCP bila diketahui — hanya menjadi label "
               "tambahan; kosongkan jika tidak diketahui (tidak ditebak).")
    if dcol:
        saved, new = load_device_environment(), {}
        for dev in sorted(pl.raw[dcol].dropna().unique()):
            new[dev] = st.text_input(str(dev), value=saved.get(dev, ""), key=f"cs_env_{dev}")
        if st.button("Simpan mapping device", key="cs_save_env"):
            save_device_environment({**saved, **new})
            st.session_state.pop("cs_sig", None)
            st.success(f"Tersimpan di {data_dir() / 'device_environment.json'}")
    else:
        st.info("Kolom device tidak terdeteksi: semua data dianggap satu section.")


def _prepare(pl, up):
    manual = dict(st.session_state.get("cs_manual", {}))
    env = load_device_environment()
    split = st.session_state.get("cs_split") or pl.settings["ips"].get("split_by", "device")
    sig = (st.session_state["cs_file_key"], tuple(sorted(manual.items())), tuple(sorted(env.items())), split)
    if st.session_state.get("cs_sig") != sig:
        pl.settings["ips"]["split_by"] = split
        pl.prepare(manual_mapping=manual or None, device_env=env)
        if not pl.validation["blocking"]:
            pl.analyze()
            pl.apply_cached_reputation()  # IP yang pernah dicek (upload/bulan lalu) langsung terisi, tanpa token
        st.session_state["cs_sig"] = sig
        st.session_state.pop("cs_result", None)


def _apply_period(pl):
    with st.sidebar.expander("REPORT PERIOD", expanded=True):
        p = pl.period or {}
        if p.get("source") == "filename":
            st.caption("⚠️ Periode diambil dari nama file (data tidak punya timestamp). Konfirmasi/override di bawah.")
        today = date.today()
        override = st.checkbox("Override periode", value=not p.get("report_month"), key="cs_period_override")
        month = st.selectbox("Month", MONTH_ID, index=(p.get("report_month") or today.month) - 1, key="cs_month")
        year = st.number_input("Year", 2020, 2100, int(p.get("report_year") or today.year), key="cs_year")
        sd = st.date_input("Start date", p.get("start_date") or date(int(year), MONTH_ID.index(month) + 1, 1), key="cs_start")
        ed = st.date_input("End date", p.get("end_date") or date(int(year), MONTH_ID.index(month) + 1, 28), key="cs_end")
        if override:
            pl.set_period(MONTH_ID.index(month) + 1, int(year), sd, ed)
    return pl.period


def _tab_validation(pl):
    _status_banner(pl.validation["overall"], "Data quality" + (" — report DIBLOKIR (critical)" if pl.validation["blocking"] else ""))
    _checks_table(pl.validation)
    if pl.sections:
        st.markdown("**Cross validation (angka antar-tabel)**")
        _status_banner(pl.cross["overall"], f"{len(pl.cross['checks'])} pengecekan")
        with st.expander("Detail cross validation"):
            _checks_table(pl.cross)


def _tab_ti(pl, enabled, max_ips, s, rep_cfg):
    if not pl.sections:
        st.info("Validasi harus lolos dulu.")
        return
    pl.settings["reputation"].update(rep_cfg)  # strategi & urutan provider dari sidebar
    kinds = next((c["value"] for c in pl.validation["checks"] if c["check"] == "Source IP public/private"), {})
    sel, union = pl.plan_reputation(max_ips)
    est = rep_mod.estimate_minutes(len(union), {k: v for k, v in s["reputation"]["providers"].items() if enabled.get(k)})
    c1, c2, c3 = st.columns(3)
    c1.metric("Source IP publik (unik)", fmt_int(kinds.get("public", 0)))
    c2.metric("Private IP (dilewati)", fmt_int(kinds.get("private", 0)))
    c3.metric("Akan dicek", fmt_int(len(union)), help="Dibatasi 'Maks. IP yang dicek' di sidebar (per section). Seleksi berselang-seling: volume terbesar & Critical terbanyak")
    cov = []
    for a in pl.sections:
        prof = a["source_profile"]
        ev = float(prof[prof["Source IP"].isin(sel[a["name"]])]["Attack Count"].sum())
        cov.append(f"{a['name']}: {len(sel[a['name']])} IP = {ev / (a['total_events'] or 1) * 100:.1f}% event")
    st.caption(f"Mengapa {len(union)} dari {kinds.get('public', 0)} IP publik? Batas **Maks. IP yang dicek** di sidebar = {max_ips or 'semua'} per section "
               f"(default {s['reputation']['max_ips_default']}, 0 = semua). Cakupan: " + " · ".join(cov) + ". "
               "Menaikkan batas aman: IP yang sudah pernah dicek diambil dari cache (sesuai 'Umur cache' di sidebar) dan tidak memakai token lagi. "
               "Perhatikan kuota: VirusTotal gratis 4 request/menit dan ±500/hari; AbuseIPDB gratis ±1.000/hari. Failover pindah otomatis saat habis.")
    if rep_cfg["strategy"] == "failover":
        st.caption(f"Strategi **failover**: {' → '.join(rep_cfg['provider_order'])}. Satu provider dipakai sampai kuota/limit habis, lalu otomatis pindah; "
                   f"IP yang sudah ada di cache ({s['reputation']['cache_ttl_hours']} jam, provider mana pun) tidak memakai token. Estimasi ±{est} menit.")
    else:
        st.caption(f"Strategi **all**: setiap IP dicek ke semua provider aktif (lebih boros token). Estimasi ±{est} menit.")
    cache = rep_mod.ReputationCache(cache_dir() / "reputation.sqlite")
    ex_rows = [(n, cache.get_exhausted(n)) for n in PROVIDERS]
    for n, ex in ex_rows:
        if ex:
            from datetime import datetime, timezone
            until = datetime.fromtimestamp(ex["until"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            st.warning(f"{n}: kuota tercatat habis ({ex['reason']}), dilewati sampai {until}.")
    if any(ex for _, ex in ex_rows) and st.button("Reset status kuota (coba semua provider lagi)", key="cs_reset_quota"):
        cache.clear_exhausted()
        st.rerun()
    missing = [n for n in PROVIDERS if enabled.get(n) and not _key_status(n)[0]]
    if missing:
        st.warning(f"Provider unavailable / API key not configured: {', '.join(missing)}. Isi di sidebar → 🔑 API Key, "
                   f"atau tulis di file `{data_dir() / '.env'}` (VT_API_KEY=..., ABUSEIPDB_API_KEY=...).")
    if st.button("Run Reputation Check", type="primary", key="cs_run_rep", disabled=not any(enabled.values())):
        bar = st.progress(0.0, text="Memulai...")
        pl.run_reputation(enabled, max_ips, progress=lambda i, n: bar.progress(i / max(n, 1), text=f"IP {i}/{n}"),
                          api_overrides=_api_overrides())
        bar.progress(1.0, text="Selesai")
        st.session_state.pop("cs_result", None)
    if pl.lookup:
        stt = pl.lookup["stats"]
        rows = [{"Provider": n, "Request API (token terpakai)": v["api_calls"], "Berhasil": v["ok"], "Dari cache": v["cached"],
                 "Gagal": v["failed"], "Status": v["state"]} for n, v in stt["providers"].items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        for sw in stt.get("switches", []):
            st.info(f"🔁 Beralih {sw['from']} → {sw['to']} setelah {sw['after_api_calls']} request.")
        for line in pl.lookup["log"][:15]:
            st.caption(line)
        st.success("Hasil reputasi sudah tampil di tab 📊 Dashboard (klik 'Simpan snapshot' agar tersimpan bersama periode).")


def _delete_snapshot_cb(path):
    try:
        snapshot_mod.delete_snapshot(path)
        st.session_state["cs_del_msg"] = ("ok", "Snapshot dihapus. Cache reputasi IP tidak ikut terhapus.")
    except (OSError, ValueError) as e:
        st.session_state["cs_del_msg"] = ("err", f"Gagal menghapus: {e}")
    st.session_state.pop("cs_dash_source", None)
    st.session_state.pop("cs_del_confirm", None)


def _delete_snapshot_ui(path, label):
    with st.expander("🗑️ Hapus dashboard tersimpan ini"):
        st.caption(f"Menghapus snapshot **{label}** dari folder database/. Data upload asli dan cache reputasi IP tidak terpengaruh; "
                   "dashboard bisa dibuat lagi dengan upload ulang file-nya.")
        ok = st.checkbox("Ya, hapus snapshot ini", key="cs_del_confirm")
        st.button("Hapus snapshot", key="cs_del_snap", disabled=not ok, on_click=_delete_snapshot_cb, args=(path,))


def _tab_dashboard(pl):
    msg = st.session_state.pop("cs_del_msg", None)
    if msg:
        (st.success if msg[0] == "ok" else st.error)(msg[1])
    """Pilih sumber: upload saat ini (live) atau periode tersimpan. Export ke PPT/Excel opsional (tab Generate)."""
    live_ok = bool(pl is not None and pl.sections and pl.period and pl.period.get("report_month"))
    snaps = snapshot_mod.list_snapshots()
    options = (["live"] if live_ok else []) + [x["path"] for x in snaps]
    if not options:
        if pl is not None and not live_ok:
            st.info("Dashboard muncul setelah validasi lolos dan periode ditentukan.")
        else:
            st.info("Belum ada data. Upload file IPS di sidebar, atau generate/simpan sebuah periode agar bisa dibuka lagi di sini.")
        return
    labels = {"live": f"Upload saat ini — {pl.meta['filename']}" if live_ok else ""}
    labels.update({x["path"]: f"{x['label']} (tersimpan {x['saved_at'][:16].replace('T', ' ')})" for x in snaps})
    choice = st.selectbox("Tampilkan data", options, format_func=lambda o: labels[o], key="cs_dash_source")
    if choice == "live":
        vm = pl.view_model()
        label = f"{vm['period']['month_name']} {vm['period']['report_year']}"
        done = {(x["hostname"], x["year"], x["month"]) for x in snaps}
        per = vm["period"]
        names = [a["name"] for a in pl.sections]
        host_of = {a["name"]: a.get("hostname") or "ALL-HOSTS" for a in pl.sections}
        pick = st.multiselect("Hostname yang disimpan", names, default=names, key="cs_snap_pick")
        todo = [n for n in pick if (host_of[n], per["report_year"], per["report_month"]) not in done]
        c1, c2 = st.columns([1, 2])
        if c1.button(f"💾 Simpan snapshot {label} ({len(pick)} hostname)", key="cs_save_snap", disabled=not pick):
            paths = pl.save_dashboard_snapshot(names=pick)
            st.success("Tersimpan: " + ", ".join(Path(x).name for x in paths) + ". Bisa dibuka lagi & dibandingkan tanpa upload ulang.")
            st.rerun()
        c2.caption("Satu snapshot per hostname per bulan di folder database/. " +
                   (f"Belum tersimpan: {', '.join(host_of[n] for n in todo)}." if todo else "Semua yang dipilih sudah tersimpan (tombol memperbarui)."))
    else:
        try:
            vm = snapshot_mod.load_snapshot(choice)
        except Exception as e:
            st.error(f"Snapshot tidak dapat dibuka: {e}")
            return
    if choice != "live":
        _delete_snapshot_ui(choice, labels[choice])
    render_ips_dashboard(vm, key="cs_dash")
    st.caption("Export PowerPoint/Excel bersifat opsional di tab Generate. Sumber lain (Akamai, DLP, dst.) ada di menu sidebar.")


def _tab_compare():
    snaps = [x for x in snapshot_mod.list_snapshots() if x["source"] == "IPS"]
    if len(snaps) < 2:
        st.info("Perbandingan butuh minimal 2 snapshot IPS (hostname sama atau berbeda, bulan berbeda). "
                f"Saat ini tersimpan: {len(snaps)}. Simpan snapshot dari tab 📊 Dashboard.")
        return
    labels = {x["path"]: x["label"] for x in snaps}
    paths = list(labels)
    c1, c2 = st.columns(2)
    pa = c1.selectbox("Periode A (pembanding / lebih lama)", paths, index=min(1, len(paths) - 1), format_func=labels.get, key="cs_cmp_a")
    pb = c2.selectbox("Periode B (yang dianalisis / lebih baru)", paths, index=0, format_func=labels.get, key="cs_cmp_b")
    if pa == pb:
        st.info("Pilih dua snapshot yang berbeda.")
        return
    try:
        va, vb = snapshot_mod.load_snapshot(pa), snapshot_mod.load_snapshot(pb)
    except Exception as e:
        st.error(f"Snapshot tidak dapat dibuka: {e}")
        return
    render_compare(va, pick_section(va), vb, pick_section(vb), labels[pa], labels[pb],
                   stable_pct=load_settings()["mom"]["stable_threshold_pct"], key="cs_cmp")


MIME = {".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".json": "application/json"}


def _streamlit_supports_ignore():
    try:
        major, minor = (int(x) for x in st.__version__.split(".")[:2])
        return (major, minor) >= (1, 43)
    except (ValueError, AttributeError):
        return False


def _download(col, label, path, key):
    """Tombol unduh yang tidak 'Canceled'. Penyebab umum: klik memicu rerun sehingga URL file sementara
    kedaluwarsa sebelum browser selesai mengunduh. Perbaikan: (1) on_click="ignore" -> klik TIDAK rerun
    (Streamlit >= 1.43); (2) byte file ditahan di session_state agar isi/URL stabil antar-rerun."""
    p = Path(path)
    ck = f"cs_bytes_{key}_{p.stat().st_mtime_ns}"
    if ck not in st.session_state:
        for old in [k for k in st.session_state if str(k).startswith(f"cs_bytes_{key}_")]:
            del st.session_state[old]
        st.session_state[ck] = p.read_bytes()
    kw = dict(file_name=p.name, mime=MIME.get(p.suffix.lower()), key=f"cs_dl_{key}")
    if _streamlit_supports_ignore():
        col.download_button(label, st.session_state[ck], on_click="ignore", **kw)
    else:
        col.download_button(label, st.session_state[ck], **kw)


def _tab_generate(pl):
    ready = bool(pl.sections) and not pl.validation["blocking"] and pl.period and pl.period.get("report_month")
    if not ready:
        st.info("Belum bisa generate: validasi harus lolos dan periode harus ditentukan.")
        return
    st.caption("Export bersifat OPSIONAL — dashboard sudah tersedia di tab 📊 Dashboard. Generate juga menyimpan snapshot dashboard periode ini.")
    override = False
    if pl.cross["blocking"]:
        st.error("Cross-validation mismatch. Report diblokir.")
        override = st.checkbox("Override (hasilkan dengan WARNING)", key="cs_override")
    save_hist = st.checkbox("Simpan KPI periode ini untuk perbandingan bulan depan (MoM)", value=True, key="cs_savehist")
    if st.button("Generate Report (PPT + Excel)", type="primary", key="cs_generate", disabled=pl.cross["blocking"] and not override):
        with st.spinner("Membuat PPT, Excel, dan audit..."):
            try:
                st.session_state["cs_result"] = pl.generate(allow_override=override, save_history=save_hist)
            except Exception as e:
                st.error(f"❌ {e}")
    res = st.session_state.get("cs_result")
    if not res:
        return
    rc = res["reconciliation"]
    c = st.columns(3)
    c[0].metric("Raw total", fmt_int(rc["raw_total"]))
    c[1].metric("Analytics total", fmt_int(rc["analytics_total"]))
    c[2].metric("PPT total", fmt_int(rc["ppt_total"]))
    (st.success if rc["match"] else st.error)("Raw total == Analytics total == PPT total" if rc["match"] else "TIDAK SAMA — jangan distribusikan PPT ini")
    _status_banner(res["ppt_verification"]["overall"], f"Verifikasi PPT terhadap analytics ({len(res['ppt_verification']['checks'])} pengecekan)")
    if res["override_used"]:
        st.warning("Report dibuat dengan override cross-validation.")
    if res.get("dashboard_snapshot"):
        st.success("Dashboard periode ini tersimpan — buka tab 📊 Dashboard, atau pilih lagi nanti dari daftar periode.")
    labels = {"pptx": "⬇️ PowerPoint", "summary": "⬇️ Excel Summary", "ioc": "⬇️ IOC Reputation (Excel)",
              "audit": "⬇️ Audit (JSON)", "validation": "⬇️ Validation Report (Excel)"}
    cols = st.columns(len(labels))
    for col, (key, label) in zip(cols, labels.items()):
        _download(col, label, res["files"][key], key)
    st.caption(f"Semua file juga tersimpan otomatis di: `{Path(res['files']['pptx']).parent}` — bila unduhan browser gagal, ambil langsung dari folder ini.")


def render_cybersec_report_dashboard():
    st.title("Cybersecurity Monthly Report")
    st.caption("Raw data → validasi → analytics → threat intelligence → dashboard (PowerPoint/Excel opsional). Angka selalu dari raw data yang di-upload.")
    up, enabled, max_ips, s, rep_cfg, source, ak_up = _sidebar()
    pl = _load_pipeline(up)
    if pl is not None:
        _prepare(pl, up)
        _apply_period(pl)
    if source == "akamai":
        render_akamai(ak_up)
        return
    if source != "ips":
        render_source_placeholder(dict(menu_entries())[source])
        return
    tab_names = ["📊 Dashboard", "🔀 Compare", "1 · Upload & Mapping", "2 · Validation", "3 · Threat Intelligence", "4 · Generate / Export"]
    tabs = st.tabs(tab_names)
    with tabs[0]:
        _tab_dashboard(pl)
    with tabs[1]:
        _tab_compare()
    if pl is None:
        for t in tabs[2:]:
            with t:
                st.info("Upload file IPS di sidebar untuk memulai.")
        return
    with tabs[2]:
        _tab_upload(pl)
    with tabs[3]:
        _tab_validation(pl)
    with tabs[4]:
        _tab_ti(pl, enabled, max_ips, s, rep_cfg)
    with tabs[5]:
        _tab_generate(pl)
