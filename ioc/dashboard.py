"""
IOC Scoring Dashboard
=========================================================
UI Streamlit untuk verifikasi IP dari log firewall - cek ke GitHub Threat
Feed (gratis, tanpa API key), VirusTotal & AbuseIPDB (opsional, butuh API
key). SELF-CONTAINED - tidak mengimpor apapun dari app.py/core/ (SOC) atau
cynet/, sesuai prinsip modular yang sama dengan modul CyNET.
"""

import io

import pandas as pd
import streamlit as st

from ioc.threat_feeds import DEFAULT_FEEDS, get_feeds, check_ips_against_feeds
from ioc.virustotal import check_ips_virustotal
from ioc.abuseipdb import check_ips_abuseipdb
from ioc.abusech import check_ips_abusech
from ioc.enrichment import check_ips_enrichment
from ioc.scorer import combine_and_score


def _extract_ips_from_upload(uploaded_file):
    """Terima file .csv/.xlsx/.txt - cari kolom yang isinya kelihatan IP,
    ATAU kalau .txt anggap 1 IP per baris. Return list IP unik, urutan
    dipertahankan. Validasi pakai modul `ipaddress` standar Python (BUKAN
    regex yang cuma cek jumlah digit - itu salah, akan meloloskan IP tidak
    valid seperti '256.256.256.256')."""
    import ipaddress

    def is_valid_ip(s):
        try:
            ipaddress.ip_address(s.strip())
            return True
        except ValueError:
            return False

    name = uploaded_file.name.lower()
    if name.endswith(".txt"):
        text = uploaded_file.read().decode("utf-8", errors="ignore")
        candidates = [line.strip() for line in text.splitlines() if line.strip()]
    else:
        if name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        candidates = []
        for col in df.columns:
            sample = df[col].astype(str).head(20)
            if sample.apply(lambda v: is_valid_ip(v)).sum() >= max(1, len(sample) // 2):
                candidates.extend(df[col].astype(str).tolist())
                break
        if not candidates:
            # tidak ketemu kolom yang jelas IP - ambil semua sel yang valid IP di seluruh file
            for col in df.columns:
                candidates.extend(df[col].astype(str).tolist())

    valid_ips = [c.strip() for c in candidates if is_valid_ip(c)]
    seen = set()
    unique_ips = []
    for ip in valid_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    return unique_ips


def render_ioc_dashboard():
    st.markdown("""
    <style>
        [data-testid="stMetric"] { border-left: 4px solid #C0392B !important; }
    </style>
    """, unsafe_allow_html=True)

    st.title("🔎 IOC Scoring - Verifikasi IP Firewall")
    st.caption("Upload daftar IP dari log firewall - dicek ke GitHub Threat Feed (gratis) + "
               "VirusTotal & AbuseIPDB (opsional, perlu API key sendiri).")

    st.warning(
        "⚠️ **Catatan jujur**: kode ini belum bisa saya test langsung ke internet dari sandbox "
        "pengembangan saya. Endpoint & format sudah sesuai dokumentasi resmi masing-masing "
        "layanan, tapi disarankan test dengan sedikit IP dulu sebelum upload massal."
    )

    # ---- 1. Input IP: upload file ATAU input manual ----
    st.markdown("### 1. Input Daftar IP")
    tab_upload, tab_manual = st.tabs(["📁 Upload File", "⌨️ Input Manual"])

    ip_list = []
    with tab_upload:
        uploaded_file = st.file_uploader("File log firewall (.csv, .xlsx, atau .txt - 1 IP per baris)",
                                          type=["csv", "xlsx", "txt"], key="ioc_upload")
        if uploaded_file is not None:
            try:
                ip_list = _extract_ips_from_upload(uploaded_file)
                st.success(f"✅ {len(ip_list)} IP unik & valid ditemukan di file.")
                if len(ip_list) > 500:
                    st.warning(f"⚠️ {len(ip_list)} IP cukup banyak - kalau VirusTotal diaktifkan "
                               f"(4 request/menit), estimasi waktu ~{len(ip_list) * 16 // 60} menit.")
            except Exception as e:
                st.error(f"Gagal membaca file: {e}")

    with tab_manual:
        st.caption("Ketik/paste sampai 10 IP, dipisah baris baru ATAU koma.")
        manual_text = st.text_area(
            "Daftar IP", height=150, key="ioc_manual_input",
            placeholder="94.154.43.164\n8.8.8.8\n1.1.1.1"
        )
        if manual_text.strip():
            import re as _re
            raw_tokens = [t.strip() for t in _re.split(r"[,\n]+", manual_text) if t.strip()]
            import ipaddress as _ipaddress
            valid_manual, invalid_manual = [], []
            for t in raw_tokens:
                try:
                    _ipaddress.ip_address(t)
                    valid_manual.append(t)
                except ValueError:
                    invalid_manual.append(t)
            seen_m = set()
            valid_manual = [ip for ip in valid_manual if not (ip in seen_m or seen_m.add(ip))]

            if len(valid_manual) > 10:
                st.warning(f"⚠️ Anda memasukkan {len(valid_manual)} IP, dibatasi cuma **10 pertama** "
                           "untuk input manual (kalau lebih, gunakan tab Upload File).")
                valid_manual = valid_manual[:10]
            if invalid_manual:
                st.error(f"❌ {len(invalid_manual)} entri BUKAN IP valid, diabaikan: {invalid_manual}")
            if valid_manual:
                st.success(f"✅ {len(valid_manual)} IP valid siap dicek.")
                ip_list = valid_manual

    if not ip_list:
        st.info("ℹ️ Upload file ATAU isi input manual dulu untuk melanjutkan.")
        return

    with st.expander(f"Lihat {len(ip_list)} IP yang akan dicek"):
        st.write(ip_list)

    st.divider()

    # ---- 2. Pilih sumber pengecekan ----
    st.markdown("### 2. Pilih Sumber Pengecekan")

    st.markdown("**GitHub Threat Feed** (gratis, tanpa API key)")
    selected_feeds = st.multiselect(
        "Pilih feed", options=list(DEFAULT_FEEDS.keys()),
        default=list(DEFAULT_FEEDS.keys())[:2], key="ioc_feeds"
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**VirusTotal** (opsional)")
        vt_enabled = st.checkbox("Aktifkan VirusTotal", key="ioc_vt_enabled")
        vt_api_key = st.text_input("VirusTotal API Key", type="password", key="ioc_vt_key") if vt_enabled else None
    with c2:
        st.markdown("**AbuseIPDB** (opsional)")
        abuse_enabled = st.checkbox("Aktifkan AbuseIPDB", key="ioc_abuse_enabled")
        abuse_api_key = st.text_input("AbuseIPDB API Key", type="password", key="ioc_abuse_key") if abuse_enabled else None

    c3, c4 = st.columns(2)
    with c3:
        st.markdown("**ThreatFox + URLhaus** (abuse.ch, opsional)")
        st.caption("1 Auth-Key gratis (daftar di auth.abuse.ch) berlaku untuk keduanya.")
        abusech_enabled = st.checkbox("Aktifkan ThreatFox + URLhaus", key="ioc_abusech_enabled")
        abusech_api_key = st.text_input("abuse.ch Auth-Key", type="password", key="ioc_abusech_key") if abusech_enabled else None
    with c4:
        st.markdown("**Shodan InternetDB + Geolokasi** (gratis, otomatis)")
        st.caption("Tanpa API key - selalu dijalankan untuk konteks tambahan (open ports, CVE, lokasi, ISP).")
        enrichment_enabled = st.checkbox("Aktifkan (disarankan, gratis)", value=True, key="ioc_enrichment_enabled")

    st.divider()

    # ---- 3. Jalankan pengecekan ----
    if st.button("🔍 Mulai Verifikasi", type="primary", key="ioc_btn_check"):
        with st.spinner("Download & cek GitHub Threat Feed..."):
            feeds_dict = get_feeds(selected_feeds) if selected_feeds else {}
            feed_df = check_ips_against_feeds(ip_list, feeds_dict)

        vt_df = None
        if vt_enabled:
            if not vt_api_key:
                st.error("VirusTotal diaktifkan tapi API key kosong - dilewati.")
            else:
                progress = st.progress(0, text="Mengecek VirusTotal...")
                def _update_vt(i, total):
                    progress.progress(i / total, text=f"VirusTotal: {i}/{total} IP")
                vt_df = check_ips_virustotal(ip_list, vt_api_key, progress_callback=_update_vt)
                progress.empty()

        abuse_df = None
        if abuse_enabled:
            if not abuse_api_key:
                st.error("AbuseIPDB diaktifkan tapi API key kosong - dilewati.")
            else:
                progress2 = st.progress(0, text="Mengecek AbuseIPDB...")
                def _update_abuse(i, total):
                    progress2.progress(i / total, text=f"AbuseIPDB: {i}/{total} IP")
                abuse_df = check_ips_abuseipdb(ip_list, abuse_api_key, progress_callback=_update_abuse)
                progress2.empty()

        abusech_df = None
        if abusech_enabled:
            if not abusech_api_key:
                st.error("ThreatFox+URLhaus diaktifkan tapi Auth-Key kosong - dilewati.")
            else:
                progress3 = st.progress(0, text="Mengecek ThreatFox + URLhaus...")
                def _update_abusech(i, total):
                    progress3.progress(i / total, text=f"ThreatFox+URLhaus: {i}/{total} IP")
                abusech_df = check_ips_abusech(ip_list, abusech_api_key, progress_callback=_update_abusech)
                progress3.empty()

        shodan_df, geo_df = None, None
        if enrichment_enabled:
            progress4 = st.progress(0, text="Mengecek Shodan InternetDB + Geolokasi...")
            def _update_enrich(i, total):
                progress4.progress(i / total, text=f"Enrichment: {i}/{total} IP")
            shodan_df, geo_df = check_ips_enrichment(ip_list, progress_callback=_update_enrich)
            progress4.empty()

        result = combine_and_score(feed_df, vt_df, abuse_df, abusech_df, shodan_df)
        if geo_df is not None and len(geo_df) > 0:
            result = result.merge(geo_df, on="IP", how="left")
        st.session_state["ioc_result"] = result
        st.success("✅ Verifikasi selesai.")

    # ---- 4. Hasil ----
    result = st.session_state.get("ioc_result")
    if result is not None:
        st.markdown("### 4. Hasil Verifikasi")

        # Kolom BARU: "Sumber_Ditemukan" - ringkasan jelas tools mana yang
        # menandai IP ini bermasalah (bukan cuma skor angka tanpa konteks).
        def _sources_flagged(row):
            sources = []
            if row.get("Feed_Match_Count", 0) and row["Feed_Match_Count"] > 0:
                sources.append(f"GitHub/Feodo Feed ({row.get('Matched_Feeds', '')})")
            if pd.notna(row.get("VT_Malicious")) and row.get("VT_Malicious", 0) > 0:
                sources.append(f"VirusTotal ({int(row['VT_Malicious'])} engine flag malicious)")
            if pd.notna(row.get("AbuseIPDB_Confidence_%")) and row.get("AbuseIPDB_Confidence_%", 0) > 0:
                sources.append(f"AbuseIPDB ({row['AbuseIPDB_Confidence_%']}% confidence)")
            if pd.notna(row.get("ThreatFox_Malware")) and str(row.get("ThreatFox_Malware", "")).strip():
                sources.append(f"ThreatFox (malware: {row['ThreatFox_Malware']})")
            if pd.notna(row.get("URLhaus_URL_Count")) and row.get("URLhaus_URL_Count", 0) > 0:
                sources.append(f"URLhaus ({int(row['URLhaus_URL_Count'])} URL malware terdaftar)")
            if pd.notna(row.get("Shodan_CVEs")) and str(row.get("Shodan_CVEs", "")).strip():
                sources.append(f"Shodan (CVE terbuka: {row['Shodan_CVEs']})")
            return " | ".join(sources) if sources else "Tidak ditemukan di sumber manapun"

        def _sources_checked(row):
            checked = ["GitHub/Feodo Feed"]
            if "VT_Error" in row.index:
                checked.append("VirusTotal" if pd.isna(row.get("VT_Error")) or not row.get("VT_Error") else "VirusTotal (gagal/di-skip)")
            if "AbuseIPDB_Error" in row.index:
                checked.append("AbuseIPDB" if pd.isna(row.get("AbuseIPDB_Error")) or not row.get("AbuseIPDB_Error") else "AbuseIPDB (gagal/di-skip)")
            if "ThreatFox_Error" in row.index:
                checked.append("ThreatFox+URLhaus" if pd.isna(row.get("ThreatFox_Error")) or not row.get("ThreatFox_Error") else "ThreatFox+URLhaus (gagal/di-skip)")
            if "Shodan_Error" in row.index:
                checked.append("Shodan+Geo" if pd.isna(row.get("Shodan_Error")) or not row.get("Shodan_Error") else "Shodan+Geo (gagal/di-skip)")
            return ", ".join(checked)

        result = result.copy()
        result["Sumber_Ditemukan"] = result.apply(_sources_flagged, axis=1)
        result["Sumber_Dicek"] = result.apply(_sources_checked, axis=1)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total IP Dicek", len(result))
        c2.metric("HIGH RISK", (result["Risk_Level"] == "HIGH RISK").sum())
        c3.metric("MEDIUM RISK", (result["Risk_Level"] == "MEDIUM RISK").sum())
        c4.metric("CLEAN", (result["Risk_Level"] == "CLEAN").sum())

        display_cols = ["IP", "Risk_Score", "Risk_Level", "Sumber_Ditemukan", "Sumber_Dicek",
                         "Geo_Country", "Geo_ISP", "Geo_Is_Hosting"]
        display_cols = [c for c in display_cols if c in result.columns]
        st.dataframe(result[display_cols], use_container_width=True)

        with st.expander("🔬 Rincian lengkap per IP (semua kolom mentah dari tiap sumber)"):
            st.dataframe(result, use_container_width=True)

        st.caption(
            "ℹ️ **Cara baca 'Sumber Ditemukan'**: kalau kosong/'Tidak ditemukan di sumber manapun', "
            "itu berarti IP ini BERSIH di sumber yang DICEK - bukan berarti bersih secara mutlak. "
            "Cek kolom 'Sumber_Dicek' untuk tahu sumber mana saja yang aktif saat itu."
        )

        csv_bytes = result.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Download Hasil (CSV)", csv_bytes,
                            file_name="IOC_Verification_Result.csv", key="ioc_dl_csv")
