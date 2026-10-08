"""Halaman sumber data selain IPS (Akamai, DLP, EDR, CSPM, Vulnerability, SIEM, Proxy, Email, SAST/DAST, Executive Summary).
Belum ada data mentah -> halaman ini HANYA menampilkan apa yang akan dilaporkan dan slide contoh dari deck referensi.
Gambar slide adalah CONTOH tampilan (bukan data yang di-upload) dan tidak pernah dipakai sebagai sumber angka."""
from pathlib import Path

import streamlit as st

from cybersec_report.core.config_loader import load_report_structure

SAMPLE_DIR = Path(__file__).resolve().parent / "templates" / "assets" / "samples"
HIDDEN_IN_DECK = {2, 3, 28, 36, 37, 38, 39}


def menu_entries():
    """[(id, label)] semua section yang punya menu, urutan sesuai report_structure.json."""
    return [(x["id"], x) for x in load_report_structure()["sections"] if x.get("menu", True)]


def sample_images(section):
    return [(n, SAMPLE_DIR / f"slide_{n:02d}.jpg") for n in section.get("sample_slides", []) if (SAMPLE_DIR / f"slide_{n:02d}.jpg").exists()]


def render_source_placeholder(section):
    st.subheader(section["title"])
    st.info("⏳ **Menunggu data mentah.** Menu ini sudah aktif sebagai gambaran isi report; analisis dan angka baru dibuat setelah file raw "
            "(CSV/XLSX) dari tim terkait di-upload dan modul parser-nya dibangun. Tidak ada angka yang ditampilkan di sini.")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Yang akan dilaporkan** (diambil dari struktur deck referensi)")
        for line in section.get("deck_reports") or ["Lihat slide contoh di bawah."]:
            st.markdown(f"- {line}")
    with c2:
        st.markdown("**Data mentah yang perlu diminta ke tim terkait**")
        st.caption("Perkiraan berdasarkan isi slide contoh — konfirmasi kolom sebenarnya setelah mendapat file.")
        for line in section.get("needs_raw") or ["Konfirmasi ke tim terkait."]:
            st.markdown(f"- {line}")
    imgs = sample_images(section)
    if imgs:
        st.markdown("**Contoh tampilan dari deck referensi** (gambar contoh, bukan data hasil upload)")
        hidden = [n for n, _ in imgs if n in HIDDEN_IN_DECK]
        if hidden:
            st.caption("Slide " + ", ".join(map(str, hidden)) + " berstatus hidden di deck asli; tetap ditampilkan sebagai referensi.")
        for n, path in imgs:
            st.image(str(path), caption=f"Contoh — slide {n} deck referensi", use_container_width=True)
