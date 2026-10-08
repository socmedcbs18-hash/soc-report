# SOC Incident Report (modul ke-6)
Laporan insiden SOC bulanan dari export tiket Ivanti. Pembeda utama: bulan yang memuat **dua state machine** dilaporkan per era.

- Jalankan seperti biasa (`streamlit run app.py ...`), pilih kartu **SOC Incident Report**.
- Upload satu file bulan penuh. Cutover terdeteksi otomatis (atau atur manual / "tidak ada"). Untuk bulan setelah cutover (mis. Oktober) pilih
  "Seluruh bulan memakai state machine: Baru" agar bisa dibandingkan apel-ke-apel dengan era baru bulan sebelumnya.
- Simpan snapshot tiap bulan (tab 💾) lalu bandingkan di tab 🔀. Snapshot = angka agregat, tanpa data tiket/customer.
- Pengaturan: `soc_incident/config.json` (pola akun sistem, ambang deteksi & insight, label prioritas).
- Test: `python -m unittest discover -s soc_incident/tests -t .`
- Batasan: MTTC belum bisa dihitung (belum ada timestamp Contained); Created→Resolved bukan MTRV.
