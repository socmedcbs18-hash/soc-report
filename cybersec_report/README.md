# Cybersecurity Monthly Report (modul ke-5 di Security Reporting Dashboard)

Mengganti pekerjaan manual membuat deck cybersecurity bulanan: upload raw data security device ->
validasi -> analytics -> threat intelligence -> PowerPoint + Excel + audit.
**Raw data adalah sumber kebenaran; deck contoh hanya referensi struktur/gaya. Tidak ada angka dari deck contoh.**

Status: **Phase 1 (IPS) selesai**. Phase berikutnya: Akamai -> DLP -> EDR/Cynet -> CSPM -> Vulnerability -> SIEM -> Proxy -> Email -> Executive Summary.

## Instalasi dan menjalankan (Windows)
Tidak ada dependensi baru (semua sudah ada di `requirements.txt` project). `python-dotenv` opsional.
```
cd SOC_Report_Generator
pip install -r requirements.txt
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```
Buka homepage -> card **Cybersecurity Monthly Report**.

Menjalankan test (60 test): `python -m unittest discover -s cybersec_report/tests -t .`

## Lokasi data & API key
Semua data user disimpan di **`database/cybersec_report/`** (di folder root project, sejajar `app.py`), BUKAN di folder kode,
sehingga mengganti/menimpa `cybersec_report/` tidak menghapus data:

| Lokasi | Isi |
|---|---|
| `database/cybersec_report/.env` | **API key** (lokasi utama) |
| `database/cybersec_report/snapshots/` | snapshot dashboard per periode (`IPS_2026-09.json`) |
| `database/cybersec_report/cache/` | cache reputasi (`reputation.sqlite`, termasuk status kuota provider), histori MoM |
| `database/cybersec_report/output/` | PPT/Excel/audit hasil Generate |
| `database/cybersec_report/device_environment.json` | mapping device -> environment dari UI |

**Cara mengisi API key** (pilih salah satu):
1. Di aplikasi: sidebar -> **🔑 API Key** -> isi VirusTotal / AbuseIPDB -> **Simpan ke .env** (key ditampilkan ter-mask).
2. Atau buat file `database/cybersec_report/.env` berisi:
   ```
   VT_API_KEY=isi_key_virustotal
   ABUSEIPDB_API_KEY=isi_key_abuseipdb
   ```
   (`.env` di root project atau di `cybersec_report/` juga dibaca; urutan: input UI > environment OS > database/ > root > cybersec_report/.)
File dibaca ulang setiap kali dipakai, jadi edit `.env` langsung berlaku tanpa restart. Jangan commit `.env`.
Tanpa key aplikasi tetap jalan; kolom reputasi tampil `Not assessed`, bukan angka 0.

## Cara pakai
1. **Upload & Mapping**: upload CSV/XLSX/XLS IPS (delimiter terdeteksi otomatis). Kolom dikenali via alias persis di
   `config/source_mapping.json`; kolom yang tidak dikenali **tidak ditebak** - petakan manual di UI.
   Isi mapping **device -> environment** (DCI/NTT/GCP). Kosong = semua device digabung "All Devices".
2. **Validation**: PASS/WARNING/FAIL. FAIL level CRITICAL (kolom wajib hilang, count negatif) memblokir report.
3. **Threat Intelligence**: jumlah IP publik/private, estimasi waktu, tombol *Run Reputation Check* (strategi failover, lihat bawah).
4. **📊 Dashboard** (tab pertama): tampil langsung dari upload ATAU dari periode tersimpan ("IPS September 2026") tanpa upload ulang.
   Layout mengikuti slide contoh: pie, tabel severity + Description, Attack Name per severity, Dest, Source Country (Top 5 + Others, By%),
   top source IP + reputasi, insight/rekomendasi, MoM. Klik **Simpan snapshot** agar periode bisa dibuka lagi.
5. **Generate / Export (opsional)**: PPT + 4 file lain; verifikasi Raw total == Analytics total == PPT total. Generate juga menyimpan snapshot dashboard.

Periode: otomatis dari timestamp -> nama file (mis. `IPS_Sep_2026.csv`) -> input manual. Bisa di-override di sidebar.

## Hapus file, hostname, Compare, dan sumber lain
- **Hapus file** (sidebar): upload file lain tanpa kehilangan cache reputasi IP, snapshot, atau API key. IP yang pernah dicek (dalam umur cache, default 168 jam) tidak query ulang.
- **Per hostname**: satu file boleh berisi banyak hostname; otomatis dipisah. Snapshot bulanan per hostname (`P1FWX0209-IPS-September-2026`).
- **Compare**: pilih dua snapshot IPS mana pun (mis. September vs Oktober, hostname sama atau berbeda).
- **Menu lain** (Akamai, DLP, EDR, CSPM, Vulnerability, SIEM, Proxy, Email, SAST/DAST, Executive Summary): halaman contoh dari deck referensi sambil menunggu data mentah.

## Output (folder `database/cybersec_report/output/`)
`Cybersecurity_Monthly_Report_<YYYY_MM>.pptx`, `Cybersecurity_Monthly_Summary_<YYYY_MM>.xlsx`,
`IOC_Reputation_<YYYY_MM>.xlsx`, `Report_Audit_<YYYY_MM>.json`, `Validation_Report_<YYYY_MM>.xlsx`

## Konfigurasi (tanpa ubah kode Python)
| File | Isi |
|---|---|
| `source_mapping.json` | alias kolom raw -> canonical, kolom wajib/rekomendasi |
| `settings.json` | Top-N, toleransi, action yang dihitung, rate limit provider, TTL cache, ambang insight |
| `scoring.json` | bobot & band Internal Normalized Threat Score |
| `device_environment.json` | default kosong; versi yang diisi lewat UI disimpan di `database/cybersec_report/` (menang atas default) |
| `asset_inventory.json` | IP internal -> nama aset (**seed dari deck contoh, mohon diverifikasi**) |
| `attack_knowledge.json` | kamus interpretasi signature IPS; signature tak dikenal = tanpa interpretasi |
| `report_structure.json` | section report, judul, section yang belum diimplementasikan |

## Cara kerja
- **Total attack = SUM(count)**, bukan jumlah baris. Rekonsiliasi ditampilkan (mis. 547 record -> 939 event).
- **Penyebut persentase mengikuti konteks**: attack Critical dibagi total Critical. Top 5 + Others bila item > 5.
- **Failover reputasi (hemat token)**: `settings.json -> reputation.strategy = "failover"`, `provider_order = ["virustotal","abuseipdb"]`.
  Satu provider dipakai sampai kuota/limit habis, lalu otomatis pindah ke berikutnya (mis. 10 IP -> VT sampai kuota habis, sisanya AbuseIPDB).
  Hasil di cache (provider mana pun, 24 jam) tidak memakai token. Kuota habis dideteksi dari HTTP 429 berisi pesan quota/daily limit,
  `Retry-After` > `max_retry_after_seconds` (120), atau header `X-RateLimit-Remaining: 0` (AbuseIPDB); status "habis" disimpan sampai
  00:00 UTC berikutnya (asumsi kuota harian) agar run berikutnya tidak membuang request - tombol *Reset status kuota* tersedia.
  429 singkat (per-menit) hanya di-retry. `strategy = "all"` memanggil semua provider untuk tiap IP (korelasi dua sumber, boros token).
  Deteksi kuota mengikuti perilaku API yang terdokumentasi dan diuji dengan respons tiruan; belum diverifikasi terhadap API live.
- **Reputasi**: IP private/loopback/link-local tidak pernah di-query. Cache SQLite (`database/cybersec_report/cache/reputation.sqlite`, TTL 24 jam,
  hanya hasil sukses), rate limiter per provider, retry + exponential backoff (hormati `Retry-After`), circuit breaker
  setelah 5 kegagalan beruntun, key salah (401/403) menonaktifkan provider. Satu provider gagal tidak menggagalkan proses.
  IP yang dicek dibatasi N teratas (default 50) dengan seleksi berselang-seling antara volume terbesar dan Critical terbanyak.
  Estimasi: VirusTotal gratis = 4 request/menit.
- **Skor** "Internal Normalized Threat Score" 0-100 = rata-rata berbobot komponen yang tersedia (VT malicious,
  AbuseIPDB confidence, jumlah laporan, recency); 0-19 Low, 20-39 Guarded, 40-59 Medium, 60-79 High, 80-100 Critical.
  Bukan skor resmi vendor.
- **Narasi**: rule-based dari evidence; redaksi "mengindikasikan/teramati/berpotensi". Tidak pernah menyatakan compromise
  tanpa evidence. Hook AI hanya membangun payload teragregasi (`narrative.ai_payload`, tanpa IP/aset/username); belum memanggil AI.
- **Audit**: setiap angka tercatat di `Report_Audit_*.json` (slide, metric, value, source_file, filter, calculation).
  PPT dibaca balik setelah dibuat dan dicocokkan dengan analytics.

## Dependency graph
```
dashboard.py -> pipeline.py -> core/ingestion -> core/normalization -> sources/ips
                            -> core/validation -> core/analytics -> core/insights -> report/narrative
                            -> core/reputation -> threat_intel/{virustotal,abuseipdb} -> core/scoring
                            -> report/ppt_generator -> report/slide_components -> report/charts
                            -> report/ppt_verify, report/exports, core/history, core/audit, core/period
core/config_loader <- semua modul (membaca config/*.json)
```
Modul ini tidak mengimpor apa pun dari SOC/Cynet/IOC/SR SLA. Perubahan di luar folder ini: `app.py` (card ke-5 + gate).

## Pemetaan PPT contoh -> data
| Slide contoh | Data raw | Transformasi | Output |
|---|---|---|---|
| (IPS) Firewall DMZ - data | severity, attack, dstip, srccountry, count | filter action -> SUM(count) per dimensi | pie + tabel severity, attack per severity, Dest, Source Country |
| (IPS) Firewall DMZ - analisis | hasil slide data + kamus signature | finding -> implikasi -> rekomendasi | Kesimpulan / Implikasi+Insight / Rekomendasi+Tindakan |
| (baru) Top Source IP | srcip + reputasi | profil per IP + skor | KPI + tabel Top 10 |

## Keterbatasan yang diketahui
- Panggilan API VirusTotal/AbuseIPDB sungguhan belum diuji end-to-end (hanya dengan respons tiruan).
- Pie chart 2D (python-pptx tidak dapat menulis pie 3D seperti deck contoh).
- Tanpa kolom timestamp, attack trend tidak dapat dihitung; MoM hanya jika bulan sebelumnya pernah disimpan.
- Format `.xls` butuh paket `xlrd` (`pip install xlrd`) atau simpan sebagai `.xlsx`.
- Layout PPT dirender/diverifikasi lewat LibreOffice; font Aptos/Lato di PowerPoint asli bisa sedikit mengubah spasi.
