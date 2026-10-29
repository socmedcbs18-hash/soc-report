# CHANGELOG - Perbaikan & Penambahan Fitur

Semua perubahan diuji langsung ke data `input/weekly/w27` (dan gabungan w27-w29
untuk mode monthly) sebelum diserahkan. Angka di bawah adalah hasil pengujian nyata,
bukan estimasi.

## 1. Bug kritis: rule name tidak pernah match (FIXED)

**Sebelum:** `core/normalizer.py` hanya membuang bracket `[ESV2]` dan simbol, tidak
membuang prefix kategori (`"Access - "`, `"Threat - "`, dst) maupun suffix
(`"- Rule"`, `"- Severity 3"`). Hasilnya: **0% alert dan 1% incident** berhasil
match ke Master Rules (dibuktikan dengan menjalankan kode asli ke data w27).

Menariknya, solusinya sebagian sudah ada di `config/constants.py`
(`REMOVE_PREFIX`/`REMOVE_SUFFIX`) dan `utils/helpers.py`
(`remove_prefix()`/`remove_suffix()`) - tapi tidak pernah dipanggil dari
`normalizer.py`.

**Sesudah:** fungsi `clean_rule_name()` baru di `utils/helpers.py` (regex,
anchored, urutan strip yang benar: severity dulu baru "- Rule", environment
ESV2/ESV3 distandarkan ke satu tag). Hasil: **97% alert, 93% incident match**
(week 27) / **95.8% alert, 90.1% incident match** (bulan Juli gabungan).

## 2. Bug: perbandingan tidak sepadan di validator (FIXED)

`validate_unknown_rule()` membandingkan `alert["Normalized Rule"]` (sudah bersih)
dengan `master["Rule_Names"]` (mentah, belum dibersihkan) - dua sisi tidak
sepadan. Diperbaiki: sekarang pakai kolom `Matched` dari normalizer yang
konsisten.

## 3. Bug: data hilang diam-diam saat digabung (FIXED)

`build_rule_summary()` sebelumnya mulai dari `master.merge(alert_summary,
how="left")` - artinya SEMUA alert/incident yang rule-nya tidak dikenal master
otomatis hilang dari total report, tanpa jejak. Sekarang pakai outer merge;
baris yang tidak dikenal master tetap muncul dan ditandai kolom `In_Master =
False` + masuk sheet baru `Unmapped`. Total alert & incident sekarang selalu
sama persis dengan angka mentah di file sumber (sudah diverifikasi otomatis di
log setiap run).

Catatan tambahan: ditemukan juga 26 rule di Master Rules yang punya nama
ternormalisasi kembar (typo/duplikat) - kalau tidak di-dedupe dulu sebelum
merge, angka alert/incident bisa gandeng (fan-out). Sudah di-dedupe otomatis,
duplikatnya sendiri tetap dilaporkan di sheet `Duplicate Master`.

## 4. Bug: format Priority tidak sesuai (FIXED)

`build_priority()` mengasumsikan kolom `Priority` berformat string `"P1"`/`"P2"`,
padahal data asli numeric (`1.0`, `2.0`, dst). Akibatnya urutan prioritas selalu
gagal (semua jadi NaN). Diperbaiki untuk membaca angka langsung dan
menampilkan label `P1`/`P2` untuk keterbacaan.

## 5. Bug: keyword domain mapping tidak terurut (FIXED)

`Domain_Mapping_Splunk.xlsx` sudah punya kolom `Priority` untuk menentukan
keyword mana yang menang kalau ada tumpang tindih, tapi `build_domain()` tidak
pernah men-sort berdasarkan itu - hanya ikut urutan baris di file. Sekarang
diurutkan eksplisit (dan baris instruksi non-numerik di kolom Priority di
file sumber di-filter dulu supaya tidak bikin sort error).

## 6. Bug: dashboard.py referensi kolom salah (FIXED, tapi tetap tidak dipakai)

`core/dashboard.py` (`DashboardGenerator`) tidak pernah dipanggil dari
`main.py` - dead code. Referensinya juga salah (`"Alert Count"` vs
`"Alert_Count"` yang sebenarnya dihasilkan processor). Sudah diperbaiki
supaya konsisten kalau suatu saat mau dipakai lagi, tapi fungsinya sekarang
digantikan oleh `build_executive_summary()` + `build_hypothesis_insight()`.

## 7. BARU: KPI per individu SOC analyst

Sheet baru `Soc Individual Kpi` (`build_soc_individual_kpi()` di
`processor.py`): per analyst - jumlah tiket, % workload dari total tim,
rata-rata MTTR (Created On -> Responded On), rata-rata MTTC (Responded On ->
Resolved On), breach rate, dan status terhadap SLA (`SLA_MTTR_SECONDS` di
`config/settings.py`).

## 8. BARU: Insight berbasis hipotesis, bukan cuma angka

Sheet baru `Hypothesis Insight` (`build_hypothesis_insight()`): setiap baris
menjawab pertanyaan konkret - conversion rate alert-ke-tiket, rule mana yang
paling banyak "gap" (alert tapi tidak jadi tiket), rule noise, cakupan
deteksi (berapa % alert dari rule yang tidak dikenal master), rule dormant,
serta insight beban kerja & SLA analyst.

## 9. BARU: Native Excel chart (sebelumnya `core/charts.py` kosong)

`ChartBuilder` di `core/charts.py`: bar chart top rule, pie chart distribusi
security domain, bar chart workload per analyst. Chart native Excel (bisa
diklik/diedit), bukan gambar statis, otomatis ditambahkan saat export.

## 10. BARU: Mode Monthly

`main.py` sekarang tanya mode di awal (Weekly/Monthly). Mode Monthly
menggabungkan SEMUA folder `input/weekly/*`, lalu memfilter baris
berdasarkan tanggal ASLI di data (`Alert Time`/`Created On`) - bukan
berdasarkan nama folder - supaya minggu yang lintas 2 bulan (mis. 28 Jun - 4
Jul) tetap terhitung akurat ke bulan masing-masing.

## Belum dikerjakan / rekomendasi langkah berikutnya

- **Integrasi sumber data non-Splunk** (Akamai/CSPM/Microsoft Defender) dan
  **migrasi rule ESV2->ESV3** (`Database_Alert_Splunk_29July.csv`) - sudah
  dirancang & divalidasi terpisah di percakapan sebelumnya (87% rule berhasil
  di-mapping lintas environment), tinggal disambungkan ke `loader.py` &
  `settings.py` kalau mau dipakai di tool ini juga.
- Kolom `security_domain` dari `Database_Alert_Splunk_29July.csv` bisa
  dipakai memperkaya `build_domain()` di luar keyword matching manual.

## 11. BARU (update): Integrasi alert non-Splunk (Akamai/CSPM/Microsoft Defender)

- File `alert_nonsplunk...xlsx` (opsional per minggu, taruh di `input/weekly/wXX/`
  bersama alert Splunk & tiket Ivanti) sekarang otomatis ke-load kalau ada, dan
  dilewati dengan aman kalau tidak ada (tidak bikin error).
- Tidak perlu fuzzy-matching rumit seperti Splunk<->Ivanti, karena file ini sudah
  punya kolom eksplisit `Apakah dibuat tiket Ivanti? (Y/N)`.
- Sheet baru `Nonsplunk Coverage` (ringkasan % coverage per device) dan
  `Nonsplunk Detail` (baris mentah, termasuk yang "BELUM DIVERIFIKASI").
- Masuk otomatis ke `Executive Summary` (total alert non-Splunk & yang sudah jadi
  tiket) dan `Hypothesis Insight` (H2 - NonSplunk Coverage).
- Chart baru: bar chart coverage % per device.
- Berlaku juga untuk mode Monthly (digabung dari semua minggu, difilter per bulan
  berdasarkan `Alert_Time_Std`).

## 12. BARU (update): Penanganan data non-Splunk partial/lintas-minggu

- `loader.py` sekarang membatasi data non-Splunk yang dipakai laporan MINGGUAN
  hanya yang tanggalnya masuk rentang tanggal alert Splunk minggu itu (diambil
  dari min/max `Alert Time` di file Splunk minggu tsb) - jadi kalau file manual
  Anda kelebihan tanggal (mis. dipakai untuk beberapa minggu sekaligus), baris di
  luar minggu itu otomatis dikecualikan dari laporan minggu ini (tapi tetap aman
  terhitung di laporan bulanan, karena mode Monthly membaca ulang file yang sama
  dan memfilter sendiri sesuai bulan).
- `processor.py` sekarang otomatis mendeteksi kalau data non-Splunk TIDAK
  menutupi periode secara penuh (mis. baru mulai di-track pertengahan minggu) dan
  menaruh PERINGATAN eksplisit di baris paling atas sheet `Hypothesis Insight` -
  supaya angka partial ini tidak disalahartikan sebagai "alert sepi" atau
  dibandingkan apel-ke-apel dengan minggu yang datanya sudah lengkap.
- Konsekuensi praktis: Anda TIDAK perlu bingung taruh file di folder minggu mana -
  taruh saja file mentahnya (boleh berisi rentang tanggal berapa pun) di folder
  minggu manapun yang relevan, script yang akan memilah sendiri per periode.

## 13. BARU: Streamlit app (`app.py`) sebagai antarmuka utama

- Upload file langsung dari browser (Alert Splunk, Insiden Ivanti, Alert
  NonSplunk opsional), atau pilih folder minggu yang sudah ada.
- Mode Weekly & Monthly, sama seperti CLI - memakai ULANG core module yang
  persis sama (`normalizer`/`validator`/`processor`/`excel_writer`), jadi hasil
  selalu konsisten dengan `python main.py`.
- KPI card, insight hipotesis (termasuk peringatan data partial - ditaruh
  paling atas), chart interaktif (top rule, domain, workload analyst, coverage
  non-Splunk), tabel detail yang bisa di-expand.
- Tombol Download untuk ambil file Excel lengkap (chart native Excel tetap ada).
- Opsi simpan file upload ke `input/weekly/wXX/` supaya tetap tersimpan untuk
  kebutuhan laporan bulanan nanti.
- Cara jalankan: `cd` ke folder project dulu, baru `streamlit run app.py`
  (lihat PANDUAN_PENGGUNAAN.md bagian 3).

**Catatan:** logic di app.py TIDAK menduplikasi kode dari main.py - keduanya
sama-sama memanggil fungsi yang sama persis di folder `core/`, supaya kalau ada
bug fix di masa depan, cukup diperbaiki di satu tempat.

## 14. FIXED: Angka ".0" di Executive Summary & sheet lain

Root cause: kolom "Value" di Executive Summary berisi campuran int dan 1 float
(Overall Detection Rate) - pandas otomatis meng-upcast SELURUH kolom jadi float64
kalau ada 1 nilai float di dalamnya, sehingga semua angka bulat lain ikut tampil
"535.0" dst. Diperbaiki dengan eksplisit `dtype=object` saat membuat DataFrame-nya
supaya tiap nilai mempertahankan tipe aslinya (int tetap int). Kolom Alert_Count/
Alert_Event/Incident_Count/Breach_Count di Rule Summary juga di-cast eksplisit ke
int (sebelumnya bisa float64 kalau ada NaN sebelum di-fillna).

## 15. BARU: Teks insight sekarang period-aware, bukan hardcode "minggu ini"

`build_period_info()` menghitung rentang tanggal ASLI dari data alert (bukan dari
nama mode Weekly/Monthly) dan dipakai di semua teks Hypothesis Insight & Executive
Summary. Otomatis benar untuk laporan mingguan (termasuk yang lintas 2 bulan) MAUPUN
bulanan (dan otomatis "jujur" kalau datanya belum lengkap 1 bulan penuh - lihat baris
"Periode Laporan" di Executive Summary).

## 16. BARU: Traceability - kolom "Sumber_Data" di Hypothesis Insight

Tiap baris insight sekarang menyebutkan eksplisit sheet & kolom mana yang jadi
dasar angkanya, supaya bisa dipertanggungjawabkan saat presentasi (tinggal buka
sheet yang disebut untuk verifikasi manual kalau ditanya BoD).

## 17. BARU: Sheet "Reading Guide" (glossary + lineage)

Sheet pertama di setiap laporan - menjelaskan tiap sheet/chart: apa isinya, dari
mana datanya (termasuk hubungan antar-sheet, mis. "Top Rule/Noise/Tuning/Dormant/
Unmapped semuanya adalah HASIL FILTER dari Rule Summary, bukan sumber terpisah"),
dan pertanyaan apa yang dijawab. Juga ditampilkan sebagai expander di Streamlit.

## 18. FIXED: Tombol Download di Streamlit ke-cancel

Root cause: Streamlit me-rerun SELURUH script dari atas setiap ada interaksi
(termasuk klik tombol Download). Karena `report` sebelumnya cuma variabel lokal
yang di-set di dalam blok `if st.sidebar.button("Generate Report")`, begitu halaman
rerun akibat klik Download, `report` kembali jadi `None` sebelum file sempat
terkirim ke browser - itu yang bikin "cancelled". Diperbaiki dengan menyimpan
`report` & hasil Excel-nya ke `st.session_state`, supaya tetap ada meskipun halaman
rerun. Hasil Excel juga di-cache (tidak di-generate ulang tiap rerun) supaya proses
download lebih cepat.

## 19. FIXED: Selisih "Total Alert Event" (7036 vs 3243)

Root cause: kolom `Total` di file Splunk berisi jumlah raw log hits DI BALIK satu
notifikasi alert (mis. 1 notifikasi "SSH Brute Force" = 9 percobaan login gagal).
Sebelumnya "Total Alert Event" dihitung dari SUM kolom `Total` (3009->7036),
padahal yang dimaksud sebagai "total alert" adalah JUMLAH BARIS notifikasi
(1015->3243). Sekarang `Alert_Count` = jumlah baris/notifikasi (dipakai di semua
metrik: Detection Rate, Noise threshold, Executive Summary), dan `Alert_Volume`
= sum kolom Total tetap disimpan terpisah di Rule Summary/Top Rule sebagai
metrik sekunder (volume raw log di baliknya), tidak lagi tercampur.

## 20. BARU: Executive Summary dikelompokkan (Group column)

3 grup sesuai kebutuhan presentasi: (1) Master Rules Database - total/enabled/
disabled/belum-mapping, (2) Splunk vs Ivanti - total alert, insiden, gap, noise,
dormant, tuning, detection rate, (3) Non-Splunk vs Ivanti - total alert, jadi
tiket, gap, belum diverifikasi. Di Streamlit tampil sebagai section terpisah
per grup, di Excel ada kolom "Group" untuk difilter/dikelompokkan.

## 21. BARU: Insight CTI, Threat Hunting, dan Temuan Berulang

- H-CTI: menghitung item non-Splunk yang sifatnya advisory/CTI report (dari
  kolom Reason mengandung "CTI") - ditandai perlu direview manual, bukan
  otomatis dianggap "tidak jadi tiket = tidak penting".
- H-TH: rule Dormant ditandai sebagai kandidat aktivitas Threat Hunting
  proaktif (bukan cuma "diabaikan").
- H-Recurring + sheet baru "Recurring Findings": BARU bisa terisi setelah
  report dijalankan >=3 kali (butuh histori). Menyimpan snapshot rule
  Noise/Tuning tiap kali report digenerate ke `database/rule_history.csv`,
  lalu mendeteksi rule yang muncul sebagai risiko di >=3 dari 5 periode
  terakhir - pola berulang, bukan kejadian sekali. File histori TERPISAH
  dari folder input/output, jangan dihapus supaya kontinuitas antar
  periode tetap terjaga.

## 22. BARU: Domain_Mapping dikonsolidasi ke Master_Rules_Splunk.xlsx

`Master_Rules_Splunk.xlsx` sekarang punya 2 kolom baru: `Security_Domain` dan
`Security_Sub_Domain` - hasil klasifikasi keyword yang dilakukan SEKALI (bukan
dihitung ulang tiap laporan). Ini bikin klasifikasi domain STABIL antar
minggu/bulan (sesuai tujuan "report berkesinambungan"). `Domain_Mapping_Splunk.xlsx`
sekarang OPSIONAL - hanya dipakai sebagai fallback kalau ada rule baru yang
belum sempat diberi Security_Domain di master. Kalau fallback ini sering
kepakai, sebaiknya kolom Security_Domain di master di-update manual untuk
rule yang bersangkutan.

## 23. FIXED (upaya perbaikan): Tombol Download di Streamlit

File Excel sekarang di-generate LANGSUNG setelah klik "Generate Report" (bukan
ditunda sampai discroll ke tombol Download), dibungkus try/except dengan pesan
error jelas kalau gagal. Juga ditambahkan catatan bahwa file yang sama selalu
tersimpan di folder `output/` sebagai jalan pintas kalau tombol browser tetap
bermasalah (kemungkinan penyebab di luar kendali kode: antivirus/Windows
Defender yang men-cancel download dari server lokal - screenshot pesan error
persis dari browser kalau masih terjadi, supaya bisa didiagnosis lebih lanjut).

## 24. BARU: 3 insight advanced

- **H-Mismatch (Severity vs Priority)**: sheet `Severity_Priority_Mismatch` -
  membandingkan severity rule Splunk vs priority tiket Ivanti, fokus ke kasus
  UNDER-PRIORITIZED (rule serius tapi tiket dikasih priority rendah - risiko
  nyata, insiden bisa terlambat direspons).
- **H-Entity (Multi-Vektor)**: sheet `Entity_Correlation` - individu (kolom
  Customer di Ivanti) yang terlibat di >=2 rule berbeda dalam 1 periode -
  kandidat investigasi akun secara menyeluruh. Akun sistem/tim otomatis
  (mis. "splunkhwc-alert") difilter keluar.
- **H-TimePattern**: sheet `Time_By_Hour` & `Time_By_Day` - distribusi alert
  per jam/hari, plus % alert di luar jam kerja (08:00-17:00 WIB, Senin-Jumat) -
  relevan untuk evaluasi shift SOC.

## 25. BUG DITEMUKAN & DIPERBAIKI: clean_severity tidak menangani data Splunk asli

Saat membangun H-Mismatch, ketahuan bahwa kolom Severity mentah di file Splunk
JAUH lebih berantakan dari asumsi awal - ada nilai gabungan seperti
"CRITICAL HIGH LOW MEDIUM", nilai sampah "ERROR", bahkan angka mentah (3).
`clean_severity()` sebelumnya cuma menangani 1 kata bersih (dipakai untuk file
non-Splunk yang memang rapi), TIDAK PERNAH benar-benar dipanggil untuk kolom
Severity di alert Splunk - sehingga nilai mentah yang berantakan itu lolos
sampai ke perhitungan mismatch dan menghasilkan angka yang SALAH (sempat
menunjukkan 0% under-prioritized, padahal itu artefak bug, bukan temuan asli).

Diperbaiki: `clean_severity()` sekarang mem-parsing SEMUA kata severity yang
valid dalam string (untuk nilai gabungan), mengambil yang PALING PARAH
(pendekatan konservatif), dan eksplisit dipanggil di `build_rule_summary()`
sebelum data severity dipakai di mana pun. Setelah fix: 5 kasus
UNDER-PRIORITIZED genuin ditemukan (sebelumnya salah menunjukkan 0).

**Pelajaran dari bug ini**: hati-hati mempercayai angka 0/kosong sebagai
"tidak ada masalah" - kadang itu tanda ada yang salah di pipeline-nya, bukan
benar-benar tidak ada temuan. Selalu sanity-check dengan lihat data mentahnya
kalau hasilnya "terlalu bersih untuk jadi kenyataan".

## 26. KLARIFIKASI: Owner vs Customer (dikonfirmasi user, bukan bug)

Dikonfirmasi eksplisit: kolom `Owner` di Ivanti = SOC analyst yang MENGERJAKAN
tiket (dipakai di sheet Soc Individual Kpi & Analyst). Kolom `Customer` = PIC/
pihak TUJUAN tiket, yaitu target/terdampak insiden (dipakai di sheet
Entity_Correlation). Implementasi sudah benar sejak awal, tapi teks deskripsi
di Reading Guide & Hypothesis Insight diperjelas eksplisit supaya tidak
disalahartikan sebagai "SOC analyst yang paling banyak tersangkut" - ini soal
TARGET serangan, bukan beban kerja analyst.

## 27. FIXED: Urutan Severity_Priority_Mismatch salah (yang berbahaya terkubur)

Sheet sebelumnya diurutkan alfabetis berdasarkan kolom Arah, sehingga
"Over-prioritized" (aman) muncul duluan dan "UNDER-PRIORITIZED" (berbahaya, cuma
5 dari 191 baris) terkubur di bawah - baru kelihatan kalau di-scroll jauh.
Diperbaiki: urutan dibalik supaya UNDER-PRIORITIZED selalu tampil paling atas.

## 28. BARU: Insight ke-4 - Outcome (Prevention Rate & False Positive Rate)

Kolom `Cause Code` & `Status` di tiket Ivanti ternyata menyimpan hasil akhir
investigasi yang belum pernah dipakai. Sheet baru `Outcome_Summary` + insight
H-Outcome: berapa % tiket berhasil DICEGAH (Prevented) vs benar-benar jadi
BREACH (Breach - Reported), dan berapa % ternyata false positive (status
Cancelled). Temuan dari data Juli: 56.9% prevention rate, 28 tiket
Breach-Reported, 25.6% false positive rate - TAPI 197 dari 262 tiket (75%)
belum punya Cause Code sama sekali, jadi angka ini baru mewakili sebagian
kecil tiket yang sudah diklasifikasi tuntas, bukan representasi penuh 1 bulan.

## 29. BUG DIPERBAIKI (dikonfirmasi user): Skala Priority Ivanti ternyata 0-based

Sebelumnya diasumsikan Priority 1=Critical, 2=High, 3=Medium, 4=Low (1-based).
User mengonfirmasi skala yang benar di organisasi ini adalah 0-based:
**0=Critical, 1=High, 2=Medium, 3=Low**. Ini menggeser SEMUA mapping severity-dari-
priority satu tingkat.

Dampak ke hasil Severity vs Priority Mismatch (data Juli 2026):
- Total mismatch: 191 -> 91 baris
- UNDER-PRIORITIZED (kasus berbahaya): **5 (2.4%) -> 23 (11.0%)** - signifikan
  lebih tinggi dari yang dilaporkan sebelumnya.

Kalau skala priority berbeda lagi antar sistem/kustomer, sesuaikan dict
`priority_to_severity` di `build_severity_priority_mismatch()` (core/processor.py).

## 30. BARU: Modul PPTX Generator (core/pptx_writer.py)

PPT otomatis chart-heavy sesuai referensi format BoD - MENGONSUMSI data yang
SAMA PERSIS dengan Excel/Streamlit (dari `report` dict hasil SOCProcessor.run(),
tidak menghitung ulang apapun secara terpisah) - menjamin angka & chart di PPT,
Excel, dan Streamlit selalu konsisten satu sama lain.

Slide yang di-generate: Cover, Executive Summary (3 grup), Key Findings (dari
Hypothesis Insight), Top 10 Rule, Distribusi Domain, Workload Analyst, Coverage
Non-Splunk, Pola Waktu Alert. Semua chart native PowerPoint (bisa diedit/diklik),
bukan gambar statis.

Terintegrasi ke:
- `main.py` - otomatis generate PPTX setelah Excel setiap run CLI
- `app.py` - tombol Download PPTX terpisah dari Download Excel, sama-sama
  di-generate langsung setelah klik "Generate Report"

Divalidasi dengan `scripts/office/validate.py` (skill pptx) - semua
pengecekan struktur/chart/schema PASSED.

## 31. FIXED: Jam kerja salah (dikonfirmasi user: 09:00-18:00, bukan 08:00-17:00)

`build_time_pattern()` diperbaiki: business hour sekarang 09:00-18:00 WIB
Senin-Jumat (sebelumnya salah diasumsikan 08:00-17:00). Kalau shift SOC
berbeda lagi, ubah `alert_dates.dt.hour.between(9, 17)` di processor.py.

## 32. KLARIFIKASI: 2 konsep "breach" yang berbeda, sengaja/kebetulan sama nama

Sheet `Breach` (2 baris) = tiket yang MELANGGAR SLA (kolom `Breach ?` di Ivanti,
soal waktu respons). Insight H-Outcome yang sebut "28 tiket Breach - Reported"
= kolom `Cause Code`, soal insiden yang BENAR-BENAR jadi breach keamanan (soal
hasil investigasi, bukan waktu). Dua hal yang tidak berhubungan, sayangnya sama
istilah "breach". TODO kalau ada waktu: ganti nama kolom biar tidak rancu -
`SLA_Breach` vs `Security_Breach_Reported`.

## 33. FIXED: Kemungkinan penyebab Download PPT cancel (Excel sudah normal)

Karena Excel sudah bisa didownload normal, kemungkinan besar penyebab PPT masih
cancel adalah file `output/SOC_Report_{periode}.pptx` dari percobaan
sebelumnya masih ter-lock (umum terjadi di Windows kalau file sempat kebuka
di PowerPoint, atau proses sebelumnya belum benar-benar release file handle-nya).
`PPTXWriter.export()` sekarang menangkap `PermissionError` saat menyimpan dan
otomatis fallback ke nama file dengan timestamp kalau path utama terkunci -
tidak gagal diam-diam lagi.

## 34. BARU: Severity Breakdown - distribusi tiket per severity

Sheet baru `Severity_Breakdown` + chart pie (Excel & PPT) + bar chart (Streamlit):
jumlah tiket dikelompokkan Critical/High/Medium/Low (bukan cuma nomor P0-P3).
Temuan dari data Juli: 80.2% tiket berada di severity High, sangat jarang
Critical (0%) - insight ini bagus untuk cek apakah threshold Critical di
Ivanti pernah benar-benar dipakai atau selalu default ke High.

## 35. BARU: Tren Harian dalam Periode (Daily Trend)

Sheet baru `Daily_Trend` + line chart (Excel & PPT) + Streamlit: jumlah alert
& insiden per TANGGAL (bukan per jam/hari-dalam-minggu seperti Time_By_Hour/Day
yang sudah ada). Insight H-DailyTrend menandai tanggal dengan alert terbanyak
vs rata-rata harian. Temuan Juli: puncak di 5 Juli (399 alert, 2.2x rata-rata
harian 180.2) - kandidat dicek apakah ada insiden besar/anomali tuning di
tanggal itu.

## 36. BARU: Integrasi Task SOC (kerja "tak resmi" dari tim lain)

Sumber data baru: task pengecekan yang di-assign tim lain ke SOC TANPA insiden
ter-assign resmi (mis. tim lain minta SOC cek sesuatu, tercatat sebagai "Task"
bukan "Incident" di Ivanti) - selama ini beban kerja ini tidak kelihatan di
laporan sama sekali.

- File OPSIONAL per minggu: `task_soc...xlsx`, kolom wajib `Task`/`Subject`/
  `Status`/`Owner`/`Created On`. Kolom `Requestor_Team` (tim peminta) BELUM
  PASTI tersedia - kalau tidak ada, breakdown per-tim-peminta otomatis
  dilewati (tidak error), tinggal ditambahkan begitu file dari tim Ivanti
  sudah ada kolom itu.
- Sheet baru: `Task_Summary`, `Task_By_Owner`, `Task_By_Requestor` (kalau
  datanya ada), `Task_Weekly_Regularity` (buat lihat pola rutin per minggu
  dalam periode).
- `Soc Individual Kpi` diperluas: kolom `Total_Task` dan
  `Total_Workload (Insiden+Task)` - beban kerja SEBENARNYA analyst, bukan
  cuma insiden ter-assign. Sheet ini sekarang diurutkan berdasarkan total
  workload gabungan, bukan cuma insiden.
- Executive Summary grup baru "4. Task dari Tim Lain": total, completed,
  belum selesai, rata-rata task per minggu.
- Insight baru H-TaskWorkload.
- Sudah diuji dengan data simulasi 40 task (format sesuai screenshot user) -
  semua alur (load optional file, merge ke KPI, insight) berfungsi benar.
  File simulasi TIDAK disertakan di paket ini.

**Catatan sampingan dari testing**: ditemukan kemungkinan ada 2 variasi
penulisan nama analyst yang sama ("Ramzi Qudamah" vs "Ramiz Qudamah") di data
Owner asli - kalau benar typo, KPI individu analyst tsb kepecah jadi 2 baris
terpisah. Perlu dicek & dibersihkan di sumber data (Ivanti), bukan bug script.

## 37. BUG DIPERBAIKI (ditemukan user): Outcome_Summary tidak bisa dipertanggungjawabkan matematisnya

37 (Prevented) + 28 (Breach) + 67 (Cancelled) + 197 (Belum Cause Code) = 329,
padahal Total Tiket cuma 262. Root cause: 4 baris itu digabung dalam 1 tabel
seolah kategori yang saling eksklusif, padahal berasal dari 2 KOLOM BERBEDA
yang independen (Cause Code vs Status) - bisa tumpang tindih.

Diperbaiki, dipecah jadi 3 sheet terpisah dengan penjelasan eksplisit:
- `Cause_Code_Breakdown`: Prevented + Breach-Reported + Belum Diklasifikasi -
  SALING EKSKLUSIF, sekarang ada assert() di kode yang GAGAL kalau jumlahnya
  tidak persis sama dengan Total Tiket (self-check otomatis).
- `Status_Summary`: Cancelled (dimensi terpisah, dari kolom Status)
- `Cancelled_Crosstab`: rincian dari tiket Cancelled, apa Cause Code-nya -
  supaya overlap-nya transparan, bukan cuma angka berdiri sendiri.

Temuan tambahan dari crosstab: SEMUA 67 tiket Cancelled ternyata memang
belum punya Cause Code (masuk akal - tiket dibatalkan tidak perlu diklasifikasi
prevented/breach). Artinya dari 197 "belum diklasifikasi", cuma 130 yang
benar-benar jadi gap operasional (bukan 197 seperti kesan sebelumnya).

## 38. BARU: Alur baca Streamlit dinomori & lebih jelas

Ditambahkan pengantar alur baca + penomoran section (1-6) dengan divider dan
caption singkat tiap section: Executive Summary -> Temuan Utama -> Visualisasi
-> Insight Lanjutan -> SOC Individual KPI -> Detail Data Lengkap. Sebelumnya
semua section menyatu tanpa penanda urutan, membingungkan saat presentasi.

## 39. RESTRUKTURISASI BESAR: Laporan jadi 8 bab terstruktur (Excel + PPT + Streamlit konsisten)

Sesuai diskusi & mockup yang disetujui user, seluruh laporan (Excel, PPT,
Streamlit) sekarang mengikuti struktur narasi yang SAMA:

1. Master Rules Database
2. Splunk vs Ivanti (+ Domain distribution, + Entity Multi-Vektor, + deep-dive
   dampak/rekomendasi per Top 10 Rule)
3. Non-Splunk vs Ivanti (matematika CTI diperbaiki - CTI adalah SUBSET dari
   "Tidak Jadi Tiket", bukan kategori tambahan)
4. Task dari Tim Lain
5. Tren Alert (+ rule kontributor terbesar tiap tanggal - korelasi trend
   dengan top rule sesuai permintaan user)
6. Efektivitas & Severity (+ root-cause: Cause Code per domain, breakdown
   "Belum Diklasifikasi" per Status, tiket Closed-tanpa-CauseCode per
   analyst, rule/analyst paling sering under-prioritized)
7. Temuan Berulang (auto-hide kalau kosong)
8. KPI SOC per Analyst - DIPINDAH ke paling akhir sesuai permintaan user,
   berisi TABEL LENGKAP seluruh nama analyst + MTTR + jumlah tiket breach +
   breach rate (bukan cuma ringkasan)

Perubahan teknis:
- `processor.py`: report dict di-reorder mengikuti 8 bab (menentukan urutan
  sheet Excel otomatis), + 6 method baru (build_domain_recommendation, root-
  cause breakdowns di build_outcome_insight & build_severity_priority_mismatch,
  rule kontributor di build_daily_trend, breakdown CTI di
  build_nonsplunk_coverage)
- `app.py`: seluruh MAIN AREA ditulis ulang jadi 8 expander per bab (bab 1-2
  default terbuka, sisanya tertutup)
- `pptx_writer.py`: ditulis ulang total - section divider slide per bab,
  slide deep-dive Top 10 Rule, tabel KPI SOC lengkap di slide terakhir

**Temuan konkret dari root-cause baru** (data Juli 2026): 110 tiket sudah
CLOSED tapi Cause Code tidak pernah diisi (kelalaian, bukan pending). Rule
"Cynet - Insertion of Storage" paling sering under-prioritized (4x). Lonjakan
5 Juli 88% berasal dari 1 rule ("Linux GCP SSH Brute Force Attempt").

## 40. Klarifikasi & Perbaikan (batch review user)

- **"Rule Belum Ter-mapping"** = sama dengan sheet Unmapped (rule tidak ditemukan
  di Master Rules).
- **FIXED**: deep-dive Top 10 Rule di PPT sebelumnya cuma tampil 6 (potong
  karena ruang slide), padahal chart & judul bilang "Top 10" - tidak konsisten.
  Sekarang dipecah 2 slide (5 rule/slide) supaya tetap 10 rule utuh.
- **BARU**: `build_weekly_trend()` - untuk periode > 10 hari (laporan bulanan),
  chart tren UTAMA sekarang mingguan (bukan harian yang terlalu detail).
  Detail harian tetap ada untuk drill-down. Laporan mingguan tetap pakai
  harian sebagai utama (otomatis terdeteksi dari `is_long_period`).
- **Pola Jam/Hari dipertahankan** terlepas dari granularitas tren - karena ini
  jawab pertanyaan berbeda (kapan dalam 1 hari/minggu rawan, untuk shift SOC),
  bukan soal tren naik-turun.
- **Severity_Breakdown diperjelas**: label diganti jadi eksplisit "dari sisi
  IVANTI (Priority tiket)" - BUKAN severity rule Splunk, supaya tidak
  disalahartikan. "Tidak Diketahui" diganti jadi "Priority Kosong (Ivanti)".
- **Cause_Code_Breakdown - definisi ditambahkan LANGSUNG ke laporan** (bukan
  cuma dijelaskan sekali): Prevented = kontrol keamanan berhasil mencegah;
  Breach - Reported = ancaman benar-benar menembus. Field ini diisi MANUAL
  oleh analyst saat closing tiket - disimpulkan dari nama field, ditandai
  perlu dikonfirmasi ke tim terkait karena bukan dari dokumentasi resmi.
- **BUG DITEMUKAN & DIPERBAIKI**: `build_recurring_findings()` gagal (TypeError
  sort mixed string/Timestamp) saat histori `database/rule_history.csv` sudah
  pernah ditulis sebelumnya - kolom Period_End jadi string setelah round-trip
  CSV, bentrok dengan Timestamp dari run baru. Diperbaiki dengan eksplisit
  `pd.to_datetime()` setelah baca CSV. Diuji jalan 2x berturut-turut tanpa error.
- **Modul Weekly diuji ulang eksplisit** (bukan cuma monthly yang selama ini
  jadi fokus) - Excel & PPT berhasil, `is_long_period=False` otomatis
  terdeteksi benar untuk periode 7 hari.

## 41. Perbaikan batch besar (review mendalam user)

1. **Download gagal di Firefox, sukses di Chrome**: kemungkinan besar soal
   pengaturan/ekstensi Firefox (bukan bug di kode - mekanisme download
   Streamlit standar). Cek `about:preferences` bagian Downloads, atau
   nonaktifkan sementara ekstensi/antivirus scan Firefox untuk uji coba.
   Tidak ada perubahan kode yang bisa memastikan ini dari sisi server.

2. **BARU**: chart persentase (Bab 1) - distribusi Enabled/Disabled/Belum
   Ter-mapping (sheet `Master_Status_Distribution`).

3. **BARU**: chart persentase (Bab 2) - distribusi status rule Healthy/
   Acceptable/Noise/Tuning/Dormant (sheet `Rule_Recommendation_Distribution`).

4. **BUG DIPERBAIKI**: threshold `KEEP_THRESHOLD=10` bikin SEMUA rule dengan
   Detection Rate >=10% dilabel "Healthy" - termasuk yang cuma 16%,
   menyesatkan. Ditambah tier baru **"Acceptable"** (10-25%) di
   `config/settings.py` (`HEALTHY_THRESHOLD=25`) - "Healthy" sekarang cuma
   untuk rule >=25%, benar-benar berarti "bagus". Ditemukan juga blok
   threshold DUPLIKAT di settings.py (2x definisi sama) - sudah dihapus
   duplikatnya.

5. **BARU**: definisi Noise/Tuning/Acceptable/Healthy/Dormant ditulis
   eksplisit LANGSUNG di laporan (caption Bab 2 Streamlit + slide definisi
   di PPT), bukan cuma di Reading Guide yang perlu dibuka manual.

6. **BARU**: label "Rule Summary" di app.py sekarang punya caption jelas
   ("tabel INDUK semua rule... - sheet lain adalah HASIL FILTER dari ini").

7. **FIXED**: tabel Tren Mingguan/Harian sebelumnya TIDAK menampilkan kolom
   Jumlah_Insiden (cuma Jumlah_Alert) - sekarang lengkap. Chart line gabungan
   yang bikin garis insiden "hilang" (skala ribuan vs puluhan) diganti jadi
   2 chart terpisah (Alert & Insiden masing-masing). Ditambah **catatan
   cakupan eksplisit**: tren ini HANYA Alert Splunk + Insiden Ivanti dari
   Splunk - TIDAK termasuk alert non-Splunk (yang datanya ada di Bab 3,
   belum ada tren waktunya).

8. **Pola Jam/Hari diperjelas**: caption sekarang eksplisit bilang ini
   TOTAL alert dijumlahkan dari SEMUA tanggal dalam periode dikelompokkan
   per jam/hari-dalam-minggu - BUKAN rata-rata harian/mingguan, dan
   independen dari granularitas tren (tetap relevan untuk shift SOC
   walau tren utamanya mingguan).

9. **Avg_MTTR_sec diperjelas**: caption eksplisit di Bab 8 (app.py) dan
   catatan di slide tabel KPI (PPT) - MTTR = Created On -> Responded On
   (waktu respons PERTAMA), BUKAN waktu sampai tiket selesai/resolved.

## 42. RESTRUKTURISASI: Bab Master Rules digabung ke Bab Splunk vs Ivanti (8 bab -> 7 bab)

Sesuai permintaan user - metrik "Total Rule Terdaftar" dan "Disabled" dianggap
tidak perlu, cukup "Rule Splunk Active" (jumlah Enabled). Struktur baru:

1. Splunk vs Ivanti (Rule Splunk Active, Belum Ter-mapping, Total Alert,
   Total Insiden, Gap, Noise, Dormant, Tuning, Detection Rate - SEMUA
   digabung jadi 1 bab, bukan 2 terpisah)
2. Non-Splunk vs Ivanti
3. Task dari Tim Lain
4. Tren Alert
5. Efektivitas & Severity
6. Temuan Berulang (auto-hide)
7. KPI SOC per Analyst

Diterapkan konsisten di `processor.py` (Executive Summary), `app.py` (7
expander, dari sebelumnya 8), dan `pptx_writer.py` (7 chapter method,
dari sebelumnya 8) - diuji ulang end-to-end, 25 slide PPT, validasi PASSED.

## 43. Integrasi data Task SOC ASLI (bukan simulasi lagi)

Data real dari user (`Example_Data_Task_SOC_Juli_2026.xlsx`) ternyata punya
struktur kolom BEDA dari asumsi awal (berdasarkan screenshot) - untung dicek
dulu sebelum dipakai:

- `TaskID` (bukan `Task`), `status` huruf kecil (bukan `Status`),
  `CreatedDateTime`/`CompleteDateTime` (bukan `Created On`/`Completed On`).
- Kolom BONUS yang ternyata ada: `AcceptedDateTime`, `Duration Complete
  (Minutes)` (durasi SUDAH DIHITUNG Ivanti - dipakai langsung, tidak dihitung
  ulang), `Response_meet/breach` & `Resolution_meet/breach` (SLA breach SUDAH
  ADA dari Ivanti, dipakai langsung untuk metrik baru "Response/Resolution
  SLA Breach").
- Kolom `Requestor_Team` TIDAK ADA di export Ivanti - breakdown per tim
  peminta tetap graceful di-skip (sudah didesain begitu sejak awal).

**BUG DITEMUKAN & DIPERBAIKI**: modul Task Ivanti pakai nama pendek/username
("alif") sedangkan modul Incident pakai nama lengkap ("Alif Elang
Abhipraya") - kalau dibiarkan, KPI SOC pecah jadi baris terpisah untuk orang
yang sama (13 baris, seharusnya 10). Diperbaiki dengan pencocokan nama
otomatis (short name dicocokkan sebagai kata utuh di nama lengkap Owner
insiden) - kalau match ganda/tidak ketemu, dibiarkan apa adanya dan dicatat
di sheet baru `Task_Unmatched_Owner` untuk direview manual.

`loader.py` (`load_task_from_file`) & `processor.py` (`build_task_summary`)
diperbaiki total sesuai struktur asli, diuji end-to-end dengan file real
user (bukan simulasi), Excel & PPT keduanya sukses.

## 44. BUG KRITIS DIPERBAIKI: Data Task tidak pernah masuk ke Streamlit sama sekali

Ditemukan: `run_pipeline()` di app.py TIDAK PERNAH menerima parameter task di
KETIGA mode Streamlit (Weekly-Upload, Weekly-Folder, bahkan Monthly yang
sebenarnya sudah berhasil load task datanya dari `loader.load()` tapi tidak
diteruskan). Ini kenapa data task tidak pernah muncul di Streamlit meskipun
modul backend-nya (loader.py, processor.py) sudah benar - CLI (`main.py`)
tidak kena bug ini karena jalur kodenya beda.

Diperbaiki:
- `run_pipeline()` sekarang menerima parameter `task` (default None -> DataFrame kosong)
- Mode "Upload file baru": ditambahkan file uploader "Task SOC dari Ivanti (.xlsx)"
  yang sebelumnya TIDAK ADA sama sekali di sidebar
- Mode "Folder input/weekly yang sudah ada": ditambahkan `loader.load_task_from_file()`
  + filter rentang tanggal (sama seperti nonsplunk)
- Mode Monthly: `data["task"]` sekarang diteruskan ke `run_pipeline()`

Diuji dengan mensimulasikan persis alur Streamlit "Folder yang sudah ada"
memakai file task real user - data task sekarang benar-benar muncul di
`task_summary`, `task_by_owner`, dst.

## 45. BARU: 4 Advanced Insight sesuai arahan manajemen

Bab baru **"8. Threat Profiling & Attack Surface"** (di Excel, PPT, dan
Streamlit) + perluasan Bab 5:

1. **Threat Profiling per P0/P1/P2/P3** (`Threat_By_Priority`,
   `_Domain`, `_Target`) - threat/rule paling sering per tier priority,
   disilang dengan domain & target. CATATAN: "asset"/"target" adalah PROXY
   dari Security_Domain & Customer - export Splunk/Ivanti tidak punya data
   inventaris aset (CMDB) sungguhan.
2. **Attack Surface Tracking lintas periode** (`Attack_Surface_Trend`,
   `database/attack_surface_history.csv`) - domain mana yang KONSISTEN
   bermasalah dari periode ke periode, bukan cuma 1 snapshot. Butuh
   minimal 2 periode histori.
3. **Priority Insiden per Rule Splunk** (`Priority_Per_Rule`) - breakdown
   P0/P1/P2/P3 untuk tiap rule, supaya kelihatan rule mana yang paling
   banyak hasilkan insiden KRITIKAL, bukan cuma banyak insiden.
4. **Resolved->Closed timeline** (`Resolved_Closed_Stats`) - waktu dari
   Resolved ke Closed, termasuk deteksi tiket yang langsung Closed tanpa
   jeda (potensi tanpa review). **Lesson Learned Log** (`Lesson_Learned_Log`)
   - diambil dari modul TASK, BUKAN Incident, karena export Incident Ivanti
   TIDAK punya kolom catatan/resolusi bertuliskan bebas (sudah dicek
   langsung ke data, tidak bisa dipaksakan).

Temuan nyata dari data Juli: rule "Cynet - Insertion of Storage" adalah
threat P1-High PALING SERING (23x) SEKALIGUS rule yang paling sering
under-prioritized (4x) - dua insight independen saling menguatkan temuan
yang sama. Resolved->Closed rata-rata ~70 jam, 0 tiket ditutup tanpa jeda
(tidak ada indikasi auto-close tanpa review).

## 46. BUG DIPERBAIKI: Resolved->Closed & Lesson Learned Log tidak pernah muncul di PPT

Sudah ada di Excel dan Streamlit (Bab 5 Efektivitas & Severity) sejak
poin #45, tapi TIDAK PERNAH ditambahkan ke `pptx_writer.py` - konsistensi
3 output (Excel/Streamlit/PPT) sempat pecah. Sudah diperbaiki, sekarang
2 slide baru muncul di PPT Bab 5: "Resolved -> Closed: Timeline & Potensi
Tanpa Review" dan "Lesson Learned Log (dari modul Task)". Diuji dengan
data task real user (`Example_Data_Task_SOC_Juli_2026.xlsx`, kolom
Resolution berisi catatan investigasi asli) - 3 baris lesson learned
berhasil muncul di ketiga output.

## 47. RESTRUKTURISASI BESAR: Streamlit jadi gaya Tableau (tab navigasi + filter + Help)

Sesuai mockup yang disetujui user - struktur expander bertumpuk (bikin scroll
panjang, membingungkan) diganti total jadi navigasi tab ala Tableau:

**9 tab**: Overview, Splunk vs Ivanti, Threat Profiling, Non-Splunk, Task SOC,
Tren, Efektivitas, KPI Analyst, Help - klik pindah tab, bukan scroll.

**Filter fungsional di sidebar** (bukan dekorasi): Analyst, Domain, Priority -
otomatis menyaring tabel/chart yang relevan lewat fungsi generik `apply_filter()`
(cek dulu kolomnya ada di tabel, baru filter - supaya tidak error di tabel yang
memang tidak punya dimensi itu). Diuji ke SEMUA titik pemakaian filter dengan
data real sebelum diserahkan - tidak ada error.

**Tab Help baru**: glossary A-Z dari semua 33 sheet/metrik, diambil dari
Reading Guide yang sudah ada (tidak duplikasi data, cuma disortir & ditampilkan
beda).

**Tab Overview baru**: gabungan semua Executive Summary group + semua Key
Findings di 1 tempat, untuk yang cuma butuh ringkasan cepat.

Threat Profiling & Attack Surface + Recurring Findings sekarang jadi 1 tab
tersendiri (sebelumnya tercampur/terpisah tidak konsisten).

## 48. BARU: CSS custom + Plotly untuk visual lebih halus

- **CSS custom** (`st.markdown(unsafe_allow_html=True)`): kartu KPI dengan
  background & border halus, tab dengan warna aksen navy saat aktif, sidebar
  warna beda, expander dengan border rounded - mendekati mockup yang
  disetujui sebelumnya.
- **14 chart diganti dari `st.bar_chart`/`st.line_chart` (polos) ke Plotly**
  (interaktif, warna konsisten, hover tooltip, label angka langsung di bar,
  pie chart untuk distribusi proporsi). Helper baru: `plot_bar()`,
  `plot_bar_multi()`, `plot_pie()`, `plot_line()`.
- **Fallback otomatis**: kalau `plotly` belum ter-install, semua helper
  otomatis pakai `st.bar_chart`/`st.line_chart` biasa - TIDAK bikin app
  crash. `plotly` ditambahkan ke `requirements.txt`.
- **Catatan jujur**: sandbox pengembangan tidak punya akses internet untuk
  install & test Plotly secara langsung. Sebagai gantinya, seluruh 11 titik
  pemanggilan Plotly (`plot_bar`/`plot_bar_multi`/`plot_pie`) sudah
  di-smoke-test pakai stub module yang memvalidasi nama kolom & parameter
  persis ke data report asli - tidak ada error nama kolom/parameter salah.
  Tetap disarankan Anda coba jalankan dan laporkan kalau ada yang aneh
  secara visual (styling/rendering asli belum bisa saya lihat langsung).

## 49. BUG DITEMUKAN & DIPERBAIKI: requirements.txt korup

Baris "python-pptx" dan "plotly" sempat tergabung jadi 1 baris tunggal
"python-pptxplotly" akibat operasi echo append tanpa newline di sesi
sebelumnya - kalau tidak ketahuan, `pip install -r requirements.txt` akan
gagal mencari package "python-pptxplotly" yang tidak ada. File ditulis ulang
bersih dari awal.

## 50. BARU: Tren Severity Lintas Periode + Action Tracker (Tracking Improvement)

Menjawab gap yang ditemukan user - 2 kebutuhan yang SEBELUMNYA belum
tercakup meski terlihat mirip fitur yang sudah ada:

1. **Severity Trend** (`Severity_Trend`, tab Efektivitas) - tren jumlah
   tiket Critical/High/Medium/Low LINTAS PERIODE (bukan snapshot 1 periode
   seperti Severity_Breakdown yang sudah ada sebelumnya). Histori otomatis
   tersimpan ke `database/severity_history.csv` tiap generate, butuh
   minimal 2 periode untuk mulai bermakna - baru 1 periode akan muncul
   pesan "menunggu periode berikutnya", bukan chart kosong yang membingungkan.
   Insight H-SeverityTrend: arah NAIK/TURUN/STABIL untuk Critical+High.

2. **Action Tracker** (`Action_Tracker`, tab Threat Profiling) - KONSOLIDASI
   semua rule yang PERNAH ditandai Noise/Tuning di periode manapun, dengan
   status eksplisit: 🔴 **Masih Terbuka** (masih bermasalah periode ini)
   vs ✅ **Sudah Membaik** (dulu bermasalah, sekarang sudah tidak lagi
   muncul di kategori itu) - ini yang beda dari `Recurring_Findings` yang
   sudah ada sebelumnya (Recurring Findings cuma menunjukkan yang TERUS
   bermasalah, tidak menunjukkan mana yang SUDAH selesai ditindaklanjuti).
   Pakai histori yang sama (`database/rule_history.csv`), tidak duplikasi
   mekanisme. Insight H-ActionTracker: Improvement Rate (% rule yang sudah
   membaik dari total yang pernah ditandai).

Ditambahkan konsisten ke Excel, PPT, dan Streamlit. Diuji 2x run berturut-
turut tanpa error.

## 51. RESTRUKTURISASI: Streamlit fokus MONTHLY-only, upload langsung (bukan gabungan folder mingguan)

Sesuai arahan user - fitur Weekly di Streamlit disembunyikan sementara
(BUKAN dihapus dari codebase - `main.py` CLI masih mendukung Weekly kalau
suatu saat dibutuhkan lagi, cukup diaktifkan lagi di app.py). Streamlit
sekarang cuma punya 1 alur: upload data periode (biasanya 1 bulan) LANGSUNG,
tanpa perlu disusun dulu jadi folder-folder mingguan.

**Perubahan sidebar:**
- Mode radio (Weekly/Monthly) DIHAPUS dari tampilan
- **BARU**: uploader "Master Rules Splunk (.xlsx)" - SEBELUMNYA tidak ada
  sama sekali di Streamlit (selalu baca file tetap di `input/master/`) -
  sekarang bisa upload langsung dari sidebar. Kalau tidak diupload, fallback
  ke file default kalau ada.
- **BARU**: uploader "Domain Mapping (.xlsx)" - opsional, sama polanya
  dengan Master Rules.
- **BARU**: input teks "Label Periode" (mis. "2026-07") - bebas diisi
  sesuai kebutuhan, tidak terikat penamaan folder minggu lagi.
- Upload: Alert Splunk, Insiden Ivanti (wajib) + Alert NonSplunk, Task SOC
  (opsional) - SEMUA untuk periode penuh sekaligus, bukan per-minggu.

Diuji dengan mensimulasikan upload "1 bulan penuh" (gabungan data 3 minggu
jadi 1 file, seperti skenario upload asli) memakai Label Periode manual
"2026-07" - seluruh pipeline (termasuk period detection otomatis,
is_long_period, severity trend, action tracker) tetap berjalan benar TANPA
bergantung pada struktur folder `input/weekly/` sama sekali.

## 52. BARU: Dukungan upload .csv (selain .xlsx)

Ditambahkan `read_any_table()` di `utils/helpers.py` - fungsi universal baca
tabel yang otomatis deteksi `.xlsx` vs `.csv` dari ekstensi nama file.
Diterapkan ke: Master Rules Splunk, Domain Mapping, Alert Splunk, Insiden
Ivanti, Task SOC.

**Alert NonSplunk TETAP wajib .xlsx** - butuh 3 sheet sekaligus (Akamai/
CSPM/Microsoft Defender), CSV secara struktural cuma bisa 1 sheet, tidak
bisa dipaksakan.

**Catatan penting**: dukungan CSV ini soal FORMAT FILE saja - nama kolom
di dalamnya tetap harus sama persis dengan yang diharapkan pipeline
(Rule_ID/Rule_Names/Rule_Status untuk Master Rules, dst). Diuji dengan
file CSV asli (`Database_Alert_Splunk_29July.csv`) - terbaca sukses, plus
xlsx (dengan & tanpa sheet_name) tetap berfungsi normal seperti sebelumnya.

## 53. BUG KRITIS DIPERBAIKI (ditemukan dari data real user): CSV delimiter & skema Master Rules

Ditemukan langsung dari file production user (`Database-Rules-Splunk-July-2026.csv`):

1. **CSV pakai delimiter titik-koma (;), bukan koma** - `read_any_table()`
   sebelumnya cuma pakai `pd.read_csv()` default (asumsi koma), hasilnya
   SATU kolom raksasa gabungan semua field. Diperbaiki: `sep=None,
   engine="python"` (auto-deteksi delimiter) + fallback eksplisit ke `;`
   kalau auto-detect tetap gagal.

2. **Skema kolom Master Rules beda dari yang diasumsikan** - file user
   cuma punya `No`/`title`/`security_domain`/`severity`, TIDAK ADA
   `Rule_ID`/`Rule_Names`/`Rule_Status` yang dipakai pipeline. Ditambahkan
   `normalize_master_rules_columns()` di `utils/helpers.py`: rename
   otomatis (`title`->`Rule_Names`, `No`->`Rule_ID`,
   `security_domain`->`Security_Domain`), generate `Rule_ID` kalau tidak
   ada, dan `Rule_Status` diisi `"Unknown"` (BUKAN ditebak Enabled/Disabled)
   dengan warning eksplisit kalau kolom itu tidak ada - supaya Enabled/
   Disabled count di Executive Summary jujur 0 daripada salah klaim.

3. **BUG TERPISAH ditemukan dari test yang sama**: `build_rule_summary()`
   crash `KeyError: 'Security_Sub_Domain'` kalau master cuma punya
   `Security_Domain` TANPA `Security_Sub_Domain` (kasus umum - banyak
   export Splunk cuma py domain besar, tidak sampai sub-domain).
   Diperbaiki: `Security_Sub_Domain` di-generate otomatis ("Others") kalau
   tidak ada, tidak lagi crash.

Diuji end-to-end LENGKAP dengan 3 file asli user (2 CSV + 1 xlsx, data
production Juli 2026 - 5001 alert, 609 insiden) - Excel & PPT berhasil
digenerate tanpa error.

## 54. Perbaikan batch UI/UX (review mendalam user)

1. **Judul "SOC Weekly / Monthly Report" -> "SOC Monthly Report"** - sesuai
   fokus monthly-only.
2. **Tab "Splunk vs Ivanti" -> "Ticket"** (lebih intuitif), label grup
   Executive Summary disamakan jadi "1. Ticket".
3. **Warning eksplisit di UI** kalau Master Rules tidak punya kolom status -
   sebelumnya cuma tercatat di log console yang tidak kelihatan user,
   sekarang muncul st.warning() jelas kenapa "Rule Splunk Active" = 0.
4. **Overview sekarang selalu tampilkan status Task & Non-Splunk** (meski
   belum ada datanya - dengan caption "Belum ada data" daripada hilang
   tanpa jejak).
5. **BARU: Tab "📊 Perbandingan Bulanan"** - jawaban langsung untuk
   "dimana lihat tracking/perbandingan semua bulan yang sudah diupload?"
   Berisi: Total Alert/Insiden per periode, Detection Rate trend, Severity
   trend, Attack Surface trend - SEMUA periode yang pernah digenerate
   (bukan dibatasi 5-6 terakhir seperti Severity/Attack Surface Trend).
   Sheet baru `Monthly_Comparison` (`database/monthly_summary_history.csv`).
6. **BARU: "📁 Laporan Tersimpan"** di tab Perbandingan Bulanan - daftar
   file Excel/PPT yang sudah pernah digenerate di folder `output/`, bisa
   didownload ulang tanpa perlu generate lagi - menjawab "dimana lihat
   report bulan yang sudah diupload sebelumnya?"
7. **Tab Tren & Efektivitas disederhanakan**: 1 kalimat tujuan jelas di
   awal ("Menjawab: kapan..." / "Menjawab: seberapa efektif..."), detail
   teknis/definisi dipindah ke expander collapsed (tidak langsung penuh
   teks), severity trend duplikat (sudah ada di Perbandingan Bulanan)
   dihapus dari tab Efektivitas.
8. Caption 1-kalimat penjelasan ditambahkan ke tab Ticket, Threat
   Profiling, Non-Splunk, Task SOC, KPI Analyst untuk konsistensi.

Diuji dengan simulasi 2 periode berurutan (data Juli dipecah 2 bagian) -
Monthly Comparison terisi benar (1 baris -> 2 baris), Excel & PPT keduanya
sukses.

## 55. BUG KRITIS DIPERBAIKI: Kunci histori periode salah (sebab "01-18 Jul" nyangkut)

Root cause dari temuan user (screenshot Severity Trend menampilkan "periode
01 Jul - 18 Jul 2026" padahal user cuma upload 1 bulan penuh): SELURUH
mekanisme histori (Recurring Findings, Attack Surface Tracking, Severity
Trend, Monthly Comparison) memakai `period_label_text` (teks tanggal
OTOMATIS dari rentang data asli) sebagai KUNCI penyimpanan/dedup - BUKAN
Label Periode yang diketik user. Karena teks otomatis ini bisa beda-beda
tiap kali generate (tergantung rentang tanggal persis di data yang
diupload saat itu), setiap variasi kecil data dianggap "periode baru" yang
terus menumpuk di histori, tidak pernah tergantikan.

Diperbaiki: ditambahkan `self.period_key` (nilai `data["week"]`/Label
Periode yang diketik user, mis. "2026-07") sebagai kunci STABIL untuk semua
histori - `period_label_text` (teks tanggal otomatis) sekarang HANYA
dipakai untuk kalimat narasi ("periode 01 Jul - 31 Jul 2026"), tidak lagi
untuk pelacakan lintas periode. Diuji: generate 2x dengan Label Periode
sama ("2026-07") tapi jumlah data beda - hasil tetap 1 baris di histori
(ter-update, bukan nambah).

## 56. FIXED: Deteksi status rule tidak fleksibel ("Rule Splunk Active: 0")

Sebelumnya cuma mendeteksi kolom bernama persis "Rule_Status". Diperluas
mendeteksi variasi nama umum (status/Active/Enabled/State/Aktif) DAN
menormalisasi NILAI-nya (Active/Yes/1/True -> "Enabled", Inactive/No/0/
False -> "Disabled") - supaya file dengan struktur berbeda-beda tetap
terhitung benar. Kalau ada >1 kolom yang mirip status (ambigu), TIDAK
menebak sembarangan - tetap "Unknown" dengan warning, lebih baik kosong
daripada salah pilih.

## 57. BARU: Modul CTI FortiRecon (kategori baru sesuai permintaan user)

Sumber data baru: alert threat intelligence eksternal (Stealer Infection,
EASM Change, dll) yang selama ini cuma di-track manual di Excel tanpa
reporting bulanan.

**KEAMANAN (prioritas utama)**: kolom Password dari sumber data mengandung
KREDENSIAL BOCOR ASLI (plaintext) - nilai ini TIDAK PERNAH disimpan/
ditampilkan di laporan manapun (Excel/PPT/Streamlit). Diganti jadi
indikator boolean `Password_Leaked` (ada/tidak) saja. Diverifikasi
eksplisit dengan test - password asli TIDAK ditemukan di sheet Excel
manapun setelah export.

Fitur: `CTI_Summary` (Total Alert, True/False Positive, Closed/In Progress,
indikator kredensial bocor), `CTI_By_Type` (breakdown Stealer Infection vs
EASM Change dst), `CTI_By_Status`, `CTI_Trend` (lintas periode, pola sama
seperti Severity/Attack Surface Trend - `database/cti_history.csv`).
Ditampilkan di tab gabungan "Non-Splunk & Task" (sub-section ke-3, supaya
tidak menambah jumlah tab). File opsional, prefix `cti_fortirecon`,
support .xlsx & .csv.

## 58. Simplifikasi tab (sesuai permintaan "terlalu banyak menu")

Tab "Non-Splunk" dan "Task SOC" digabung jadi 1 tab "Non-Splunk & Task"
(dengan 3 sub-section setelah CTI ditambahkan). Total tab: 9 (dari
sebelumnya 10, meski ada modul baru CTI - karena digabung bukan ditambah
tab terpisah). Tab Threat Profiling diberi pointer eksplisit ke tab
Perbandingan Bulanan untuk tren Critical/High/Medium/Low lintas periode
(supaya tidak duplikasi konten di 2 tempat).

Diuji end-to-end lengkap dengan 3 file asli user + 1 file CTI simulasi dari
data yang dilampirkan - Excel & PPT berhasil, password terverifikasi tidak
bocor.

## 59. BARU: Checkbox "Semua rule sudah Enabled" (konfirmasi eksplisit dari user)

User mengonfirmasi: file Master Rules yang diminta ke tim Splunk memang
sengaja di-filter cuma berisi rule yang SUDAH ENABLED ("harap export semua
rules splunk yang enabled") - jadi meski file tidak punya kolom status,
SEMUA baris di dalamnya valid dianggap Enabled.

Ini konteks bisnis yang TIDAK bisa ditebak dari data semata - jadi TIDAK
di-hardcode di kode, tapi dibuat jadi **checkbox eksplisit di sidebar**:
"File ini SEMUA rule sudah Enabled". User yang mengaktifkan, bukan sistem
menebak sendiri - supaya tetap aman kalau suatu saat upload file lain yang
konteksnya beda (belum tentu semua-enabled).

`normalize_master_rules_columns()` sekarang menerima parameter
`assume_all_enabled` - kalau True DAN tidak ada kolom status terdeteksi,
Rule_Status diisi "Enabled" (bukan "Unknown"). Diuji dengan file asli user:
"Rule Splunk Active" berubah dari 0 -> 256 (setelah dedup 26 rule
duplikat) saat checkbox diaktifkan.

## 60. BARU: "Buka Laporan Tersimpan" - tidak perlu upload ulang terus-menerus

Menjawab keluhan user: "sudah upload Juni & Juli, apa harus upload lagi tiap
buka aplikasi?" - JAWABANNYA SEBELUMNYA memang "ya, harus" karena hasil
report cuma tersimpan di session_state (hilang begitu browser ditutup/
refresh). Sekarang diperbaiki dengan mekanisme cache permanen:

- Setelah "Generate Report" berhasil, HASIL LENGKAP yang sudah diproses
  (bukan file mentah) otomatis disimpan ke `database/report_cache/
  {period_label}.pkl` menggunakan `pickle`.
- Sidebar sekarang punya 2 bagian terpisah sesuai usul user: **"📂 Buka
  Laporan Tersimpan"** (pilih bulan dari dropdown, klik "Buka Laporan Ini" -
  LANGSUNG tampil tanpa upload apapun) dan **"➕ Upload Data Baru/Update"**
  (alur upload seperti biasa, cuma perlu dipakai untuk bulan yang benar-
  benar baru atau mau update data).
- Diuji: simpan report Juli ke cache, lalu "buka sesi baru" (load ulang
  dari file cache tanpa proses apapun) - data 5001 alert langsung muncul
  utuh, 66 sheet lengkap, tanpa upload file sama sekali.

**Catatan**: cache disimpan di folder `database/report_cache/` di komputer
lokal - jangan dihapus folder itu kalau mau laporan lama tetap bisa dibuka.

## 61. BARU: Warna semantic di chart & CSS lebih hidup

- **CSS diperkaya**: kartu KPI dengan border kiri navy, judul section (###)
  diberi warna navy + garis bawah tipis, kotak info/warning/success diberi
  border kiri tebal berwarna, divider dikasih warna.
- **Warna semantic di chart** (bukan warna acak lagi): Critical=merah,
  High=oranye, Medium=kuning, Low=hijau - diterapkan otomatis ke chart
  Distribusi Severity, Status Rule (Healthy/Noise/Dormant/dst), dan Cause
  Code (Prevented=hijau, Breach-Reported=merah) - supaya orang awam bisa
  langsung paham "merah = masalah, hijau = aman" tanpa perlu baca detail.

## 62. BUG DIPERBAIKI: Duplikat periode legacy + domain case-sensitive

Ditemukan dari screenshot user - 2 bug terpisah yang sama-sama bikin chart
tampil rusak (titik-titik lepas, bukan garis):

1. **Duplikat periode dari SEBELUM fix period_key**: baris histori lama
   (tersimpan pakai teks tanggal otomatis "periode 31 May - 30 Jun 2026")
   tidak ikut terhapus/tergabung saat fix sebelumnya - cuma mencegah
   duplikat BARU, tidak membersihkan yang lama. Ditambahkan
   `_clean_period_history()`: kelompokkan baris berdasarkan Period_End
   (tanggal asli, bukan teks label), pilih label kanonik (prioritas yang
   TIDAK diawali "periode " otomatis), relabel semua baris dengan
   Period_End sama ke situ, baru dedup. Diterapkan ke SEMUA histori
   (Monthly Comparison, Severity Trend, Attack Surface, Rule/Recurring
   Findings, CTI Trend). Diuji dengan mensimulasikan persis histori korup
   dari screenshot user - 4 baris (2 pasang duplikat) berhasil bersih jadi
   2 baris.

2. **Domain "INFRASTRUCTURE" vs "Infrastructure" dianggap domain berbeda**:
   nilai Security_Domain dari sumber CSV mentah (uppercase, "INFRASTRUCTURE")
   tidak konsisten dengan hasil klasifikasi keyword lama (Title Case,
   "Infrastructure") - bikin data yang seharusnya sama kepisah jadi 2 baris.
   Diperbaiki: `Security_Domain`/`Security_Sub_Domain` dinormalisasi ke
   Title Case di `build_rule_summary()` (titik tunggal, jadi otomatis
   konsisten di semua sheet turunan - Domain, Domain_Recommendation,
   Attack_Surface_Trend, Threat_By_Priority_Domain, dst).

**PENTING untuk user**: histori lama di `database/*.csv` di komputer Anda
kemungkinan masih ada baris duplikat dari sebelum fix ini. Cukup generate
report 1x lagi (upload data terbaru seperti biasa) - proses cleanup di atas
otomatis jalan dan membereskan histori lama saat itu juga, tidak perlu
hapus manual file CSV-nya.

## 63. BARU: SLA Metrics (state machine) & People Performance sesuai arahan management

Sesuai notes hasil diskusi dengan management - dipetakan ke data yang
tersedia, dengan gap eksplisit ditandai (bukan ditebak):

- **MTTD** (kejadian -> Logged): proxy Alert Time (Splunk) -> Created On
  (Ivanti) - PERLU DIKONFIRMASI apakah pemetaan ini sesuai maksud.
- **MTTR** (Logged -> Active): Created On -> Responded On (sudah ada
  sebelumnya, definisinya kebetulan sudah cocok).
- **MTTC** (Active -> Contained): **BELUM BISA DIHITUNG** - tidak ada kolom
  timestamp "Contained" terpisah di data Ivanti. Kolom disiapkan berisi
  "Menunggu data" (bukan angka palsu), tinggal diisi begitu tim Ivanti
  konfirmasi nama kolomnya.
- **MTTRV** (Active -> Resolved): Responded On -> Resolved On.

Sheet baru `SLA_Metrics` (breakdown per tier P0-P3 + keseluruhan), tab
Efektivitas di Streamlit.

**BUG DITEMUKAN & DIPERBAIKI sekaligus**: kode lama SALAH menamai
`Avg_MTTC_sec` di KPI SOC untuk metrik yang sebenarnya MTTRV (Responded->
Resolved) - sudah diluruskan sesuai definisi resmi state machine dari
management, kolom `Avg_MTTC_sec` yang benar sekarang eksplisit "Menunggu
data" di People Performance juga.

**BUG DATA KUALITAS DITEMUKAN & DIPERBAIKI**: kolom `Alert Time` di file
Ivanti user formatnya TIDAK KONSISTEN - sebagian "12:14 7/1/2026" (jam+
tanggal), sebagian cuma "08:46" (JAM SAJA tanpa tanggal). Parse polos bikin
MTTD ngaco (rata-rata 87 hari - jelas salah). Diperbaiki dengan deteksi
otomatis + fallback: kalau parse mencurigakan (beda >3 hari dari Created
On), ambil jam dari teks mentah + gabung tanggal Created On (asumsi alert &
tiket dibuat hari yang sama - PERLU DIKONFIRMASI). Setelah fix, MTTD masuk
akal (13-169 menit).

**People Performance**: tabel KPI Analyst diperluas - Take_Incident/
Take_Task (rename dari Total), MTTR, MTTRV, MTTC (placeholder), Breach
Rate - sesuai framework "Take/Response/Contain/Resolve" dari management.

**Masih pending, butuh info dari user**: 
1. Konfirmasi kolom "Contained" (MTTC) - user perlu cek ke tim Ivanti
2. Subject/attacker identification - user minta di-skip dulu, tidak ada datanya
3. Security Control (device pendeteksi) - belum diimplementasi, perlu klarifikasi field mana yang dipakai

## 64. Perbaikan layout, font, dan warna chart (feedback user)

- **Font diperbesar** di seluruh dashboard: body text 17px, metric value
  30px (bold), judul section (h2/h3) 26px/21px, tab label 16px, isi tabel
  15px - sebelumnya semua terlalu kecil (default Streamlit ~14px).
- **Chart perbandingan diberi warna beda per kategori**: fungsi `plot_bar()`
  ditambah parameter `distinct_colors` - diterapkan ke chart Distribusi
  Domain dan Coverage per Device supaya tiap bar/kategori punya warna
  sendiri (bukan monoton biru semua), lebih gampang dibandingkan sekilas
  lihat.
- **Font di dalam chart Plotly juga diperbesar** (axis, legend, label
  angka) - sebelumnya size=12, sekarang size=14-17 tergantung elemennya.

## Catatan untuk "Rule Splunk Active masih 0"

Kemungkinan besar checkbox "File ini SEMUA rule sudah Enabled" (di sidebar,
tepat di bawah uploader Master Rules) belum dicentang - fitur ini SENGAJA
opt-in (tidak otomatis) supaya tidak salah asumsi untuk file lain. User
diminta cek lagi checkbox itu sebelum generate.

## 65. BUG DIPERBAIKI: KeyError saat buka laporan cache lama (skema kolom beda)

Root cause: laporan Juni/Juli yang tersimpan di cache dibuat SEBELUM
perbaikan penamaan MTTC->MTTRV (poin #63) - jadi strukturnya beda dari yang
diharapkan kode terbaru, bikin `KeyError: "['Avg_MTTRV_sec'] not in index"`
saat coba ditampilkan di tab KPI Analyst.

Diperbaiki: tabel KPI Analyst sekarang ambil HANYA kolom yang memang ada di
laporan yang sedang dibuka - kalau ada kolom yang hilang (skema lama),
kasih tahu lewat caption, TIDAK crash total. Ini juga jadi pengaman umum
untuk evolusi skema ke depannya - kalau ada perubahan struktur data lagi,
laporan cache lama tidak bikin aplikasi berhenti, cuma kolom baru itu saja
yang tidak muncul sampai laporan itu di-generate ulang.

## 66. BARU: Tombol Hapus Data Tersimpan (reset ke nol)

Sesuai permintaan user - laporan Juni/Juli lama (dari sebelum berbagai
perbaikan skema) ingin dihapus supaya tidak ada data usang/duplikat
tercampur dengan yang baru. Ditambahkan di sidebar, bagian "📂 Buka Laporan
Tersimpan":
- Tombol **🗑️ Hapus** per periode - hapus 1 laporan cache spesifik saja
- Expander **"⚠️ Hapus SEMUA data tersimpan"** - hapus SELURUH folder
  `database/` (semua laporan cache + semua histori tren: Monthly
  Comparison, Severity Trend, Attack Surface, Recurring Findings/Action
  Tracker, CTI Trend) sekaligus - perlu centang konfirmasi dulu sebelum
  tombol hapus aktif, supaya tidak kepencet tidak sengaja.

Diuji: simulasi kondisi cache lama (skema sebelum fix) tidak lagi bikin
KeyError, tabel tetap tampil dengan kolom yang tersedia.

## 67. BUG DIPERBAIKI: AttributeError saat kolom Alert Time gagal di-parse total

`AttributeError: Can only use .dt accessor with datetimelike values` di
`build_sla_metrics()` - terjadi kalau kolom `Alert Time` di file yang
diupload isinya SAMA SEKALI tidak bisa dibaca sebagai tanggal/jam (beda
kasus dari sebelumnya yang cuma "format tidak konsisten" - ini "gagal
total"). Pada kondisi itu, sebagian versi pandas mengembalikan tipe data
'object' alih-alih 'datetime64', yang tidak punya `.dt` accessor - bikin
crash.

Diperbaiki dengan pengecekan tipe data eksplisit sebelum pakai `.dt`
accessor - kalau hasil parsing BUKAN datetime64, dipaksa ulang; kalau
masih gagal juga, MTTD untuk periode itu dikosongkan (None) dengan
peringatan di log, TIDAK memaksakan/menebak angka yang salah. Diuji dengan
skenario ekstrem (kolom Alert Time isinya teks acak sama sekali) - tidak
crash lagi, SLA_Metrics tetap terbentuk dengan MTTD kosong untuk kasus itu.
Data asli user (Juli) tetap berfungsi normal seperti sebelumnya.

## 68. BARU: Radar Chart untuk SLA Metrics per Tingkat Keparahan

Sesuai permintaan BOD - chart "melingkar, makin lancip kalau nilai tinggi"
= Radar/Spider Chart. Ditambahkan fungsi `plot_radar()` (pakai
`plotly.graph_objects.Scatterpolar`), diterapkan di tab Efektivitas: 1
garis per tier Priority (P0-P3), 4 sumbu = MTTD/MTTR/MTTC/MTTRV - jadi
sekali lihat langsung kelihatan tier mana yang paling lambat di metrik apa.

Kolom MTTC yang masih "Menunggu data" (teks, bukan angka - karena belum
ada kolom Contained dari Ivanti) digambar sebagai 0 di radar, DIBERI
CAPTION PERINGATAN eksplisit di bawah chart supaya tidak disalahartikan
sebagai "cepat" - jujur ke pembaca bahwa itu memang belum ada datanya.

**Catatan sandbox**: karena tidak ada akses internet untuk install Plotly
langsung, `plot_radar()` sudah di-smoke-test pakai stub module yang meniru
API `plotly.graph_objects` persis, termasuk skenario data campuran (angka +
teks "Menunggu data" untuk MTTC) - tidak ada error. Tetap disarankan
dicoba langsung setelah `pip install -r requirements.txt`.

## 69. BARU: Tab "📋 BoD Summary" - 1 halaman ringkas untuk manajemen

Sesuai arahan management (dashboard terlalu kompleks) - ditambahkan tab BARU
di posisi PALING DEPAN, isinya cuma radar chart + angka kunci (TANPA detail
teknis), disusun persis mengikuti 3 kategori yang diminta:

1. **Cybersecurity Incident Ticket Performance** - metrik ringkas + Radar
   SLA per severity (reuse dari Efektivitas) + Meet vs Breach (pie) +
   Dormant/Noisy Rules.
2. **Cybersecurity Attack Patterns** - transparan ditandai BELUM LENGKAP
   (Subject/Security Control/TTP/Kill Chain belum ada data) - yang sudah
   ada (Object/target per domain) ditampilkan.
3. **SOC Ticket Performance** - Ticket Taken per analyst (bar) + **Radar
   People Performance BARU** (Take/Response/Resolve/Meet Rate, dinormalisasi
   0-100 supaya metrik beda satuan bisa dibandingkan di 1 radar - lebih
   cepat/lebih sedikit breach = radar lebih lebar) + Operational Tasks.

**Tab detail lama TETAP ADA** (Ticket, Threat Profiling, Efektivitas, KPI
Analyst, dst) - tidak dihapus, tetap dibutuhkan untuk kerja analyst
sehari-hari. Di akhir tab BoD Summary ada expander "📖 Menu mana menjawab
pertanyaan BoD yang mana?" - tabel pemetaan eksplisit pertanyaan -> tab
mana yang punya detailnya.

Diuji dengan data asli end-to-end (normalisasi radar performa analyst -
Owner dengan MTTR jauh lebih lambat otomatis dapat skor 0, proporsional ke
yang lain) - Excel & PPT tetap berjalan normal.

## 70. Update besar sesuai permintaan management (8 poin)

1. **BUG DIPERBAIKI**: `StreamlitDuplicateElementId` di semua chart Plotly -
   ditambahkan `key` unik otomatis (counter global) ke SEMUA pemanggilan
   `st.plotly_chart`/`st.bar_chart`/`st.line_chart`.

2. **Skema Ivanti BARU didukung penuh** (`normalize_incident_columns()` di
   `utils/helpers.py`): `Ticket Number`->`Incident`, `Active DateTime`->
   `Responded On`, kolom `Created On` duplikat di header dibuang otomatis.
   `Duration Active/Resolved (Minutes)` dan `FlagBreachResponse`/
   `FlagBreachResolution` (yang SUDAH DIHITUNG Ivanti sendiri) dipakai
   LANGSUNG - lebih akurat daripada dihitung ulang dari nol. Fallback ke
   cara lama tetap ada untuk skema lama. Ditambahkan `_compute_incident_
   breach_flag()` - 1 sumber kebenaran terpusat untuk status breach,
   dipanggil paling awal di `run()`, dipakai ulang di semua method (tidak
   ada lagi kode breach yang terduplikasi/berpotensi beda hasil).

3. **BARU: Subject Internal/External** dari kolom `Incident Type` (field
   baru di skema Ivanti) - sheet `Subject_Internal_External`, ditampilkan
   di Executive Summary & Threat Profiling.

4. **BARU: Resolved_Closed_Stats prioritaskan `Closed On`** (field baru,
   lebih akurat) daripada `Modified On` (proxy lama).

5. **"BoD Summary" -> "Executive Summary"** (rename sesuai permintaan).

6. **RESTRUKTURISASI NAVIGASI**: dari `st.tabs()` (tidak bisa dikontrol
   dari kode - keterbatasan resmi Streamlit) ke sistem halaman berbasis
   `st.session_state` + `st.radio` (gaya tab dipertahankan via CSS) - supaya
   tombol **"Lihat Detail →"** di Executive Summary bisa BENAR-BENAR lompat
   ke halaman detail (Efektivitas/Threat Profiling/KPI Analyst/Perbandingan
   Bulanan). 4 tombol ditambahkan.

7. **Executive Summary dirombak**:
   - Metrik operasional yang tidak relevan buat BoD (Rule Splunk Active,
     Belum Ter-mapping, Total Alert Splunk mentah) DIPANGKAS - cukup Total
     Tiket, % Breach, Detection Rate. Detail teknis tetap ada di halaman
     "Ticket".
   - **Tren Bulan ke Bulan ditambahkan** (bagian baru #4) - sebelumnya tidak
     muncul di Executive Summary meski data Juni-Juli sudah pernah diupload.
   - **Notifikasi "⚠️ Belum ada data"** ditambahkan eksplisit di SETIAP
     bagian yang datanya kosong (Subject/Object, Security Control/TTP/Kill
     Chain, People Performance, Operational Tasks, Tren) - tidak lagi
     senyap/hilang begitu saja.

8. **Radar chart TIDAK diperluas ke tempat yang tidak cocok** - dicek ulang,
   cuma dipakai di SLA per severity & People Performance (2 skenario yang
   memang cocok - 3-6 kategori, banyak dimensi). Chart lain tetap bar/line/
   pie sesuai jenis datanya.

Diuji end-to-end dengan skema Ivanti BARU (data sample dari user) - Excel &
PPT sukses, semua sheet baru (SLA_Metrics dengan breach dari flag Ivanti,
Subject_Internal_External) terisi benar. Navigasi (`current_page`/
`goto_page()`) diverifikasi struktural - 10 halaman, 4 tombol lompat semua
menuju nama halaman yang valid.

## 71. BUG DIPERBAIKI: KeyError '%_Breach' saat buka laporan cache lama

Pola yang sama seperti sebelumnya (poin #65) - laporan yang tersimpan di
cache dibuat SEBELUM kolom `%_Breach`/`Jumlah_Breach` ditambahkan ke
`sla_metrics`, bikin `KeyError` saat Executive Summary coba menampilkannya.

Diperbaiki dengan pola defensif yang sama: `overall_sla.get(...)` dengan
default, cek `"kolom" in overall_sla.index` sebelum dipakai, plus deteksi
eksplisit "laporan ini dari skema lama" dengan pesan yang jelas (bukan
crash) menyarankan generate ulang. Diterapkan juga ke radar People
Performance (Executive Summary bagian 3) - kalau ada kolom yang hilang,
sumbu radar yang tersedia saja yang dipakai (minimal 3 sumbu), bukan crash.

Diuji 2 skenario: (1) simulasi data cache lama tanpa kolom %_Breach - tidak
crash, tampil "-" dengan warning; (2) data skema terbaru - %_Breach tetap
terhitung normal (100.0% untuk 1 tiket breach dari 1 tiket total).

## 72. BUG FATAL DIPERBAIKI: StreamlitAPIException saat klik "Lihat Detail"

Root cause: `goto_page()` mencoba set `st.session_state["current_page"]`
LANGSUNG - padahal "current_page" adalah key MILIK widget `st.radio()` yang
sudah dirender lebih dulu di run yang sama. Streamlit MELARANG modifikasi
session_state milik widget setelah widget itu diinstansiasi (keterbatasan
resmi, bukan bug Streamlit).

Diperbaiki dengan pola standar: `goto_page()` sekarang cuma set flag
terpisah `_pending_page` (BUKAN key widget) lalu `st.rerun()`. Di awal
script pada run berikutnya - SEBELUM widget radio dibuat - flag itu diproses:
`current_page` di-update DAN key widget radio (`nav_radio_widget`) dipaksa
ikut sinkron (aman karena dilakukan sebelum widget itu sendiri render di
run tsb). Tombol radio manual tetap berfungsi normal juga (dicek `if
selected_page != current_page`).

## 73. BUG DIPERBAIKI: Radar chart skala kacau ("cuma nunjuk 1 arah")

Root cause: sumbu radar (MTTD/MTTR/MTTC/MTTRV) digambar pakai angka MENIT
MENTAH - padahal skalanya beda jauh (MTTR ~10-17 menit vs MTTRV ~500-640
menit). Sumbu dengan angka terbesar (MTTRV) otomatis mendominasi seluruh
chart, sumbu lain kelihatan rata/hilang - persis yang di screenshot user
("lancip 1 arah doang, radar-nya nyaris kosong").

Diperbaiki: `plot_radar()` sekarang MENORMALISASI tiap sumbu 0-100 secara
independen SEBELUM digambar (default `normalize=True`) - jadi tiap metrik
kelihatan variasinya relatif ke metrik itu sendiri, bukan tenggelam oleh
metrik lain. Nilai ASLI (menit) tetap ditampilkan di tabel di bawah chart
supaya tidak menyesatkan. Diuji dengan data mirip skenario user (MTTC semua
"Menunggu data", MTTRV jauh lebih besar dari lainnya) - normalisasi bekerja
benar, tidak ada lagi 1 sumbu yang mendominasi.

Sekalian diperbaiki bug kecil: `title=None` yang dikirim ke Plotly bisa
render teks "undefined" di beberapa browser - sekarang title cuma dikirim
kalau memang ada isinya.

## 74. BARU: Rata-rata MTTR Tim Keseluruhan

Sesuai permintaan user - ditambahkan metrik "Rata-rata MTTR Tim" (bukan
per-analyst) di Executive Summary bagian 3 DAN halaman detail "KPI Analyst"
- dihitung TERTIMBANG berdasarkan jumlah tiket tiap analyst (bukan cuma
rata-rata dari rata-rata, supaya analyst dengan tiket sedikit tidak
"menyeret" angka tim secara tidak proporsional). Sekalian ditambahkan
Breach Rate Tim dan Total Analyst Aktif sebagai konteks pendamping.

## Catatan: Radar untuk Security Control/TTP/Kill Chain (jawaban pertanyaan user)

BUKAN radar yang cocok, meski nanti datanya sudah ada:
- **Security Control** (device pendeteksi) = perbandingan JUMLAH per
  kategori -> **Bar chart** (bukan multi-dimensi, cuma 1 angka per kategori)
- **TTP Trends** = tren dari waktu ke waktu -> **Line chart**
- **Cyber Kill Chain Trends** = tahapan BERURUTAN (Reconnaissance ->
  Weaponization -> ... -> Actions on Objectives), bukan dimensi independen
  yang setara -> **Funnel chart atau bar chart bertahap**, radar akan
  menyesatkan karena radar cocok untuk dimensi yang SETARA/tidak berurutan.

## 75. BARU: Checkbox pilih bulan + 3 tambahan penting untuk BoD di Executive Summary

**1. Multi-select bulan** (sesuai konfirmasi user) - bagian "4️⃣ Tren Bulan
ke Bulan" sekarang punya widget pilih bulan (`st.multiselect`, default
SEMUA tercentang) - centang/hilangkan bulan mana saja yang mau
ditampilkan/dibandingkan, chart otomatis update ke bulan yang dipilih saja.
Kalau cuma 1 bulan dipilih, tampil angka ringkas (bukan chart perbandingan
yang perlu >=2 titik).

**2-4. Tambahan yang menurut saya penting untuk BoD** (ditaruh PALING ATAS
Executive Summary, sebelum bagian 1):

- **Status Keseluruhan (RAG - Merah/Kuning/Hijau)**: 1 badge besar warna-
  warni berdasarkan % Breach keseluruhan (≤5%=Hijau, 5-15%=Kuning,
  >15%=Merah - ambang bisa disesuaikan nanti kalau BoD punya standar SLA
  sendiri). Ini yang paling sering ditanyakan BoD di awal - "gimana kondisi
  kita bulan ini?" - langsung terjawab tanpa perlu baca detail apapun.
- **Indikator naik/turun vs bulan lalu** (▲/▼) untuk Detection Rate -
  otomatis muncul kalau ada histori >=2 periode.
- **Ringkasan Temuan Utama** - 3 insight paling penting dari Hypothesis
  Insight (sumber sama dengan halaman Overview), ditulis ringkas dalam
  expander yang default terbuka - supaya BoD yang cuma sempat baca 30 detik
  tetap dapat inti masalahnya tanpa scroll ke bawah.

Diuji end-to-end: generate 2 periode berturut-turut (simulasi Juni & Juli
dari data asli user) - Monthly Comparison terisi 2 baris benar, logic
filter checkbox/delta/RAG semua diverifikasi tanpa error (delta terdeteksi
turun 3.53%/turun sesuai data, status RAG sesuai ambang).

## 76. Perbaikan besar sesuai review presentasi (6 poin dari user)

**1. Konfirmasi setup baru** - user hapus data lama, upload format Ivanti terbaru.

**2. Selisih 496 vs 497 baris - BUKAN BUG**: dicek langsung ke file user -
Ticket Number `2773649` muncul 2x IDENTIK di source data (baris 347 & 348,
sama persis Created On & Summary). Deduplikasi otomatis sistem sudah benar
membuang 1 duplikat - 496 tiket UNIK adalah angka yang benar, bukan
kehilangan data.

**3. SLA per Severity kosong (MTTD/MTTC)** - dicek langsung: file terbaru
dari tim Ivanti MASIH TIDAK punya kolom timestamp "Contained" (state
machine yang dilampirkan user mengonfirmasi konsep ini ada di proses
mereka, tapi field datanya belum di-export). MTTD juga tidak ada (kolom
"Alert Time" tidak ada di format baru). Kedua ini jujur ditandai
"Belum ada data"/"Menunggu data" - bukan dipaksa dihitung salah.

**4. BUG DIPERBAIKI - "undefined" di 4 chart lain**: root cause SAMA
seperti radar chart (poin #73) - `title_font` dikirim ke Plotly meski
`title=None`, tapi kemarin cuma diperbaiki di `plot_radar()`, LUPA
diterapkan ke `plot_bar`, `plot_bar_multi`, `plot_pie`, `plot_line`.
Sekarang semua 5 fungsi chart konsisten pakai pola yang sama (title_font
cuma dikirim kalau title memang ada isinya).

**4b. Radar 6 orang vs Bar chart 10 orang - diperjelas, bukan bug**: radar
memang SENGAJA dibatasi Top 6 (dari total analyst) supaya garis tidak
saling tumpuk/tidak terbaca - sekarang caption-nya eksplisit ("Top 6 of
{N}") dan chart bar di sebelahnya diberi label "Semua {N} Analyst" supaya
jelas ini 2 sudut pandang berbeda, bukan data yang tidak konsisten.

**4c. Kolom radar diperjelas namanya**: `Take_norm`/`Response_norm`/dst
diganti jadi `Ticket Volume Score`/`Response Speed Score`/`Resolution
Speed Score`/`SLA Meet Rate Score` - plus expander "ℹ️ Arti tiap sumbu
radar ini" dengan penjelasan lengkap tiap sumbu, bukan cuma nama kolom
mentah tanpa konteks.

**5. Urutan Executive Summary diubah**: "Tren Bulan ke Bulan" DIPINDAH dari
Bab 4 (paling bawah) ke **Bab 2** (langsung setelah Ticket Performance) -
sesuai masukan user, ini metrik yang paling sering ditanya di awal
presentasi. Ditambahkan juga PERINGATAN EKSPLISIT di bagian ini: kalau
tanggal yang muncul tidak sesuai dugaan (mis. bulan lama yang sudah
dihapus filenya masih muncul), itu karena menghapus file upload TIDAK
otomatis menghapus histori tersimpan aplikasi (`database/` folder) -
harus direset manual lewat tombol "Hapus SEMUA data tersimpan".

**6. Bahasa/istilah security dikembalikan ke Inggris** ("Tingkat
Keparahan" -> "Severity", dst) - istilah teknis security TIDAK
diterjemahkan lagi supaya tidak ambigu untuk presentasi.

Diuji end-to-end dengan FILE TERBARU dari user (`incident_ivanti_
july2026-newformat.xlsx`, 496 tiket unik terkonfirmasi persis sama dengan
dashboard) - Excel & PPT sukses, PPT lolos validasi.

## 77. Perbaikan dashboard sesuai review presentasi (3 poin)

**1. BUG DIPERBAIKI - sumbu-X chart salah dideteksi sebagai tanggal
kalender**: label periode ("2026-06", "2026-07") auto-terdeteksi Plotly
sebagai tanggal, bikin sumbu-X jadi "Jun 1 2026"/"Jul 1" atau "May 31,
Jun 7, Jun 14..." (membingungkan, tidak sesuai label bulan yang
sebenarnya). Diperbaiki: `plot_bar`, `plot_bar_multi`, `plot_line`
sekarang PAKSA sumbu-X jadi kategori teks (`type="category"` +
`category_orders`) - label tampil persis sesuai nilai aslinya.

**2. Urutan bab Executive Summary**: "Tren Bulan ke Bulan" dipindah jadi
**Bab 1** (sebelumnya sempat jadi Bab 2) - Ticket Performance geser ke Bab
2, Attack Patterns & SOC Performance tetap Bab 3 & 4. Sekaligus "Detection
Rate per Month" diganti dari line chart jadi **bar chart** - perbandingan
tinggi antar bulan lebih jelas dibaca daripada garis miring 2 titik.

**3. Ukuran font**: dibuat DINAMIS lewat slider baru di sidebar ("🔤
Ukuran Tulisan", 14-26px) - semua elemen (judul h1/h2/h3, body text, tabel,
metric card) otomatis menyesuaikan proporsional saat slider digeser.
Default dinaikkan jadi 19px (dari 17px sebelumnya).

Diuji: f-string CSS dengan berbagai nilai font tervalidasi tidak error
(kurung kurawal literal CSS di-escape ganda `{{ }}`, cuma variabel ukuran
font yang di-interpolasi). Logic category_orders diverifikasi mengembalikan
label periode asli, bukan tanggal kalender. Pipeline end-to-end dengan data
asli tetap sukses (Excel & PPT).

## 78. Update sesuai masukan management setelah presentasi (5 poin)

**1. Detection Rate per-month DIHAPUS** dari Executive Summary Bab 1
(Tren Bulan ke Bulan) - sesuai arahan management. Layout dirapikan jadi
full-width untuk chart Total Alert & Incident yang tersisa.

**2. BARU: Tren Attack Pattern lintas bulan** - sebelumnya Subject
(Internal/External) cuma snapshot 1 periode. Ditambahkan
`build_attack_pattern_trend()` (pola sama seperti Severity/Attack Surface
Trend - histori `database/attack_pattern_history.csv`) - ditampilkan di
Executive Summary Bab 3 sebagai bar chart Internal vs External per bulan.
Attack Surface Trend (domain) juga ditambahkan sebagai expander di bagian
yang sama.

**3. MTTD - DI-SKIP sesuai permintaan user**, menunggu diskusi lebih
lanjut dengan line manager. Tidak ada perubahan logic MTTD di rilis ini.

**4. Weekly (Tactical) - BELUM diaktifkan**, sesuai keputusan user fokus
Monthly dulu. Tidak ada perubahan di area ini.

**5. BARU: Risk Score Strategic** (menggantikan status RAG sederhana
sebelumnya yang cuma pakai % Breach) - komposit 3 komponen dengan bobot:
- **A. SLA Compliance (40%)**: 100 - % Breach periode ini
- **B. Tren Detection Rate (30%)**: membaik/memburuk vs bulan lalu (butuh
  >=2 periode - kalau belum ada, komponen ini dikosongkan, TIDAK dipaksa 0)
- **C. Perbaikan Isu Berulang (30%)**: Action Tracker Improvement Rate

Skor 0-100 (semakin TINGGI = semakin BERISIKO, konvensi umum "Risk
Score"), rata-rata tertimbang HANYA dari komponen yang datanya tersedia
(supaya periode pertama - cuma komponen A yang ada - tidak salah dihukum
seolah B dan C = 0). Metodologi ditampilkan transparan lewat expander
(bukan black-box), lengkap dengan angka tiap komponen dan sumbernya.

Diuji: logic komposit dengan 4 skenario (bagus/buruk/data-parsial/data-
kosong) - hasil masuk akal di semua kasus. End-to-end 2 periode (Juni-Juli)
- Attack Pattern Trend terisi 2 baris benar, Excel & PPT sukses, PPT lolos
validasi.

## 79. BARU: Modul CyNET Report (STEP 1-3 sesuai spesifikasi user)

Menambahkan modul BARU untuk CyNET Report (compliance/coverage agent Cynet
EDR - Endpoint & Server), TERPISAH TOTAL dari SOC Report, sesuai batasan
ketat yang diberikan user (data separation, no refactor SOC, single
Streamlit app).

**Hasil inspeksi sebelum coding:**
- Existing SOC: entry point `app.py`, modul di `core/` (bukan folder
  bernama `soc/` - struktur existing dipakai sebagai baseline, TIDAK
  dipaksa rename sesuai instruksi user sendiri).
- File CyNET (`Dashboard-Cynet-2026-Terbaru.xlsx`): 9 sheet - raw data
  Endpoint/Server per kuartal, sheet Kalkulasi (PivotTable), sheet
  Dashboard (PivotChart), sheet `Compare` (tren manual Maret-September).
  **Kolom mentah TERKONFIRMASI TIDAK KONSISTEN** antar file (`Status
  Compliance` vs `Status-Compliance`, kolom `Custom`/`Custom.1` yang tidak
  konsisten - tidak dipakai sama sekali di logic).

**File BARU dibuat:**
- `cynet/__init__.py`, `cynet/loader.py` (baca & normalisasi 2 file
  Endpoint+Server), `cynet/processor.py` (hitung metrik + histori bulanan
  - pola SAMA seperti SOC: period_key sebagai kunci, dedup, database/
  folder TAPI file terpisah `cynet_history.csv`), `cynet/dashboard.py` (UI
  Streamlit self-contained, TIDAK import apapun dari `app.py`/`core/`).

**File DIUBAH:** cuma `app.py` - **1 blok ~35 baris** disisipkan tepat
setelah `st.set_page_config()` (Report Selection Gate). **DIVERIFIKASI
via diff**: nol baris kode SOC existing yang terhapus/berubah - blok baru
cuma ditambahkan, sisanya identik 100% dengan versi sebelumnya.

**Dashboard CyNET** (6 bagian sesuai spec): Executive Summary, Key Metrics
(Compliance per Asset Type + Agent Version distribution), Trend/Timeline
(month-over-month, butuh >=2 periode), Important Findings (device stale
>30 hari + warning kalau %Compliance <80%), Detailed Data, Report Export
(CSV).

**Testing yang dilakukan:**
1. Load data Q2 asli (format kolom "Status Compliance") - berhasil, 3948
   baris, 77.8% compliance.
2. Load data Q1 asli (format kolom BEDA - "Status-Compliance" + kolom
   tambahan "Status") - berhasil tanpa error, normalisasi robust.
3. Generate 2 periode berturut (April, Agustus) - histori akumulasi benar
   (2 baris, tidak duplikat).
4. Diff `app.py` sebelum/sesudah - dikonfirmasi HANYA blok gate yang
   ditambahkan.
5. Pipeline SOC penuh (Excel+PPT) dijalankan ulang setelah penambahan
   CyNET - hasil tetap sukses, tidak ada regresi.

**Belum diimplementasikan (STEP selanjutnya, menunggu konfirmasi user)**:
sheet `Kalkulasi`/`Dashboard` yang berisi PivotChart Excel native belum
di-reverse-engineer detail per elemen visualnya (baru diambil metrik
utamanya: compliance count, version breakdown) - kalau ada chart/metrik
spesifik dari sheet itu yang belum tercakup, perlu direview bersama user.

## 80. BARU: Modul IOC Scoring - Verifikasi IP Firewall

Menambahkan modul BARU (`ioc/`), TERPISAH TOTAL dari SOC & CyNET (pola
sama: self-contained, tidak saling import), untuk verifikasi IP dari log
firewall ke 3 sumber:

1. **GitHub Threat Feed** (`ioc/threat_feeds.py`) - GRATIS, TANPA API KEY.
   Download daftar IP jahat dari repo publik FireHOL (raw.githubusercontent.com),
   cache 24 jam (tidak download ulang tiap kali kalau masih fresh). Kalau
   download gagal, fallback ke cache lama, atau dikosongkan (TIDAK crash).
2. **VirusTotal** (`ioc/virustotal.py`) - OPSIONAL, butuh API key sendiri
   (user belum punya - didesain aman: kalau key kosong, di-skip dengan
   pesan jelas, bukan error). Auto-throttle 16 detik/request (rate limit
   tier gratis 4/menit).
3. **AbuseIPDB** (`ioc/abuseipdb.py`) - OPSIONAL, sama pola dengan VirusTotal.

**Scoring komposit** (`ioc/scorer.py`): Feed match (40%) + VirusTotal
malicious ratio (30%) + AbuseIPDB confidence (30%) - HANYA dihitung dari
sumber yang datanya tersedia. Klasifikasi: HIGH/MEDIUM/LOW RISK/CLEAN.

**UI** (`ioc/dashboard.py`): upload file (.csv/.xlsx/.txt) - otomatis
deteksi kolom mana yang isinya IP, atau 1 IP per baris untuk .txt. Progress
bar untuk VT/AbuseIPDB (bisa lama untuk ratusan IP). Hasil bisa didownload CSV.

**BUG DITEMUKAN & DIPERBAIKI saat testing**: validasi IP awal cuma
memeriksa JUMLAH digit (regex `\d{1,3}`), bukan RENTANG nilai oktet
(0-255) - meloloskan IP tidak valid seperti "256.256.256.256". Diperbaiki
pakai modul `ipaddress` standar Python (validasi sungguhan), bukan regex.

**Ditambahkan ke gate navigasi Security Reporting Dashboard** - opsi
ke-3 "🔎 IOC Scoring" di samping SOC & CyNET. Diverifikasi via diff:
HANYA 1 baris berubah di dalam blok gate itu sendiri (`st.columns(2)` ->
`st.columns(3)`) - NOL baris kode SOC/CyNET yang tersentuh. Pipeline SOC
dijalankan ulang setelah penambahan - tetap sukses, tidak ada regresi.

**Catatan jujur untuk user**: SEMUA panggilan ke GitHub/VirusTotal/
AbuseIPDB belum bisa saya test langsung (sandbox tidak ada akses internet).
Endpoint & format response sesuai dokumentasi resmi masing-masing, tapi
WAJIB dicoba dulu dengan sedikit IP sebelum dipakai untuk verifikasi
massal - terutama VirusTotal yang rate limit-nya ketat (4/menit).

## 81. IOC Scoring - Input Manual & Rincian Sumber (validasi real-world berhasil)

**Konfirmasi dari user**: modul IOC Scoring TERBUKTI BERHASIL di dunia
nyata - IP `94.154.43.164` berhasil terdeteksi MEDIUM RISK lewat GitHub
Threat Feed (match FireHOL Level 1). User cross-check manual ke
ip-checker.info menemukan IP ini SEBENARNYA jauh lebih parah (Abuse Score
100%, 2136 laporan, masuk 8 blacklist RBL) - PEMBUKTIAN NYATA bahwa GitHub
Feed saja tidak cukup komprehensif, AbuseIPDB/VirusTotal perlu diaktifkan
untuk deteksi lebih luas (sudah dijelaskan ke user).

**1. BARU: Input manual (maks 10 IP)** - tab baru "⌨️ Input Manual" di
samping "📁 Upload File". Ketik/paste IP dipisah baris baru ATAU koma,
otomatis validasi (modul `ipaddress`), buang duplikat, potong ke 10
pertama kalau lebih (kasih peringatan jelas), tandai entri yang bukan IP
valid.

**2. BARU: Kolom "Sumber_Ditemukan" & "Sumber_Dicek"** - sebelumnya hasil
cuma tampil skor angka tanpa konteks jelas tools mana yang berkontribusi.
Sekarang eksplisit: `"GitHub Feed (FireHOL Level 1) | AbuseIPDB (100%
confidence)"` - langsung kelihatan temuan dari tools mana. Kolom
"Sumber_Dicek" menunjukkan sumber MANA YANG AKTIF dicek saat itu (supaya
"Tidak ditemukan di sumber manapun" tidak disalahartikan sebagai "pasti
bersih" kalau ternyata cuma 1 sumber yang dicek).

Tabel ringkas hasil sekarang tampilkan kolom penting saja (IP, Risk_Score,
Risk_Level, Sumber_Ditemukan, Sumber_Dicek); rincian mentah lengkap semua
kolom tetap ada di expander "🔬 Rincian lengkap per IP" untuk yang butuh detail.

Diuji: logic `_sources_flagged()` dengan skenario user (cuma GitHub Feed)
vs skenario andaikan AbuseIPDB diaktifkan (100% confidence, sesuai temuan
manual user) - keduanya menghasilkan teks yang jelas & benar. Logic parsing
input manual diuji dengan 12 IP (>10, terpotong benar), 1 duplikat (dibuang),
1 entri invalid ("bukan-ip", ditandai terpisah).

## 82. IOC Scoring - Tambahan Sumber dari 5 Repo GitHub yang Direview

User memberikan README lengkap 5 tools GitHub (`ThreatFeed`, `ioc-threat-
intel`, `ioc_analyzer`, `iocinfo`, `RepChecker`) untuk dikombinasikan.
Setelah dianalisis: SEMUA tools itu adalah CLI/script pribadi (bukan API
terhosting), dan pada akhirnya memanggil sumber API yang SAMA. Strategi:
BUKAN install repo mereka (berisiko - proyek personal, tidak stabil),
TAPI ekstrak sumber gratis baru + adopsi algoritma scoring yang lebih
matang dari dokumentasi mereka.

**Sumber BARU ditambahkan:**
1. **Feodo Tracker Official** (abuse.ch) - ditambahkan ke `DEFAULT_FEEDS`
   di `threat_feeds.py` (dari ide `ioc-threat-intel` - "Not required, no
   auth").
2. **Shodan InternetDB** (`ioc/enrichment.py`) - GRATIS TANPA API KEY
   (dikonfirmasi 2 README independen: ThreatFeed & iocinfo). Sinyal BEDA
   JENIS - soal exposure (open ports, CVE), bukan "terbukti jahat".
3. **ip-api.com Geolocation** (`ioc/enrichment.py`) - GRATIS TANPA KEY.
   Konteks tambahan (negara, ISP, flag hosting/proxy) - BUKAN indikator
   skor, murni informasi bantu analyst.
4. **ThreatFox + URLhaus** (`ioc/abusech.py`, abuse.ch) - OPSIONAL, 1
   Auth-Key gratis untuk keduanya. **CATATAN**: ada ketidaksamaan info
   antar README (ThreatFeed bilang "tanpa key", iocinfo bilang "perlu
   Auth-Key") - diikuti yang lebih ketat/detail (iocinfo) demi keamanan.

**Scorer diperbarui** (`ioc/scorer.py`) - bobot terinspirasi algoritma
`ioc-threat-intel` yang terdokumentasi detail: VirusTotal 25%, AbuseIPDB
25%, GitHub/Feodo Feed 20%, ThreatFox 15%, URLhaus 10%, Shodan exposure
5%. Tetap HANYA menghitung dari sumber yang datanya tersedia.

**UI diperbarui**: checkbox baru untuk ThreatFox+URLhaus (opsional) dan
Shodan+Geolokasi (gratis, default AKTIF). Kolom "Sumber_Ditemukan" &
tabel hasil sekarang menyertakan semua sumber baru + info Geo/ISP.

Diuji: skenario IP nyata yang dilaporkan user (94.154.43.164) - dengan
SEMUA sumber aktif menandai jahat, skor naik dari 50 (cuma feed) jadi
61.9 (MEDIUM RISK, lebih mencerminkan tingkat bahaya sesungguhnya).
Skenario IP bersih (8.8.8.8) tetap 0.0 CLEAN di semua sumber.

**Diverifikasi via diff**: `app.py` TIDAK BERUBAH SAMA SEKALI - semua
perubahan kali ini murni di folder `ioc/` (file baru + edit internal),
nol risiko ke SOC/CyNET.

**Catatan jujur berulang**: SEMUA endpoint baru ini (ThreatFox, URLhaus,
Shodan InternetDB, ip-api.com) belum bisa saya test langsung dari sandbox
saya (tidak ada akses internet). Ditulis berdasarkan dokumentasi resmi +
2 README independen yang saling menguatkan - tapi WAJIB dicoba dengan
sedikit IP dulu sebelum verifikasi massal.

## 83. Modul BARU: Cynet Agent Compliance (rewrite total modul CyNET sesuai spec detail)

User memberikan spesifikasi SANGAT detail (28 bagian) + 6 file Excel bulanan
asli (Maret-Agustus 2026) untuk modul monthly compliance tracking Cynet
Agent (minimal version 4.30 sesuai SOP). Modul CyNET SEBELUMNYA (compliance
generik berbasis "Status Compliance" text) DIGANTI TOTAL karena struktur
data & requirement benar-benar berbeda.

**Hasil inspeksi (sebelum coding, sesuai instruksi eksplisit user):**
1. **Nama kolom hostname BERUBAH 3x antar bulan**: "Hostname" (Maret),
   "Endpoint" (April-Agustus, mayoritas), "Servers" (Juni-sheet Server,
   1x anomali) - loader HARUS toleran ke semua variasi.
2. **Kolom "OS" baru ada mulai Agustus** - bulan sebelumnya tidak punya.
3. **BUKTI KRITIS**: kolom `Is_Compliant` di file mentah TIDAK AKURAT -
   Maret ada 71 server versi 4.29.x ditandai Compliant=True (salah),
   Agustus ada 6 server versi 4.30.x ditandai Compliant=False (salah).
   **Divalidasi matematis**: selisih Compliance_Summary Excel (413) vs
   hitung ulang dari Agent Version (484) = tepat 71, PERSIS sama dengan
   jumlah mismatch yang ditemukan - CONFIRMED sheet Compliance_Summary di
   Excel memang salah hitung (pakai Is_Compliant, bukan Agent Version).
4. Sheet `ACTION_REQUIRED` dan `Remediation Plan` - diabaikan total sesuai
   instruksi.

**File yang diganti**: `cynet/loader.py`, `cynet/processor.py`,
`cynet/dashboard.py` (isi lama dihapus, ditulis ulang sesuai spec baru -
BUKAN modul CyNET yang lama, karena struktur data fundamental berbeda).

**File app.py**: 3 baris berubah (label tombol + nama fungsi import) -
DIVERIFIKASI via diff, nol baris lain tersentuh, SOC 100% aman.

**Business logic diimplementasikan:**
- Version parsing PROPER (tuple (major, minor), BUKAN string comparison -
  spec eksplisit memperingatkan soal ini).
- Compliance dihitung ULANG dari Agent Version (>= 4.30), `Is_Compliant`
  mentah HANYA disimpan sebagai referensi, TIDAK dipakai kalkulasi.
- Device matching antar bulan pakai Hostname (lowercase+trim) sebagai
  identifier stabil, BUKAN IP.
- Upgrade Tracking 5 kategori: Upgraded, Still Non-Compliant, Already
  Compliant, Regression/Downgraded, No Longer Seen/Missing, New Device -
  device yang hilang TIDAK dihitung sebagai upgraded (instruksi eksplisit).
- Persistent Non-Compliance (device bermasalah N bulan berturut-turut).
- Key Insights dihasilkan DINAMIS dari data (tidak hardcode kalimat).
- Data quality report (duplikat hostname, overlap Endpoint/Server, invalid
  version) - tidak diam-diam mengubah data, cuma ditampilkan sebagai warning.
- **Upload Excel untuk bulan baru** - sidebar upload + auto-guess periode
  dari nama file (regex YYYY-MM atau nama bulan Indonesia), user WAJIB
  konfirmasi/edit sebelum simpan.

**Diuji dengan SEMUA 6 file asli (Maret-Agustus 2026):**
- Load & normalize: semua 6 bulan sukses, total device match Compliance_
  Summary Excel (Total Unique) persis, Non-Compliant count BEDA dari Excel
  dengan alasan yang sudah dibuktikan (poin 3 di atas).
- Upgrade Tracking Juli->Agustus: 130 Upgraded, 323 Still Non-Compliant, 0
  Regression, 7 Missing, 48 New Device - Upgrade Rate 28.3%.
- Persistent Non-Compliance (>=3 bulan): 322 device ditemukan.
- Key Insights: 5 insight dinamis dihasilkan benar dari data aktual.

### Validation Result (Dashboard vs Excel)

| Periode | Metric | Excel (Compliance_Summary) | Dashboard (hitung ulang) | Status |
|---|---|---|---|---|
| Maret | Total Device | 1263 | 1263 | ✅ PASS (cocok) |
| Maret | Server Non-Compliant | 413 | 484 | ⚠️ BEDA SENGAJA - Excel pakai Is_Compliant yang salah, dashboard pakai Agent Version (benar) |
| Agustus | Total Device | 1318 | 1318 | ✅ PASS (cocok) |

### Remaining Limitation
Upgrade Tracking & Compliance Trend butuh minimal 2 bulan data - kalau
cuma 1 bulan diupload, halaman-halaman itu akan menampilkan pesan
"Historical comparison is not available" (sesuai instruksi), bukan error.

## 84. RESTRUKTURISASI: Cynet Agent Compliance dari 5 submenu ke 2 (Summary + Details)

Sesuai permintaan user - dashboard sebelumnya (Monthly Overview /
Compliance Trend / OS Breakdown / Upgrade Tracking / Device Detail, 5
halaman terpisah) dianggap terlalu terpecah untuk kebutuhan management.
Direstrukturisasi jadi 2 halaman: **Summary** (BoD/management, gaya BI
eksekutif) dan **Details** (SOC/IT, device-level).

**File TIDAK diubah** (business logic sudah benar & teruji sebelumnya):
`cynet/loader.py` - 100% sama. `cynet/processor.py` - HANYA ditambah 1
fungsi kecil `period_exists()` untuk validasi duplikat upload (sesuai
permintaan #5), semua fungsi lain tidak disentuh.

**File ditulis ulang total**: `cynet/dashboard.py` - restrukturisasi
murni di layer presentasi, konsolidasi 5 halaman jadi 2 + redesign visual
gaya BI (KPI card row, trend chart, horizontal bar OS breakdown, funnel
upgrade tracking, key insights) sesuai layout yang diminta (Row 1 KPI,
Row 2 Trend, Row 3 OS Breakdown, Row 4 Upgrade+Insights).

**Fitur baru:**
- **Period Compare selector** (Previous Month / Last 3 Months / Last 6
  Months / None) di bagian atas Summary.
- **Warning duplikat period**: kalau upload periode yang sudah ada, tampil
  "Reporting period X already exists" SEBELUM data ditimpa (bukan diam-
  diam replace).
- **Details page**: filter Category/OS/Compliance Status/Upgrade Status +
  search box hostname/IP, kolom Previous vs Current Version per device.
- **Warna semantic konsisten**: hijau=compliant/upgrade berhasil,
  merah=non-compliant/regression, netral/abu=already-compliant/missing.
- Sidebar disederhanakan: Upload, Available Data (list period + jumlah).

**`app.py` tidak berubah sama sekali** - diverifikasi via diff (exit code
0, tidak ada perbedaan) - SOC & fungsi navigasi lain 100% aman.

Diuji ulang dengan SEMUA 6 file asli (Maret-Agustus) - KPI Cards, Key
Insights, dan merge Details (Previous Version + Upgrade Status per device)
menghasilkan angka PERSIS SAMA dengan sesi sebelumnya (74.3% compliance,
130 upgraded/28.3% rate) - membuktikan restrukturisasi murni presentasi,
tidak mengubah hasil kalkulasi.

## 85. BUG DIPERBAIKI: Compare mode & konsistensi warna (Cynet Agent Compliance)

Ditemukan dari review langsung dashboard yang berjalan:

**1. Bug "Compare" tidak memengaruhi periode pembanding KPI**: root cause -
`prev_period` (dipakai untuk KPI "Upgraded This Month", "Compliant"/
"Non-Compliant", Upgrade Tracking, dan teks header "Comparing X vs Y")
SELALU di-set ke "1 bulan sebelumnya" APAPUN pilihan dropdown Compare -
cuma `trend_periods` (rentang chart tren) yang benar-benar berubah. User
pilih "Last 6 Months" tapi header/KPI tetap cuma bandingkan vs bulan lalu
- ambigu, sesuai laporan user.

Diperbaiki: `prev_period` SEKARANG ikut mengikuti rentang yang dipilih -
"Previous Month" -> 1 bulan lalu, "Last 3 Months" -> 3 bulan lalu, "Last 6
Months" -> 6 bulan lalu (titik AWAL window yang dipilih). Header diperjelas
jadi "Comparing X vs Y (mode)". Ditambahkan pengaman: kalau prev_period ==
current_period (window belum cukup panjang), dianggap tidak ada pembanding.

Diuji dengan data asli 6 bulan: "Previous Month" -> Upgraded=130 (rate
28.3%, vs Juli), "Last 6 Months" -> Upgraded=161 (rate 33.3%, vs Maret) -
HASIL BERBEDA sesuai mode yang dipilih (sebelumnya SELALU 130 apapun mode).

**2. Warna Server tidak konsisten antar chart** - sebelumnya Server
tampil MERAH di Compliance Trend, ABU-ABU di Total Device Trend, MERAH
lagi di "Server - Non-Compliant by OS" - membingungkan. Diperbaiki:
didefinisikan `COLOR_ENDPOINT` (biru) dan `COLOR_SERVER` (oranye/jingga)
sebagai warna IDENTITAS tetap, diterapkan KONSISTEN di 4 tempat:
Compliance Trend (garis Server_%), Total Device Trend (bar Server),
Server-Non-Compliant by OS, Endpoint-Non-Compliant by OS (biru, untuk
simetri). `_plot_trend_line()` diubah dari warna berdasarkan URUTAN
(rawan salah kalau urutan kolom berubah) jadi `color_discrete_map`
EKSPLISIT per nama kolom.

**3. BARU: Label Total di Total Device Trend** - `_plot_stacked_bar_device()`
ditambah parameter `total_col` - menambahkan teks total (Endpoint+Server)
di atas tiap bar via trace `go.Scatter(mode="text")`, supaya user tidak
perlu jumlah manual.

Diverifikasi via diff: `app.py` tidak berubah sama sekali (exit code 0) -
semua perbaikan murni di `cynet/dashboard.py`.

## 86. UI/UX Improvement: SOC Report navigasi 2-tingkat (benchmark Cynet)

Sesuai permintaan user (pakai Cynet Agent Compliance sebagai benchmark
desain) - navigasi SOC Report disederhanakan TANPA menyentuh business
logic sama sekali.

**Pendekatan (dijelaskan dulu sebelum coding, sesuai instruksi)**: SOC
punya 10 halaman flat (jauh lebih kompleks dari Cynet yang cuma 2) -
memaksa gabung semua jadi 1 halaman "Details" berisiko tinggi merusak
logic yang sudah berkali-kali diuji sepanjang percakapan ini. Sesuai
prinsip user sendiri ("jangan menggabungkan modul yang secara bisnis
harus terpisah"), dipilih pendekatan low-risk: navigasi 2 TINGKAT.

**Perubahan navigasi**: radio atas sekarang cuma **"Summary" / "Details"**
(bukan 10 tombol flat). Pilih "Summary" -> langsung ke Executive Summary
(sudah ada). Pilih "Details" -> muncul selectbox sub-halaman (Overview,
Perbandingan Bulanan, Ticket, Threat Profiling, Non-Splunk & Task, Tren,
Efektivitas, KPI Analyst, Help) - SEMUA 10 blok konten `if current_page ==
"X":` TIDAK DIUBAH SATU BARIS PUN (diverifikasi: masih persis 10 blok).
Variabel `current_page` tetap sama persis, cuma CARA MEMILIHNYA yang
disederhanakan dari 1 baris tombol jadi 2 tingkat.

**BARU: Category color konsisten (poin 9 spec)** - ditambahkan
`CATEGORY_COLORS` (terpisah dari `SEMANTIC_COLORS` yang soal tingkat
bahaya) dan fungsi `category_color_map()` - Security_Domain yang sama
(mis. "Infrastructure") SEKARANG SELALU dapat warna yang sama di chart
manapun, TIDAK tergantung urutan data seperti `distinct_colors` sebelumnya
(yang bisa bikin domain sama dapat warna beda di 2 render berbeda).
Diterapkan ke chart Distribusi Domain di tab Ticket.

**Business logic**: TIDAK BERUBAH. Divalidasi: total Alert/Incident dan
distribusi Security_Domain (Infrastructure=333, Others=116, Applications=43,
dst) PERSIS SAMA dengan sebelum perubahan.

**Modul lain**: `cynet/*.py` dan `ioc/*.py` TIDAK TERSENTUH sama sekali
turn ini - diverifikasi compile ulang, semua aman.

## 87. BARU: Dash Pilot - Migrasi SOC Report Executive Summary ke Plotly Dash

Sesuai diskusi - user pilih migrasi ke Plotly Dash (bukan Streamlit) untuk
tampilan lebih custom/BI-style, dengan SOC Report sebagai modul pilot
pertama. Scope pilot: **HALAMAN EXECUTIVE SUMMARY SAJA** (paling sering
dipakai, manfaat terbesar - sesuai kesepakatan) - 9 halaman Details lain
BELUM di-port, masih via app.py Streamlit untuk sementara.

**File BARU** (app.py Streamlit TIDAK DISENTUH SAMA SEKALI - diverifikasi
via diff, exit code 0):
- `dash_app.py` - entry point baru, jalankan terpisah: `python dash_app.py`
  (port 8050, beda dari Streamlit di 8501 - bisa jalan BERSAMAAN).
- `dash_components/colors.py` - PALETTE/CATEGORY_COLORS/SEMANTIC_COLORS,
  SENGAJA DIDUPLIKASI (bukan import) dari app.py, sesuai prinsip "module
  isolation" yang sudah disepakati sebelumnya.
- `dash_components/charts.py` - `fig_bar/fig_bar_multi/fig_pie/fig_radar`,
  di-port dari fungsi `plot_*()` Streamlit tapi RETURN objek Figure (untuk
  `dcc.Graph`), bukan langsung render `st.plotly_chart`. Termasuk fix
  normalisasi radar 0-100 per sumbu yang pernah ditemukan sebelumnya.

**Business logic 100% REUSE** - `core/loader.py`, `core/processor.py`,
`core/normalizer.py`, `core/validator.py`, `utils/helpers.py` TIDAK
ditulis ulang sama sekali, dipanggil persis sama seperti dari Streamlit.

**Testing yang dilakukan** (sandbox tidak ada internet - tidak bisa
install `dash`/`plotly` untuk test langsung, SAMA seperti kasus
Plotly/requests sebelumnya):
1. Smoke test 4 chart builder (`fig_bar`, `fig_bar_multi`, `fig_pie`,
   `fig_radar`) pakai stub module plotly - semua lolos.
2. Smoke test PENUH `_build_executive_summary()` dengan **data SOC asli**
   (file user, pipeline lengkap RuleNormalizer->Validator->SOCProcessor)
   pakai stub module dash - BERHASIL, 10 section dihasilkan tanpa error.
3. Ditemukan & diperbaiki bug penataan folder saat testing: `dash_app.py`
   (file) bentrok nama dengan folder `dash_app/` - Python tidak bisa
   resolve keduanya sekaligus. Folder di-rename jadi `dash_components/`.

**BELUM diimplementasikan** (next steps setelah pilot ini divalidasi
user): upload NonSplunk/Task/CTI/Domain Mapping (pilot ini cuma Master+
Alert+Incident), fallback file Master Rules default, 9 halaman Details,
tombol download Excel/PPT, cache report per-session (bukan 1 cache
global) untuk multi-user.

**Cara jalankan** (WAJIB `pip install -r requirements.txt` dulu untuk
dapat `dash`):
```
python dash_app.py
```
Buka `http://localhost:8050` (Streamlit tetap di 8501, bisa jalan
bersamaan tanpa konflik).

## 88. BARU: MITRE ATT&CK & Cyber Kill Chain (menutup gap lama), + fix kolom Summary opsional

Menutup gap yang sudah lama ditandai "menunggu klarifikasi field/sumber
data" - user sekarang punya kolom `Incident MITRE`/`Incident KillChain`/
`Security Domain` di export Ivanti terbaru.

**Inspeksi ke SEMUA 219 baris data asli (Export_Data_SOC_1.xlsx, insiden
18-24 Sept 2026) sebelum coding** - ditemukan kualitas data nyata:
- 3 cara berbeda representasikan "kosong": `[]`, NaN, `-`, `--`
- 1 baris MITRE format tidak valid: `T.0001` (bukan pola `TXXXX` yang benar)
- 1 baris MITRE valid tapi tanpa kurung: `T1134.002`
- 1 baris KillChain huruf kecil tanpa kurung: `delivery`
- **1 baris KillChain BERISI MITRE Technique ID yang salah kolom**:
  `T1106, T1083, T1614` - kesalahan input di sumber
- MITRE sering campur Tactic ID (`TA####`) dan Technique ID (`T####`)
  dalam 1 list yang sama
- 7 stage Kill Chain terkonfirmasi dipakai organisasi (bukan standar
  Lockheed Martin klasik - versi mereka sisipkan "Privilege Escalation"
  dari terminologi MITRE Tactic): Reconnaissance, Weaponization,
  Delivery, Exploitation, Installation, Privilege Escalation, Actions
  on Objectives.

**File BARU**: `core/mitre_killchain.py` - parser robust (`parse_bracket_
list`, `classify_mitre_tokens`, `classify_killchain_tokens`) yang
menangani SEMUA variasi di atas tanpa crash, plus `build_data_quality_
report()` yang secara presisi menandai 2 baris anomali (T.0001 dan
KillChain-kesasar) - TIDAK lebih TIDAK kurang, diverifikasi lewat test.

**core/processor.py**: method baru `build_mitre_killchain()` - GRACEFUL
FALLBACK kalau kolom baru ini tidak ada (format Ivanti lama) - semua
kosong tanpa error, fitur ini OPSIONAL. Juga `security_domain_direct`
(dari kolom `Security Domain` LANGSUNG) - sesuai arahan user "pakai
keduanya terpisah", TIDAK menggantikan `report["domain"]` yang berasal
dari keyword-mapping.

**BUG DITEMUKAN & DIPERBAIKI saat testing (di luar scope MITRE/KillChain,
tapi WAJIB diperbaiki)**: file terbaru user TIDAK PUNYA kolom `Summary`
sama sekali (dikonfirmasi user: tim Ivanti lupa menambahkan di export
ini) - sebelumnya bikin PIPELINE CRASH TOTAL di 5 lokasi berbeda
(`core/normalizer.py`, `core/validator.py`, `core/processor.py` x3).
Semua diperbaiki jadi tahan banting: kalau `Summary` tidak ada, fallback
ke `Normalized Rule`, dengan warning eksplisit "Rule Name mapping TIDAK
BISA dihitung akurat untuk periode ini" - BUKAN dipaksa 0/kosong diam-diam.

**app.py**: Executive Summary bagian 3 (Attack Patterns) sekarang
tampilkan ringkasan Top 10 MITRE Technique + Kill Chain distribution +
warning Data Quality kalau ada anomali. Halaman Threat Profiling
tambah bagian detail lengkap "🎯 MITRE ATT&CK & Cyber Kill Chain" -
semua Technique, semua Tactic, Kill Chain funnel (urutan progresi logis,
BUKAN diurutkan by-count), tabel Data Quality lengkap, dan Security
Domain langsung (terpisah, expander sendiri).

**Testing yang dilakukan:**
1. Parser diuji dengan 219 baris asli - MITRE Technique summary (47
   unik, T1078=28x teratas), Tactic summary (7 unik), Kill Chain summary
   (7 stage, bentuk funnel masuk akal: Exploitation=67 tertinggi).
2. Data Quality report tepat menangkap 2 anomali (tidak lebih tidak
   kurang) - diverifikasi manual.
3. Pipeline end-to-end PENUH (termasuk Excel export) dengan file terbaru
   (tanpa Summary) - sukses setelah 5 titik perbaikan.
4. **Backward compatibility diverifikasi**: file LAMA (dengan Summary,
   tanpa MITRE) tetap jalan 100% normal - `top_rule` tetap 20 baris
   seperti biasa, MITRE/Security_Domain_Direct kosong tanpa error.

## 89. BARU: Kamus Nama MITRE + Insight Otomatis (menjawab gap yang ditanya user)

User bertanya: apakah kode sudah menjelaskan ARTI top MITRE/KillChain dan
insight-nya? Jawaban jujur saat itu: BELUM - cuma tampil kode mentah +
jumlah. Diperbaiki:

**Kamus nama resmi MITRE** (`MITRE_TACTIC_NAMES`, `MITRE_TECHNIQUE_NAMES`
di `core/mitre_killchain.py`) - mencakup SEMUA 47 Technique + 7 Tactic
yang terkonfirmasi ada di data asli (bukan asal tebak sebagian). Kode
yang tidak ada di kamus tetap ditampilkan dengan kode aslinya + jujur
"(nama tidak dikenal)" - TIDAK mengarang nama technique yang belum
terverifikasi.

**Fungsi `generate_mitre_killchain_insights()`** - insight dinamis (bukan
cuma angka) dari data aktual:
- Technique paling sering + persentase dari total insiden
- Tactic paling dominan
- Kill Chain stage yang paling banyak tercatat, DENGAN INTERPRETASI beda
  tergantung posisi di kill chain (stage awal = kabar baik/deteksi dini,
  stage lanjut = perlu perhatian/deteksi terlambat)
- **Postur deteksi keseluruhan**: % insiden di tahap awal vs tahap lanjut
  kill chain - metrik strategic yang menjawab "apakah kita nangkep
  serangan lebih awal makin membaik?"

**app.py**: chart Executive Summary & Threat Profiling sekarang pakai
kolom `Label` ("T1078 - Valid Accounts", bukan cuma "T1078"). Insight
otomatis ditampilkan di expander (Executive Summary) dan langsung
(Threat Profiling).

Diuji dengan 219 baris data asli: insight yang dihasilkan - "T1078 -
Valid Accounts mendominasi (28 insiden, 12.8%)", "Exploitation stage
paling banyak tercatat (67 insiden)", "47.7% deteksi tahap awal vs 52.3%
tahap lanjut". Backward compatibility diverifikasi ulang - file lama
(tanpa MITRE) tetap kosong tanpa error.

## 90. Perbaikan 3 gap dari review user + jawaban 5 pertanyaan (MITRE/KillChain/Attack Surface)

**1. BARU: `security_domain_direct_trend`** - kolom 'Security Domain'
langsung sebelumnya cuma snapshot 1 periode (tidak ada histori). Sekarang
punya tracking lintas bulan sendiri (`database/security_domain_direct_
history.csv`, TERPISAH dari `attack_pattern_history.csv`) - pola sama
seperti `build_attack_pattern_trend()`. Ditampilkan sebagai expander baru
di Executive Summary, berdampingan dengan tabel lama supaya user bisa
BANDINGKAN: kalau tabel lama (keyword-mapping) "Others" semua tapi tabel
baru ini terisi normal, terbukti masalahnya di rule-mapping (butuh
'Summary'), bukan di data domain itu sendiri.

**2. BUG DIPERBAIKI: Chart Tactic hilang di Executive Summary** -
sebelumnya insight teks menyebut "Tactic paling dominan: TA0002" tapi
chart pendukungnya CUMA ada di halaman Threat Profiling, bikin bingung
(insight tanpa visual). Sekarang Executive Summary punya 3 kolom
(Technique/Tactic/Kill Chain), konsisten dengan insight yang ditampilkan.

**3. Klarifikasi UI ditambahkan** (caption, bukan ubah logic):
- Kill Chain chart: dijelaskan eksplisit mana stage "awal" vs "lanjut"
  yang dipakai di insight "Postur Deteksi", dan bahwa Exploitation
  SENGAJA dikeluarkan dari kedua kelompok itu (posisi tengah/transisi).
- Warning eksplisit: SEMUA chart MITRE/KillChain menghitung SEMUA tiket
  TANPA filter True Positive/False Positive - dikonfirmasi LANGSUNG ke
  data (`Export_Data_SOC_1.xlsx`) TIDAK ADA kolom klasifikasi TP/FP sama
  sekali - ditandai sebagai gap data buat ditanyakan ke tim Ivanti.

**Jawaban ke user (didokumentasikan, tidak perlu kode)**:
- T1078 "Valid Accounts" bukan berarti "akun valid = ancaman" - artinya
  penyerang MEMAKAI kredensial yang secara teknis valid (dicuri/brute-
  force) untuk akses tidak sah.

**Data gap resmi untuk ditanyakan ke tim Ivanti** (dikonfirmasi via
inspeksi data langsung, bukan asumsi):
1. Kolom klasifikasi True Positive/False Positive - TIDAK ADA sama sekali
   di export saat ini, sehingga statistik MITRE/Kill Chain tidak bisa
   dipisah antara insiden yang benar-benar ancaman vs yang ternyata FP.
2. Kolom 'Summary' (sudah ditandai sebelumnya) - masih perlu dipastikan
   ada di export bulan-bulan berikutnya, supaya Attack Surface Trend
   (keyword-mapping) tidak jatuh "Others" semua lagi.

Diuji: `security_domain_direct_trend` dengan 2 periode - histori
terakumulasi benar. Backward compatibility file lama tetap OK (trend
kosong tanpa error). Pipeline penuh sampai Excel export sukses.

## 91. Fix lanjutan: "Object per Priority - Domain" masih Others (tabel berbeda dari #90)

User melaporkan tabel "Object (Target) per Priority - Domain" di Executive
Summary MASIH tampil "Others" 100% - ini TABEL BERBEDA dari yang diperbaiki
di #90 (itu untuk Attack Surface TREND lintas bulan; ini untuk snapshot 1
periode di section Attack Patterns) - akar masalah SAMA (butuh 'Summary'),
tapi kode-nya terpisah, jadi perlu diperbaiki terpisah juga.

**core/processor.py**: `build_threat_profiling()` ditambah
`self.threat_by_priority_domain_direct` - versi PARALEL pakai kolom
'Security Domain' LANGSUNG (bukan keyword-mapping), sama filosofinya
dengan `security_domain_direct_trend` di #90.

**app.py**: ditambahkan DETEKSI OTOMATIS - kalau versi keyword-mapping
cuma hasilkan 1 baris "Others" (tanda gagal total) DAN versi langsung
punya data asli, tampilkan versi LANGSUNG sebagai utama dengan warning
jelas kenapa. Kalau keyword-mapping normal, tampilkan seperti biasa +
versi langsung sebagai expander pembanding (tidak dihapus, sesuai arahan
user "pakai keduanya terpisah").

Diuji dengan data asli (Export_Data_SOC_1.xlsx, 219 insiden): versi
keyword-mapping 100% Others (1 baris) vs versi langsung menunjukkan 5
domain asli (Infrastructure=164, Applications=50, Documents=3, Data=1,
People=1) - PERSIS jumlah yang sebelumnya "tersembunyi" di balik "Others".
Backward compatibility diverifikasi: file lama (dengan Summary) tetap
tampil 5 domain normal seperti biasa via keyword-mapping, versi direct
kosong tanpa error (kolom tidak ada).

## 92. BARU: Implementasi 4 Poin MoM Feedback BoD (MITRE ATT&CK & Kill Chain)

BoD memberikan feedback resmi (MoM) untuk dashboard MITRE/Kill Chain -
diimplementasikan penuh setelah klarifikasi 1 hal ("prosedur" = Sub-
Technique, dikonfirmasi user - bukan "Procedure" resmi MITRE yang
butuh data naratif yang tidak kita punya).

**1. Hierarki Tactic → Technique → Sub-Technique** (`build_mitre_
hierarchy()` di `core/mitre_killchain.py`) - dibangun dari CO-OCCURRENCE
per tiket (tactic & technique yang muncul di TIKET YANG SAMA = 1 edge),
BUKAN dari tabel mapping resmi MITRE (tidak ada sebagai field terstruktur
di data). Tiket tanpa tactic sama sekali masuk bucket "Tactic Tidak
Diketahui" - JUJUR, tidak ditebak.

**2. Technique paling berbahaya BERDASARKAN IMPACT** (`build_technique_
impact()`) - skor % kemunculan Technique yang berujung Severity High/
Critical ATAU breach SLA, BUKAN cuma frekuensi. Baseline keseluruhan
(58% dari 219 insiden) dihitung terpisah sebagai pembanding "lebih
berbahaya dari rata-rata atau tidak" - divalidasi manual sebelum
diimplementasi (technique dengan Impact 100% memang signifikan di atas
baseline 58%, bukan artefak data homogen).

**3. Visual "anchor" yang mudah dipahami** - `plot_sunburst()` (chart
baru) untuk hierarki 3 level (klik untuk zoom), `plot_funnel()` (chart
baru, native Plotly funnel) untuk Kill Chain.

**4. Drill-down otomatis dari stage tertinggi** - `build_mitre_by_
killchain_stage()`, dipanggil OTOMATIS terhadap stage dengan Count
tertinggi (BUKAN hardcode "Exploitation" - kalau bulan depan stage lain
yang tertinggi, drill-down ikut menyesuaikan sendiri).

**5. Kill Chain FUNNEL monoton menurun** (`build_killchain_funnel()`) -
BEDA metodologi dari `build_killchain_summary()` yang lama: untuk tiap
insiden, ambil stage TERDALAM yang tercatat, lalu hitung CUMULATIVE
"insiden yang mencapai SETIDAKNYA stage ini". Hasilnya PASTI menurun/sama
ke kanan - bukan dipaksa, tapi definisi matematis "at least N" adalah
superset dari "at least N+1". Kedua versi (funnel di Executive Summary,
raw-per-tiket di Threat Profiling) DIPERTAHANKAN KEDUANYA dengan caption
yang jelas beda metodologinya - tidak menghapus yang lama.

**app.py**: Executive Summary bagian 3 dirombak total sesuai 4 poin di
atas. Threat Profiling caption diperjelas (bukan funnel, non-cumulative).

Diuji dengan 219 baris data asli:
- Hierarki: 54 kombinasi Tactic-Technique-SubTechnique.
- Impact: baseline 58% divalidasi manual, technique teratas 100% (T1566
  Phishing, T1057 Process Discovery, dst - semua signifikan di atas baseline).
- Drill-down: stage tertinggi terdeteksi otomatis = Exploitation (67
  insiden), Tactic dominan di situ = Credential Access (15) & Execution (14).
- Funnel: diverifikasi PROGRAMATIS monoton menurun (154→154→154→109→77→42→42) - True.
- Backward compatibility: file lama (tanpa MITRE) - semua field baru
  kosong tanpa error, `killchain_top_stage`=None (bukan crash).

## 93. Restrukturisasi urutan MITRE/KillChain + Homepage lebih menarik

**1. Fix urutan baca yang membingungkan** - user bingung baca dashboard
karena urutannya salah: TTP keseluruhan (Sunburst+Impact) tampil DULUAN
sebelum Kill Chain, padahal alur logis yang benar: **Kill Chain = anchor/
cerita besar dulu (di tahap mana masalah terkonsentrasi), TTP = turunan/
detail teknis SESUDAHNYA (apa yang terjadi di tahap itu)**.

Disusun ulang di Executive Summary:
1. **🎯 Anchor**: Cyber Kill Chain Funnel (paling atas, prominent)
2. **⬇️ Turunan langsung dari anchor**: Tactic & Technique KHUSUS dari
   stage tertinggi (drill-down yang sebelumnya di posisi akhir, sekarang
   langsung menyambung setelah anchor - alur baca jadi 1 garis lurus)
3. **📂 Detail tambahan (expander, opsional)**: TTP keseluruhan periode
   (Sunburst + Impact ranking) - untuk yang mau lihat lebih dalam,
   TIDAK menghalangi alur baca utama.

Tidak ada logic/kalkulasi yang berubah - murni urutan TAMPILAN.

**2. Homepage diperbaiki total** - sebelumnya cuma judul teks + 3 tombol
flat (lihat screenshot user - terlihat kosong/plat). Sekarang: hero title
lebih besar (42px) + subtitle, 3 card bergaya modern (gradient background,
shadow, hover effect naik saat di-hover), tiap card punya ikon besar (52px)
+ nama + deskripsi singkat 1 baris apa isi report itu, tombol "Buka X →"
di bawah tiap card yang berubah warna solid saat di-hover.

Diverifikasi: pipeline data (loader/normalizer/validator/processor/Excel
export) TIDAK terpengaruh sama sekali - perubahan ini murni CSS/layout,
tidak menyentuh business logic manapun.

## 94. Koreksi 4 kesalahan desain dari review user (jujur - bukan preferensi, tapi kesalahan)

**1. KOREKSI PENTING: Kill Chain Funnel bisa menyesatkan** - user curiga
bentuk "selalu menurun" itu dipaksakan. DIKONFIRMASI BENAR - bentuk
menurun itu PROPERTI MATEMATIS dari cara hitung "insiden yang mencapai
SETIDAKNYA stage ini" (selalu superset, PASTI menurun apapun isi
datanya) - BUKAN cerminan data mentah, dan BUKAN bukti kill chain
membaik/tertanggulangi. Diperbaiki: chart RAW/non-cumulative (yang boleh
fluktuatif, jujur apa adanya) dikembalikan jadi ANCHOR UTAMA. Funnel
dipindah ke expander terpisah dengan WARNING EKSPLISIT di paling atas
sebelum chart-nya (bukan cuma caption kecil) menjelaskan ini model,
bukan data, dan tidak boleh disimpulkan sebagai bukti perbaikan.

**2. Urutan Tactic-Technique dibalik** - Tactic (level lebih umum/parent)
sekarang di KIRI (dibaca duluan), Technique (turunan/lebih spesifik) di
KANAN - sebelumnya terbalik, membingungkan karena Technique seolah
duluan padahal Tactic levelnya lebih tinggi.

**3. Sunburst disederhanakan + jawaban jujur soal insight tuning
Splunk** - dibatasi Top 15 kombinasi (dari 54) supaya tidak terlalu
padat dibaca. Ditambahkan `st.info()` yang JUJUR: sistem BELUM BISA
memberi insight "rule Splunk mana yang perlu di-tuning" dari chart ini,
karena butuh data PEMETAAN Rule Splunk ↔ MITRE Technique yang SAAT INI
TIDAK ADA - bukan mengarang insight yang tidak didukung data.

**4. Impact 100% yang ambigu - filter sample size ditambahkan**
`build_technique_impact()` di `core/mitre_killchain.py` sekarang punya
kolom `Sample_Size_Warning` (True kalau n<5) - technique dengan sampel
terlalu kecil DIPISAH dari ranking utama (tidak ditampilkan sebagai
"berbahaya" di chart utama), dan chart yang tersisa menampilkan jumlah
sampel LANGSUNG di label (mis. "T1566 - Phishing (n=18)") - supaya tidak
ada lagi "100% berbahaya" tanpa konteks berapa insiden yang jadi dasarnya.

Diuji: 219 baris data asli - 20 Technique punya sampel cukup (n>=5), 27
Technique disaring karena sampel < 5. Backward compatibility file lama
tetap aman (kosong tanpa error). Pipeline end-to-end sampai Excel export sukses.

## 95. Simplifikasi drastis Executive Summary + fix bug KeyError (review kedua BoD)

User memberi kritik lanjutan yang semuanya valid - simplifikasi besar
dilakukan sesuai prinsip yang seharusnya dipegang sejak awal: **Summary
= sederhana untuk BoD, Details/Threat Profiling = lengkap untuk analyst**.

**1. Kill Chain: HAPUS funnel dari Executive Summary** - 2 chart Kill
Chain berdampingan (mentah fluktuatif vs funnel selalu menurun) tetap
membingungkan BAGAIMANAPUN disclaimer ditambahkan. Executive Summary
sekarang HANYA punya 1 chart Kill Chain (data mentah, jujur). Funnel +
disclaimer-nya DIPINDAH ke Threat Profiling sebagai expander opsional -
tidak dihapus total, cuma tidak lagi bersaing perhatian di halaman BoD.

**2. Drill-down: mini-Sunburst (korelasi Tactic->Technique), bukan 2 bar
chart terpisah** - `build_mitre_by_killchain_stage()` di `core/mitre_
killchain.py` sekarang JUGA return hierarki 2-level (Tactic->Technique)
khusus untuk stage tertinggi. User bisa klik 1 Tactic (mis. TA0006) dan
langsung lihat Technique-Technique turunannya (T1110, T1078, dst) sesuai
spesifikasi resmi MITRE ATT&CK - bukan 2 chart independen yang hubungannya
tidak kelihatan.

**3. "Lihat TTP Keseluruhan Periode" DIPINDAH ke Threat Profiling** -
seluruh isinya (Sunburst 15 kombinasi teratas, ranking Impact, caveat
soal tuning Splunk) tetap ADA, cuma tidak lagi di Executive Summary -
sesuai kritik user ini terlalu kompleks untuk BoD.

**4. BUG DIPERBAIKI: KeyError 'Sample_Size_Warning'** - root cause SAMA
seperti bug-bug sebelumnya (report cache lama dibuka via "Buka", bukan
di-generate ulang, jadi kolom baru belum ada). Ditambahkan PENGAMAN
KODE (bukan cuma minta user generate ulang): cek `"Sample_Size_Warning"
in impact.columns` dulu sebelum dipakai - kalau tidak ada, fallback
tanpa filter + info jelas "laporan ini dari cache versi lama". Ini
mencegah crash yang SAMA terjadi lagi di masa depan untuk field-field
baru lainnya juga (pola defensif, bukan patch sekali pakai).

Diuji: hierarki drill-down (22 kombinasi Tactic-Technique khusus stage
Exploitation) tervalidasi benar. Skenario cache lama disimulasikan -
TIDAK crash, fallback informatif. Backward compatibility file lama:
`killchain_top_stage_hierarchy` kosong tanpa error. Pipeline end-to-end
sampai Excel export sukses.

## 96. Fix: Drill-down MITRE tersedia untuk SEMUA stage Kill Chain, bukan cuma tertinggi

User menemukan keterbatasan tepat: drill-down sebelumnya HANYA hitung
untuk stage TERTINGGI (Exploitation, 67 insiden) - stage lain yang juga
signifikan (Delivery=57, Actions On Objectives=42, Reconnaissance=16)
tidak bisa dilihat MITRE breakdown-nya sama sekali.

**core/processor.py**: `build_mitre_killchain()` sekarang hitung drill-
down (Tactic/Technique/hierarchy) untuk **SEMUA stage yang punya data**
(Count > 0), disimpan sebagai dict `killchain_stage_drilldown` (key =
nama stage). `killchain_top_stage` tetap disimpan sebagai DEFAULT
pilihan (yang paling relevan dilihat pertama), BUKAN satu-satunya yang
bisa diakses.

**app.py**: ditambahkan `st.selectbox` "Pilih stage untuk dilihat detail
Tactic/Technique-nya" - default ke stage tertinggi (dengan label "PALING
BANYAK dari semua stage"), tapi user bisa pilih stage manapun (Reconnaissance,
Weaponization, Delivery, Installation, Privilege Escalation, Actions On
Objectives) untuk lihat mini-Sunburst Tactic->Technique-nya masing-masing.

Diuji dengan data asli - SEMUA 7 stage terkonfirmasi punya drill-down
(Reconnaissance n=16/8 kombinasi, Weaponization n=1/2, Delivery n=57/9,
Exploitation n=67/22, Installation n=35/8, Privilege Escalation n=4/2,
Actions On Objectives n=42/25). Backward compatibility: file lama ->
`killchain_stage_drilldown` = {} kosong tanpa error (selectbox otomatis
tidak muncul karena dict kosong, tidak crash).

## 97. Investigasi mendalam & HAPUS chart yang terbukti tidak valid (Impact Ranking)

**Pertanyaan 1 - "MITRE tidak menggambarkan Kill Chain stage"**: DICEK
LANGSUNG - terkonfirmasi chart "Turunan MITRE Keseluruhan Periode"
memang MENGGABUNGKAN semua 219 insiden (termasuk 27 yang TIDAK punya
Kill Chain stage sama sekali) - BUKAN dipecah per stage. Ini bukan bug,
tapi JUDUL/CAPTION saya yang menyesatkan (tidak menjelaskan ini gabungan,
bukan per-stage). Diperbaiki: ditambahkan WARNING EKSPLISIT di atas
chart menjelaskan ini gabungan seluruh periode, dan mengarahkan ke
selector drill-down per-stage di Executive Summary untuk yang butuh
breakdown per stage.

**Pertanyaan 2 - "Impact selalu 100%" - INVESTIGASI MENDALAM,
DITEMUKAN CHART TIDAK VALID, DIHAPUS**: dicek langsung ke data - untuk
5 Technique yang diperiksa (T1566, T1055, T1057, T1530, T1567), SEMUA
insiden per Technique punya Severity DAN Priority yang PERSIS SAMA
(tidak ada variasi sama sekali). Diperluas ke SEMUA 47 Technique:
**38 dari 47 (81%) punya Severity 100% seragam** di semua insidennya -
bukti kuat Severity/Priority ditentukan OTOMATIS berdasarkan jenis
Technique (semacam SOP/template), BUKAN dinilai independen per insiden.

**Kesimpulan**: chart "Technique dengan Impact Tertinggi" bersifat
MELINGKAR (circular) - dia cuma menghitung ulang "Technique mana yang
templatenya di-set High", bukan mengukur bahaya nyata berdasarkan hasil
investigasi kasus per kasus. Chart ini **DIHAPUS SELURUHNYA** dari
`app.py` (Threat Profiling) - lebih baik tidak ada chart daripada ada
chart yang kelihatan seperti insight statistik tapi sebenarnya tidak
bermakna.

**Catatan untuk ditanyakan ke tim Ivanti/SOC** (temuan baru): field
`Severity` tampaknya di-set berdasarkan KATEGORI/TEMPLATE per jenis
insiden, bukan penilaian independen tiap kasus - perlu diklarifikasi
apakah ini memang mekanisme yang dimaksud, atau ada proses assessment
manual yang seharusnya terjadi tapi belum konsisten dijalankan.

`build_technique_impact()` dan `technique_impact` di processor.py TIDAK
dihapus dari kode backend (masih dihitung, masih ada di report dict) -
cuma TIDAK DITAMPILKAN lagi di UI, supaya kalau nanti ada klarifikasi
dari SOP Severity ini dan ternyata metriknya bisa diperbaiki, tidak
perlu bangun ulang dari nol.

## 98. Ganti Sunburst -> Network/Correlation Chart untuk drill-down Tactic<->Technique

User menunjukkan contoh network graph (node-link chart) dan menanyakan
apakah Sunburst bisa diganti - masalah konkretnya: pada stage "Delivery",
"Tactic Tidak Diketahui" mendominasi 64% area Sunburst, MENELAN tampilan
Technique lain yang jadi kelihatan seperti serpihan tak terbaca.

**app.py**: fungsi baru `plot_network()` - bipartite correlation chart
(Tactic di kolom kiri, Technique di kolom kanan, garis penghubung makin
tebal/gelap = makin sering muncul bersamaan, ukuran simpul = total
kemunculan). Dipasang di bagian "Turunan dari Anchor" (drill-down
per-stage, Executive Summary) MENGGANTIKAN `plot_sunburst` - dipilih
KHUSUS untuk kasus ini karena Sunburst rawan 1 kategori dominan menelan
kategori lain, sedangkan network chart tetap menampilkan SEMUA node
proporsional tanpa saling menutupi.

Sunburst TIDAK dihapus dari kodebase - tetap dipakai di Threat Profiling
untuk "Turunan MITRE Keseluruhan Periode" (3 level Tactic->Technique->
Sub-Technique, use case berbeda, tidak segera bermasalah dengan
dominasi kategori tunggal se-ekstrem drill-down per-stage).

Diuji dengan data asli stage "Delivery" (yang menunjukkan masalah
64% dominasi) - hasil: 3 Tactic node (termasuk "Tactic Tidak Diketahui")
dan 9 Technique node SEMUA tetap terlihat jelas sebagai node terpisah
dengan ukuran proporsional, tidak ada yang tertelan. Pipeline end-to-end
sampai Excel export sukses.

## 99. Fix label salah hitung (4 vs 8) + warna & anti-tabrakan garis di network chart

**Bug ditemukan user & DIKONFIRMASI ke data**: stage "Privilege Escalation"
tercatat 4 insiden (benar), tapi node "Tactic Tidak Diketahui" di network
chart menunjukkan "(8)" - user bingung menyangka data tidak konsisten.
DICEK LANGSUNG: bukan data salah - 4 insiden yang SAMA masing-masing
punya 2 Technique sekaligus (T1098 DAN T1098.003 di tiket yang sama), jadi
sum pasangan Tactic-Technique = 4+4=8, TAPI insiden aslinya cuma 4. Label
sebelumnya salah menampilkan sum-pasangan sebagai kalau itu jumlah insiden.

**Diperbaiki di sumbernya** (`core/mitre_killchain.py`):
`build_mitre_by_killchain_stage()` sekarang hitung UNIQUE INCIDENT COUNT
yang benar (pakai `set()` per baris insiden, dedup dalam 1 insiden) untuk
Tactic (termasuk bucket "Tactic Tidak Diketahui") dan Technique secara
terpisah dari tabel pasangan - return value bertambah jadi 6 (sebelumnya
4): tambahan `tactic_unique_n`, `technique_unique_n` sebagai dict.

**Perbaikan visual sesuai contoh user** (`plot_network()` di app.py):
1. Label simpul sekarang pakai `left_unique_n`/`right_unique_n` (jumlah
   insiden benar), BUKAN sum pasangan lagi.
2. **Warna beda per Tactic** - setiap Tactic (kiri) dapat warna dari
   PALETTE, garis & node Technique yang didominasi Tactic itu ikut warna
   yang sama - gampang ditelusuri "garis ini punya siapa".
3. **Technique (kanan) dikelompokkan per Tactic dominan** (bukan cuma
   diurutkan by-count independen) - Technique dari Tactic yang sama
   diposisikan berdekatan, MENGURANGI garis saling bersilangan.

**Refactor pembersihan**: atribut `killchain_top_stage_technique/tactic/
n/hierarchy` (return value lama yang cuma dipakai untuk 1 stage
teratas) dihapus total dari processor.py dan report dict - sudah
digantikan `killchain_stage_drilldown` (dict semua stage) sejak
perbaikan #96, atribut lama ini jadi dead code yang malah bikin
AttributeError setelah signature function berubah. Ditemukan &
diperbaiki 2 bug turunan saat testing (unpack 4 vs 6 return value,
duplikasi assignment).

Diuji: Privilege Escalation - `tactic_unique_n={'Tactic Tidak Diketahui':
4}`, `technique_unique_n` masing-masing 4 - PERSIS sesuai 4 insiden asli.
Delivery - Technique berhasil dikelompokkan berurutan per Tactic dominan
(3 Technique 'Tidak Diketahui' -> 4 Technique 'Initial Access' -> 2
Technique 'Execution'), warna berbeda per grup. Backward compatibility &
pipeline end-to-end tetap sukses.

## 100. Konfirmasi bug #99 sudah teratasi + fitur BARU: fokus/zoom ke 1 Tactic

User melaporkan lagi angka "Tactic Tidak Diketahui (60)" untuk stage
Delivery (57 insiden total) - jumlah semua Tactic (60+22+12=94) jauh
lebih besar dari total. DICEK LANGSUNG dengan kode versi #99 (perbaikan
sebelumnya): hasilnya 40+11+6=57 - PERSIS PAS dengan total insiden, tidak
ada lagi kelebihan. Angka 60/22/12 di laporan user TERBUKTI dari cache
lama (dibuat sebelum perbaikan #99) - bukan bug baru. User disarankan
generate ulang periode ini.

**BARU: Fokus/zoom ke 1 Tactic tertentu** (sesuai permintaan user) -
selectbox "🔍 Fokus ke 1 Tactic tertentu" di atas network chart drill-down.
Pilih 1 Tactic (mis. "TA0001 - Initial Access") -> network chart otomatis
hanya menampilkan Technique-Technique yang berasosiasi dengan Tactic itu
saja, Tactic lain disembunyikan sementara. Pilih "Semua Tactic" untuk
kembali ke tampilan lengkap.

Diuji dengan data asli: fokus ke "TA0001 - Initial Access" pada stage
Delivery - hasil benar menyaring ke 4 Technique yang berasosiasi
(T1091, T1052, T1036, T1190), label tetap pakai jumlah insiden unik (11).
Pipeline end-to-end sampai Excel export tetap sukses.

## 101. BUG DIPERBAIKI: KeyError 'tactic_unique_n' - pengaman cache lama untuk fitur Fokus Tactic

Root cause SAMA seperti bug #96 sebelumnya (Sample_Size_Warning) - fitur
"Fokus ke 1 Tactic" yang baru ditambahkan kemarin (#100) mengakses
`dd["tactic_unique_n"]`/`dd["technique_unique_n"]` LANGSUNG tanpa
pengaman, padahal laporan cache lama (dibuat sebelum fitur ini ada)
tidak punya key itu di dict `killchain_stage_drilldown`.

**app.py** - SEMUA akses ke `dd[...]` di bagian drill-down diganti jadi
`.get()` dengan default aman (`dd.get("hierarchy")`, `dd.get("n", 0)`,
`dd.get("tactic_unique_n") or {}`, dst). Ditambahkan JUGA deteksi
eksplisit di awal blok: kalau `"tactic_unique_n" not in dd`, tampilkan
info jelas "laporan ini dari cache versi lama, generate ulang" - SAMA
pola yang sudah dipakai di bug #96, supaya konsisten di seluruh aplikasi.

**Pelajaran untuk ke depannya**: setiap kali menambahkan field baru ke
`report` dict ATAU ke dict bersarang seperti `killchain_stage_drilldown`,
WAJIB pakai `.get()` bukan akses langsung `[...]` di app.py - supaya
laporan cache dari versi kode manapun sebelumnya tidak pernah crash,
cuma fallback ke default/kosong.

Diuji: simulasi dict cache lama tanpa `tactic_unique_n` - BERHASIL
tidak crash, fallback ke `{0}`/kosong. Pipeline end-to-end dengan data
terbaru tetap normal setelah pengaman ditambahkan.

## 102. BUG DIPERBAIKI (analisis Principal Engineer): ValueError NaN di marker size plot_network

**Root cause pasti**: fitur "Fokus Tactic" dengan cache lama menghasilkan
`left_unique_n = {focus_tactic: 0}` - dict TIDAK KOSONG (lolos pengecekan
`if left_unique_n:` truthy check), tapi ISINYA literal 0. Ini bikin
`max_left = 0`, lalu `0/0 = NaN` di kalkulasi ukuran marker Scatter -
Plotly menolak NaN sebagai size property -> ValueError -> crash.

**Analisis mendalam** (review menyeluruh, bukan cuma tambal titik crash):
ditemukan pola RENTAN YANG SAMA diulang 3x di fungsi ini (edge line
width/opacity, left node size, right node size) - SEMUA pakai pembagian
langsung `value/max` tanpa guard terhadap `max=0` atau `value=NaN`. Juga
ditemukan 2 celah tambahan: `int(NaN)` akan `ValueError` terpisah kalau
NaN lolos sampai situ, dan `left_nodes[0]` akan `IndexError` kalau
`left_nodes` kosong.

**Perbaikan komprehensif** (`plot_network()` di app.py):
1. `_resolve_totals()` - helper baru yang VALIDASI data override sebelum
   dipakai: kalau `unique_n` yang dikirim caller SEMUA NOL atau kosong
   (bukan cuma dicek "ada key atau tidak", tapi dicek SUM-nya), fallback
   TOTAL ke `edge_sum` (yang selalu valid, berasal langsung dari data
   chart yang digambar) - bukan cuma fillna per-key seperti sebelumnya.
2. `_safe_ratio()` - helper terpusat untuk SEMUA kalkulasi proporsional
   (ukuran marker, lebar garis, opacity) - aman terhadap `max_value<=0`,
   `NaN`, dan hasil di luar rentang [0,1] - dipakai konsisten di 3 tempat
   yang sebelumnya rawan, bukan 3 kalkulasi terpisah yang masing-masing
   bisa lupa di-guard.
3. Guard tambahan: `int(x) if pd.notna(x) else 0` untuk label teks,
   `left_color.get(..., default_color)` dan cek `len(left_totals)==0`
   di awal untuk cegah IndexError pada kasus 0 node.

**Testing ekstensif** (extract & test fungsi langsung dari app.py pakai
stub streamlit+plotly custom yang MEMVALIDASI setiap size bukan NaN):
1. Skenario crash ASLI direproduksi (`left_unique_n={focus_tactic: 0}`,
   `right_unique_n={}`) - BERHASIL render tanpa crash.
2. Skenario cache sangat lama (kedua dict kosong total `{}`) - berhasil.
3. Data normal (bukan cache lama) - berhasil, tidak ada regresi.
4. Edge case ekstrem (`Count=0` di SATU-SATUNYA baris hierarki, bikin
   `max_edge=0` juga) - berhasil, tidak NaN.
Pipeline end-to-end dengan data asli tetap sukses sampai Excel export.

## 103. BARU: Modul SLA SR Security Operations (modul ke-4)

Modul baru sesuai permintaan - tracking Service Request bulanan tim
Security Operations. Dibangun mengikuti pola arsitektur yang sudah
established (module isolation, histori bulanan, navigasi 2-tingkat
Summary/Details - sama seperti Cynet Agent Compliance).

**Inspeksi data (SR_Updated_Cyber.xlsx, sheet 'Cybersecurity L2 only',
4718 baris Jan-Sep 2026, 23 kolom) sebelum coding:**
- Kolom `Days`/`Hours`/`Minutes`/`Seconds` = breakdown durasi resolusi
  (ResolvedOn-CreatedOn), diverifikasi cocok PERSIS ke detik.
- `Response Meet/Breach` dan `Resolution Meet/Breach` = 2 dimensi SLA
  TERPISAH (Response breach jarang ~0.3%, Resolution breach lebih sering
  ~14.7% - konfirmasi via full dataset).
- `Technician` = 11 individu unik, ~5% missing (ditandai 'Unassigned',
  bukan dibuang).
- `OwnerTeam` TIDAK dipakai untuk filter - nama sheet sendiri sudah
  mengindikasikan scope Security Operations, sesuai konfirmasi user
  bahwa `Technician` adalah kolom individu tim yang relevan.
- Upload flow dikonfirmasi user: BULANAN terpisah (pola sama SOC/Cynet),
  bukan 1 file kumulatif.

**File BARU**: `sr_sla/__init__.py`, `sr_sla/loader.py` (baca &
normalisasi, toleran nama sheet berbeda dengan fallback + warning),
`sr_sla/processor.py` (histori bulanan `database/sr_sla_monthly_raw/`,
build_summary, build_technician_performance, build_breach_detail,
build_trend, generate_insights), `sr_sla/dashboard.py` (UI self-contained,
tidak import modul lain).

**app.py**: DIVERIFIKASI via diff - HANYA penambahan (card ke-4 di
homepage + 1 blok gate baru), NOL baris kode SOC/Cynet/IOC yang berubah.

**Dashboard fitur:**
- Summary: KPI (Total SR, Response/Resolution Breach count & %, Avg
  Resolution Hours), chart Technician breach terbanyak, chart Total SR
  per Technician, trend Total SR & Breach Rate lintas bulan (butuh >=2
  periode), Key Insights dinamis, tabel ringkasan performa semua Technician.
- Details: filter (Technician/Status/Breach) + search + tabel breach
  detail tersendiri + export CSV.

**Testing yang dilakukan:**
1. Load & normalize dengan subset asli 1 bulan (Januari, 477 SR) -
   sukses, Data Quality report benar (1 Unassigned, 0 missing ResolvedOn).
2. 2 periode berturut (Januari 41.3% breach, Februari 19.0% breach) -
   histori akumulasi benar, trend insight otomatis terdeteksi "membaik
   -22.3 poin persen".
3. Technician performance tervalidasi - oktriwibowo (Jan) 61.5% breach
   rate dari 143 SR, breach detail table benar menampilkan 200 SR breach.
4. SOC pipeline dijalankan ulang setelah penambahan modul - tetap normal,
   tidak ada regresi.
5. Preview HTML dipublikasikan via Artifact untuk direview user SEBELUM
   replace file lokal (sesuai permintaan eksplisit).

## 104. Lengkapi SR SLA dengan fitur Compare (samakan dengan Cynet/SOC)

User bertanya apakah modul SR SLA sudah setara fitur compare-nya dengan
Cynet/SOC - jawaban jujur saat itu: BELUM, cuma ada trend chart pasif.
Dilengkapi sekarang:

**Compare selector** (Previous Month / Last 3 Months / Last 6 Months /
None) - `prev_period` BENAR-BENAR ikut rentang yang dipilih (bukan selalu
"1 bulan lalu" apapun mode-nya - pola yang sudah diperbaiki di Cynet
sebelumnya, diterapkan KONSISTEN dari awal di modul baru ini, bukan
menunggu bug yang sama muncul lagi).

**Delta KPI** - semua 5 KPI card (Total SR, Response Breach, Resolution
Breach, Resolution Breach %, Avg Resolution Hours) sekarang tampilkan
panah naik/turun vs periode pembanding, dengan `delta_color="inverse"`
untuk metrik breach (naik = merah/buruk, turun = hijau/baik).

**Header "Comparing X vs Y (mode)"** - konsisten dengan Cynet.

**Trend chart** sekarang ikut rentang `trend_periods` dari Compare mode
yang dipilih (sebelumnya selalu pakai SEMUA periode tersimpan).

Diuji dengan 3 bulan data asli (Jan/Feb/Mar 2026): "Previous Month" vs
"Last 3 Months" menghasilkan pembanding BERBEDA (Feb vs Jan) - terbukti
logic Compare bekerja benar, bukan selalu bandingkan ke bulan sebelumnya
seperti bug lama di Cynet. Delta Resolution Breach % Jan->Feb: -22.3
poin (membaik), insight otomatis konsisten. Pipeline end-to-end tetap sukses.

## 105. BARU: Field Triage (TP/FP) + Parser Description + 2 Bug Fix (format Export_Data_SOC_2.xlsx)

Inspeksi file terbaru (Export_Data_SOC_2.xlsx, 228 insiden, 32 kolom)
menemukan 1 field BARU yang sangat berharga dan 1 field tanpa skema tetap:

**Field `Triage` (True Positive/False Positive)** - INI MENUTUP GAP yang
ditandai sejak #90 ("tidak ada filter TP/FP untuk chart MITRE/KillChain").
Dikonfirmasi: 64.9% tiket di data sample ternyata False Positive! Dampak
besar kalau tidak difilter.

**core/mitre_killchain.py**: `normalize_triage()` (nilai tak dikenal/NaN
-> 'Unknown', bukan dipaksa), `build_triage_summary()`. `enrich_incident_
mitre_killchain()` ditambah kolom `_Triage`.

**core/processor.py**: simpan `mitre_enriched_raw` (data MENTAH per-
insiden, termasuk _Triage) ke report dict - supaya app.py bisa HITUNG
ULANG chart secara DINAMIS kalau user toggle filter, BUKAN generate ulang.

**app.py (Executive Summary)**: checkbox "🎯 Filter ke True Positive saja"
(default ON, dikonfirmasi user) di atas section Anchor Kill Chain. SEMUA
output turunan (kc_raw, mitre_tech_live, mitre_tac_live, drilldown_map,
top_stage, insights) di-RECOMPUTE LIVE dari `mitre_df` (hasil filter)
pakai fungsi core.mitre_killchain yang di-import langsung - bukan baca
report dict statis lagi untuk section ini.

**Field `Description`** - berisi dump key:value mentah dari Splunk, TAPI
field yang muncul BEDA-BEDA tergantung jenis alert (AWS CloudTrail/WAF/
Windows Event) - TIDAK ada skema tetap, TIDAK bisa gantikan 'Summary'
untuk Rule Name mapping. `parse_description_kv()` - parser GENERIK
(regex key:value dipisah 2+ spasi, handle value yang sendiri mengandung
colon seperti timestamp '00:20:00' - BUG ditemukan & diperbaiki saat
testing, value awalnya salah terpecah). Ditampilkan di Threat Profiling
sebagai viewer per-tiket (pilih Ticket Number, lihat key-value hasil
parse + teks mentah).

**2 BUG DITEMUKAN & DIPERBAIKI saat testing (di luar scope Triage/
Description, WAJIB diperbaiki karena bikin pipeline crash total):**
1. Kolom `Priority` di 1 baris data asli berisi `"[Exploitation, Actions
   on Objectives]"` (nilai KillChain yang salah kolom/nyasar) - bikin
   `.min()` TypeError (int vs str). Fix: `utils/helpers.py` koersi
   `Priority` ke numerik via `pd.to_numeric(errors='coerce')` - nilai
   tak valid jadi NaN (sudah ditangani Validator sebagai "Missing
   Priority"), bukan crash.
2. Kolom `Cause Code` TIDAK ADA SAMA SEKALI di format terbaru - bikin
   KeyError di `build_outcome_insight()`. Fix: guard di awal fungsi,
   kolom diisi NaN kalau tidak ada - semua baris otomatis masuk 'Belum
   Diklasifikasi' (konsisten, bukan crash).

Diuji: toggle TP/FP terbukti BENAR-BENAR mengubah hasil (Kill Chain TP-
saja: 77 insiden vs semua: 228 insiden, angka per-stage berbeda jauh).
Parser Description diverifikasi ke seluruh 228 baris - 0 key mencurigakan
tersisa setelah 2 kali perbaikan (timestamp colon + key numerik artefak).
Backward compatibility: file lama (tanpa Triage/Description/Cause Code)
tetap berhasil generate tanpa error.

## 106. BARU: Modul ke-5 "Cybersecurity Monthly Report" (Phase 1: IPS)

Folder baru `cybersec_report/` (self-contained). `app.py`: card ke-5 + gate `CYBERSEC` (1 baris lama berubah: kolom 4->5,
21 baris ditambah). Pipeline: ingestion (auto-delimiter) -> schema detection (alias persis, tidak menebak) -> normalisasi
canonical -> validasi PASS/WARNING/FAIL -> analytics (SUM(count), penyebut per konteks, Top5+Others) -> reputasi
VT/AbuseIPDB (cache SQLite, rate limit, retry, circuit breaker, private IP skip) -> Internal Normalized Threat Score ->
narasi rule-based -> PPT berbasis template deck contoh (background diekstrak) -> verifikasi PPT dibaca balik -> 5 file output.
Data uji `IPS_Sep_2026.csv`: 547 record, 939 event; Raw == Analytics == PPT == 939; 40 test otomatis lolos.
Bug ditemukan saat testing & diperbaiki: (1) mapping manual tidak membuka blokir validasi (missing_required tidak dihitung
ulang), (2) seleksi IP reputasi melewatkan source IP terbesar (severity Low). Penyimpangan: pie 2D (python-pptx tak bisa
3D), config JSON bukan YAML, tanpa dependensi baru.

## 107. Cybersecurity Monthly Report: dashboard di aplikasi, failover reputasi, lokasi data, perbaikan download

Hanya folder `cybersec_report/` yang berubah (`app.py` dan modul lain tidak disentuh).
1. **Download PPT/JSON "Canceled"**: tombol unduh kini memakai `on_click="ignore"` (Streamlit >= 1.43; klik tidak memicu rerun)
   dan byte file ditahan di `session_state` agar stabil antar-rerun. Streamlit lebih lama: byte stabil saja. File juga selalu
   ada di `database/cybersec_report/output/`. Tidak dapat direproduksi di sandbox, mohon dikonfirmasi di browser.
2. **API key**: lokasi utama `database/cybersec_report/.env`; bisa diisi/disimpan dari sidebar (ter-mask). `.env` kosong tidak menutupi key di file lain.
3. **Failover reputasi**: satu provider sampai kuota habis lalu pindah (VT -> AbuseIPDB); cache lintas-provider; status kuota persisten; `strategy: all` tersedia.
4. **Dashboard IPS** (tab pertama): live dari upload atau dari snapshot periode tersimpan; export PPT/Excel jadi opsional. Tab Preview digantikan Dashboard.
5. **Data pindah ke `database/cybersec_report/`** (snapshot, cache, output, device mapping, .env). Data lama di `cybersec_report/cache|output` tidak dimigrasi otomatis.
Test: 60 lolos (naik dari 40): failover, kuota, key, snapshot roundtrip, smoke UI dengan stub Streamlit.
Penyimpangan/batasan: Streamlit/Plotly tidak terpasang di sandbox, UI hanya diuji dengan stub; panggilan VT/AbuseIPDB nyata belum pernah diuji.

## 108. Dashboard IPS didesain ulang (grafik lebih rapi)

Hanya `cybersec_report/dashboard_view.py` (ditulis ulang) dan `ui_components.py` (baru). Tab di dalam dashboard: Overview | Attack Analysis |
Source IP & Reputation | Insights | Data Tables. Kartu KPI, donut severity (legenda + deskripsi), bar horizontal Top-5 + Others untuk
Source Country, Destination, Top source IP, dan Attack Name per severity (nama signature panjang tidak terpotong; angka dan % selalu tertulis).
Tabel gaya PPT dipindah ke tab Data Tables. Grafik HTML murni (tanpa Plotly), warna netral agar terbaca di tema terang dan gelap.
Skala severity: merah gelap -> terang untuk Critical -> Medium, abu-abu untuk Low (volume terbesar tetapi paling tidak mendesak).
Test: 64 lolos.

## 109. Dashboard: hasil reputasi terlihat, penjelasan cakupan IP, dan data action

Pertanyaan user: (1) hasil Reputation Check tidak terlihat di dashboard, (2) 461 IP publik tetapi hanya 54 dicek, (3) data blocked vs detected ada di mana.
1. **Overview** kini punya blok *Threat Intelligence*: jumlah IP dicek vs IP publik + % event yang terwakili, jumlah per risk level, IP di atas band Low
   beserta bukti per provider (mis. "VirusTotal: 12 malicious + 1 suspicious dari 103 engine"), interpretasi, AS/ISP, dan penjelasan cara skor dihitung
   (bobot, saturasi, band dibaca dari `scoring.json`). Kolom baru profil IP: VT Suspicious/Engines, AbuseIPDB Reports, AS / ISP, Interpretation, Evidence.
2. **Akan dicek 54**: dibatasi *Maks. IP yang dicek* di sidebar (default 50 per section, 0 = semua). Tab 3 kini menjelaskan angka itu per section
   beserta cakupan event dan catatan kuota provider. Menaikkan batas aman karena IP lama diambil dari cache.
3. **Action**: kartu *Tindakan perangkat* di Overview menampilkan event per action untuk SEMUA baris file (dihitung vs tidak dihitung).
   Pada IPS_Sep_2026.csv semua 547 record berstatus `dropped`, sehingga tidak ada event detected-only yang dikeluarkan.
Snapshot lama tetap bisa dibuka (kolom baru opsional). Test: 70 lolos.


## 110. Hapus file upload, snapshot per hostname, Compare, dan menu sumber lain aktif

1. **Hapus file**: tombol "🗑️ Hapus file ini" di sidebar mereset sesi upload (uploader diberi key baru). Cache reputasi (`database/cybersec_report/cache/reputation.sqlite`),
   snapshot, device_environment, dan `.env` TIDAK disentuh. Setelah upload berikutnya, IP yang sudah ada di cache otomatis terisi (`apply_cached_reputation`) tanpa token.
   Umur cache diatur di sidebar (default 168 jam).
2. **Per hostname**: satu file berisi banyak hostname dipisah otomatis (tidak perlu upload satu-satu). Tab Upload menampilkan daftar hostname + pilihan pemisahan
   (per hostname / gabungan / per environment). Environment hanya label opsional. Snapshot bulanan satu per hostname, mis. `P1FWX0209-IPS-September-2026`.
3. **Tab 🔀 Compare**: bandingkan dua snapshot IPS apa pun (bulan berbeda; hostname sama atau berbeda): KPI, ringkasan otomatis, severity, attack, source IP persisten/baru/hilang, negara.
4. **Menu sumber lain aktif**: Akamai, DLP, EDR, CSPM, Vulnerability, SIEM, Proxy, Email, SAST/DAST, Executive Summary tampil sebagai halaman "menunggu data":
   daftar yang akan dilaporkan, perkiraan data mentah yang diminta, dan slide contoh dari deck referensi (gambar contoh, bukan data). Tidak ada angka dikarang.
Test: 81 lolos (UI diuji dengan stub Streamlit, bukan browser).

## 111. Hapus snapshot dashboard tersimpan

Di tab Dashboard, saat memilih periode tersimpan muncul expander "🗑️ Hapus dashboard tersimpan ini" (wajib centang konfirmasi). `snapshot.delete_snapshot` hanya
menghapus file .json di folder snapshots (path lain ditolak); cache reputasi tidak disentuh. Test: 83 lolos.

## 112. BARU: Modul ke-6 "SOC Incident Report" (laporan insiden bulanan, sadar perpindahan state machine)

Latar: export Ivanti September 2026 (980 tiket) memuat dua state machine. Hasil inspeksi data (bukan asumsi): tiket skema baru pertama = 2881668
(17 Sep 21:02:27), tiket skema lama terakhir = 2881547 (18:30:47). Sejak cutover Sub_Issue & Product Type kosong 100%, Cause Code praktis kosong,
Customer berisi akun sistem ("Alert Splunk") pada 79% tiket, Resolved Date Time hanya terisi 43%, dan komposisi prioritas berbalik (P1 70% -> 1%, P3 8% -> 98%).
Menjumlahkan/membandingkan langsung kedua era menyesatkan, sehingga modul memisahkan per era.

**Modul baru `soc_incident/`** (self-contained, tidak mengimpor modul lain; `app.py` hanya +kartu homepage & +blok gate, 1 baris `st.columns(5)->6`):
- `loader.py`: baca XLSX/CSV, mapping kolom EXACT (tidak menebak), kolom wajib hilang -> error jelas, duplikat tiket dibuang + catatan.
- `processor.py`: deteksi cutover otomatis (awal "ekor" tiket yang Product Type & Sub_Issue kosong, min. 20 tiket & 5%), override manual / satu era,
  statistik per era (laju per hari memakai lama era masing-masing), SLA respons dari flag Ivanti (batas tersirat ditampilkan sebagai pengamatan),
  kelengkapan resolusi, mingguan Minggu-Sabtu, per jam, owner, prioritas, perubahan skema, insight hedged, Excel opsional (tanpa nama customer/email).
- `snapshot.py`: snapshot bulanan JSON (angka agregat saja) di `database/soc_incident/snapshots/`, hapus snapshot aman, compare dua bulan
  (basis "era terbaru" disarankan agar Oktober dibandingkan dengan era baru September).
- `dashboard.py` + `ui.py`: 6 tab (Ringkasan Eksekutif, SLA & State Machine, Beban Kerja & Pola, Skema & Kualitas Data, Bandingkan Bulan, Simpan & Export), tombol hapus file upload.
Batasan jujur: MTTC (Active->Contained) tidak bisa dihitung (tidak ada timestamp Contained); Created->Resolved bukan MTRV; makna Cause Code tidak diinterpretasikan;
asumsi "Customer berisi 'splunk' = tiket otomatis" ada di `soc_incident/config.json`. UI diuji dengan stub Streamlit (bukan browser). Test: 30 test baru, total 113 lolos.

## 113. Laporan insiden dipindah ke dalam menu "SOC Report" (kartu ke-6 dihapus)

Koreksi desain atas permintaan user: laporan insiden adalah bagian dari SOC Report, bukan modul terpisah di homepage.
- `app.py`: homepage kembali 5 kartu (nol baris existing diubah/dihapus dibanding sebelum modul insiden). Di dalam SOC Report, sidebar punya pilihan
  "Jenis laporan SOC": *Laporan Bulanan (Splunk + Ivanti)* (default, kode existing tidak disentuh) atau *Insiden Bulanan Ivanti (per state machine)*.
- Kode `soc_incident/` tidak berubah selain judul. Diuji lewat stub: kedua pilihan tampil benar dan pilihan default tetap masuk ke alur SOC lama.
- Catatan operasional: gunakan patch kode-saja; jangan menimpa folder dengan zip penuh (berisi input/ contoh dan, pada versi MERGED, database/ dari backup 2 Oktober).


## 114. Cybersecurity Monthly Report: menu Akamai aktif (WAF / BOT / Bad Reputation / DoS)

- `cybersec_report/sources/akamai.py` (baru): parser export bulanan tim Akamai (.xlsx; sheet WAF Attack, BOT Attack, Bad Reputation, DOS). Tabel dikenali dari header "Total Hits"
  (layout berdampingan maupun bertumpuk), karakter zero-width dibersihkan, kolom "By %" dihitung ulang (nilai dari file tidak dipakai). Validasi: jumlah item = baris Total tiap tabel,
  total antar tabel sejajar, sheet hilang = peringatan (bukan crash), angka berbentuk teks ditolak (tidak ditebak). Insight hedged (dominasi kategori, konsentrasi host, negara dominan,
  host muncul di banyak kategori, nama host serupa beda domain, 'Others' besar) + batasan data. Export Excel ringkas.
- `cybersec_report/sources/akamai_store.py` (baru): snapshot bulanan JSON di `database/cybersec_report/snapshots/akamai/` (terpisah dari snapshot IPS), hapus aman, compare antar bulan
  (label di luar top 5 salah satu bulan dipisah, tidak dianggap 0).
- `cybersec_report/akamai_view.py` (baru): pola SAMA dengan IPS. Sidebar: pilih sumber Akamai + UPLOAD AKAMAI (uploader IPS tetap, file tidak hilang saat pindah sumber). Tab: Dashboard, Compare, 1 · Upload & Mapping, 2 · Validation, 3 · Generate / Export; di dalam Dashboard: Overview, Attack Analysis, Insights, Data Tables (kartu, donut, bar, tabel gaya slide). Bulan laporan wajib dikonfirmasi (file tidak memuat tanggal).
- `cybersec_report/dashboard.py`: pilihan sumber "akamai" memanggil halaman baru (IPS tidak berubah). `config/report_structure.json`: akamai implemented/enabled.
- Temuan pada file September 2026: tabel Negara sheet WAF Attack berjumlah 22.875 sedangkan baris Total 22.785 (selisih 90); ditandai sebagai peringatan, tidak dikoreksi otomatis.
- Test: `tests/test_akamai.py` (16 test, data sintetis); stub UI sekarang menghormati `disabled=` pada tombol. Stub UI mendukung uploader bernama. Total cybersec_report 101 test lolos.
- Belum ada: slide PowerPoint Akamai (dashboard + Excel saja).

## 115. SOC Report: kolom MITRE/KillChain export Ivanti Sept 2026 terbaca ("IncidentMitre"/"IncidentKillChain")

- Penyebab: export baru memakai header `IncidentMitre` dan `IncidentKillChain` (tanpa spasi), sedangkan kode hanya mengenali `Incident MITRE` / `Incident KillChain`; kolom dianggap tidak ada, sehingga Kill Chain/MITRE kosong.
- `utils/helpers.py` `normalize_incident_columns`: alias tanpa-spasi/underscore/huruf-besar-kecil untuk `Incident MITRE`, `Incident KillChain`, `Triage` (hanya tiga nama ini; kolom lain tidak ditebak; kolom kanonik yang sudah ada tidak ditimpa).
- `core/mitre_killchain.py`: nama resmi MITRE ditambahkan untuk kode baru di data Sept (T1059, T1071.001, T1090, T1201, T1580, T1583.004, T1089, TA0011).
- Test baru: `core/tests/test_incident_columns.py` (4 test, data sintetis). Diuji juga pada `Raw_Data_September_SOC_2026.xlsx` (987 tiket): 457 tiket ber-Triage (176 TP, 281 FP), 351 tiket punya stage Kill Chain, 439 punya MITRE.
- Belum diubah (menunggu keputusan user): stage "Command & Control" (14 tiket) masih dilaporkan sebagai nilai bermasalah di Data Quality karena bukan salah satu 7 stage yang terkonfirmasi sebelumnya.
