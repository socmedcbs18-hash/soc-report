# Panduan Penggunaan — SOC Report Generator

Ditulis untuk dijalankan di laptop/PC lokal (bukan di web). Anggap Anda belum
pernah pakai Python — semua langkah ditulis eksplisit.

---

## 0. Instalasi sekali di awal (one-time setup)

1. Install **Python 3.10+** dari https://www.python.org/downloads/ (saat instalasi,
   centang "Add Python to PATH").
2. Extract folder `SOC_Report_Generator` ke lokasi tetap, misal `D:\SOC_Report_Generator`.
3. Buka Command Prompt / Terminal di folder tersebut, lalu jalankan:
   ```
   pip install -r requirements.txt
   ```
   Ini hanya perlu dilakukan sekali (kecuali pindah laptop/reinstall Python).

---

## 1. Upload data mingguan (rutin tiap minggu)

**Lokasi:** `input/weekly/`

**Langkah:**
1. Buat folder baru dengan format `wXX` (XX = nomor minggu ISO, contoh `w30`).
   Kalau tidak yakin nomor minggunya, cek di kalender atau googling "week number 2026".
2. Masukkan **2 file** ke dalam folder itu, dengan nama **wajib diawali**:
   - `alert_splunk...xlsx` → hasil export alert Splunk minggu tersebut
   - `insiden_ivanti...xlsx` → hasil export tiket Ivanti minggu tersebut

   Contoh struktur:
   ```
   input/weekly/w30/
       alert_splunk_19jul_25jul.xlsx
       insiden_ivanti_19jul_25jul.xlsx
   ```
   Nama file setelah prefix bebas (tanggal, dst) — yang penting **awalan**nya persis
   `alert_splunk` dan `insiden_ivanti`, dan formatnya `.xlsx`.

3. **Format kolom wajib sama** dengan file contoh yang sudah ada (jangan ubah nama
   kolom/urutan). Kalau Splunk/Ivanti mengubah format export mereka, kabari saya dulu
   sebelum dipakai — kolom yang berubah nama akan bikin script error.

**Untuk report bulanan:** tidak perlu upload apa-apa secara terpisah — script otomatis
menggabungkan semua folder `wXX` yang tanggalnya masuk ke bulan tersebut. Jadi pastikan
semua folder minggu di bulan itu sudah terisi sebelum generate laporan bulanan.

**Format file**: `.xlsx` atau `.csv` — bebas pilih, kecuali file **Alert NonSplunk** yang WAJIB `.xlsx` (karena butuh 3 sheet sekaligus: Akamai/CSPM/Microsoft Defender — CSV cuma bisa 1 sheet). Kolom di dalam file tetap harus sama persis (nama kolom tidak otomatis disesuaikan hanya karena ganti format).
- `alert_nonsplunk...xlsx` — alert dari device di luar Splunk (lihat bagian sebelumnya)
- `task_soc...xlsx` — task pengecekan dari tim lain ke SOC TANPA insiden ter-assign resmi (kolom wajib: `Task`, `Subject`, `Status`, `Owner`, `Created On`; opsional: `Completed On`, `Requestor_Team`)

---

## 2. Update Master Rules Splunk (kalau ada rule baru/berubah)

**Lokasi:** `input/master/Master_Rules_Splunk.xlsx`

**Kapan perlu update:**
- Ada rule Splunk baru yang dibuat/diaktifkan
- Ada rule yang di-disable/dihapus
- Ada migrasi environment (seperti ESV2→ESV3 kemarin)

**Cara update:**
1. Buka file `Master_Rules_Splunk.xlsx`.
2. Tambah baris baru di bagian bawah dengan kolom: `Rule_ID` (buat ID baru urut,
   misal `SPLV2_00479`), `Rule_Names` (nama persis dari Splunk), `Rule_Status`
   (`Enabled`/`Disabled`).
3. **Jangan hapus baris rule lama** meskipun sudah di-disable/pensiun — biarkan statusnya
   diubah jadi `Disabled` saja. Ini penting supaya laporan historis (minggu-minggu
   sebelumnya yang masih referensi rule itu) tetap valid.
4. Simpan file (tetap `.xlsx`, jangan ganti nama kolom).

**Untuk Domain Mapping** (`input/master/Domain_Mapping_Splunk.xlsx`, sheet
`Keyword_Mapping`): kalau ada kategori/domain baru yang belum kena mapping otomatis
(muncul sebagai "Others" di sheet Domain), tambah baris baru: `Priority` (angka,
makin kecil makin diprioritaskan kalau ada keyword yang tumpang tindih), `Keyword`
(kata kunci yang dicari di nama rule), `Security_Domain`, `Security_Sub_Domain`.

---

## 3. Menjalankan script

### Opsi A — Streamlit (disarankan, upload & lihat hasil langsung di browser)

1. Install sekali di awal (setelah `pip install -r requirements.txt` dari langkah 0,
   `streamlit` sudah otomatis ikut terinstall).
2. Buka Command Prompt / Terminal, **masuk ke folder project dulu**:
   ```
   cd D:\SOC_Report_Generator
   ```
   (Kalau dijalankan dari folder lain seperti `C:\Windows\System32`, akan muncul
   error `File does not exist: app.py` — karena `app.py` memang cuma ada di
   folder project ini, bukan di semua folder.)
3. Jalankan:
   ```
   streamlit run app.py
   ```
4. Browser otomatis kebuka (`localhost:8501`). Di sidebar kiri:
   - Pilih mode **Weekly** atau **Monthly**
   - Weekly: upload langsung file Alert Splunk, Insiden Ivanti, (opsional) Alert
     NonSplunk — atau pilih dari folder `input/weekly/` yang sudah ada
   - Monthly: pilih tahun & bulan
   - Klik **Generate Report**
5. Hasilnya langsung tampil: KPI card, insight hipotesis, chart interaktif, tabel
   detail (bisa di-expand), dan tombol **Download** untuk ambil file Excel-nya
   (isinya identik dengan hasil `python main.py`, lengkap dengan chart native Excel
   untuk dilampirkan/di-forward).
6. Untuk screenshot ke BoD: tinggal screenshot langsung dari tampilan browser ini
   (chart-nya sudah dalam bentuk visual, tidak perlu buka Excel dulu).

### Opsi B — CLI (`python main.py`)

1. Buka Command Prompt / Terminal, masuk ke folder `SOC_Report_Generator`:
   ```
   cd D:\SOC_Report_Generator
   ```
2. Jalankan:
   ```
   python main.py
   ```
3. Script akan tanya:
   ```
   Pilih mode [1] Weekly  [2] Monthly (default 1):
   ```
   - Ketik `1` lalu Enter → lanjut pilih minggu mana yang mau diproses.
   - Ketik `2` lalu Enter → lanjut diminta tahun & bulan (contoh: `2026` lalu `7`
     untuk Juli 2026).
4. Tunggu proses selesai — akan muncul log tiap tahap (normalisasi, validasi,
   processing, export).
5. Hasil laporan ada di folder **`output/`**, nama file otomatis
   `SOC_Report_w30.xlsx` (mingguan) atau `SOC_Report_2026-07.xlsx` (bulanan).

**Kalau muncul error:** screenshot pesan errornya dan kirim ke saya — biasanya
penyebabnya format kolom di file input yang berubah dari sumbernya (Splunk/Ivanti
export).

---

## 4. Ringkasan alur mingguan rutin

```
Setiap Sabtu/Minggu:
  1. Export alert Splunk & tiket Ivanti minggu berjalan
  2. Buat folder input/weekly/wXX baru, taruh kedua file di situ
  3. python main.py -> pilih Weekly -> pilih minggu itu
  4. Cek output/SOC_Report_wXX.xlsx - review sheet Hypothesis Insight dulu
     untuk highlight utama, baru dalami sheet lain kalau perlu
```

---

## 5. Rencana tahap berikutnya (belum dikerjakan)

Merujuk ke `IT_Infra_Weekly_Report_2025.pptx` yang jadi acuan BoD: format PPT
mereka pakai pola "Overall Week vs Current Week" per kategori dengan chart, plus
breakdown per tim. Ini bisa dibuatkan modul baru (`core/pptx_writer.py`) yang
otomatis generate slide dari `report` yang sudah dihasilkan `SOCProcessor` —
bisa disambungkan juga sebagai tombol "Generate PPT" di app Streamlit. Beri tahu
saya kalau mau ini dikerjakan sekarang.

(Streamlit sudah selesai dikerjakan — lihat bagian 3 Opsi A di atas.)
