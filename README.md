# SOC Report Generator (ALTO)

Dashboard Streamlit multi-modul: SOC Report (Splunk + Ivanti, termasuk Insiden Bulanan per state machine), Cybersecurity Monthly Report (IPS, Akamai), Cynet Agent Compliance, SLA SR Security Operations, IOC.

## Menjalankan
```
pip install -r requirements.txt
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```
Jalankan dari folder repo (sebagian modul membaca `database/` relatif terhadap folder kerja).

## Data TIDAK ada di repo
`database/`, `input/`, `output/`, dan `.env` (API key VirusTotal/AbuseIPDB) di-ignore oleh git. Jangan dihapus saat update:
update server cukup `git pull`. Contoh variabel .env: `cybersec_report/.env.example`.
`input/master/` (Master_Rules_Splunk.xlsx, Domain_Mapping_Splunk.xlsx) perlu disalin manual ke server.

## Catatan
Riwayat perubahan: `CHANGELOG_FIX.md`. Panduan pemakaian: `PANDUAN_PENGGUNAAN.md`.
Test: `python -m unittest discover -s cybersec_report/tests -t .` (juga `soc_incident/tests`).
