"""
IOC - AbuseIPDB Checker
=========================================================
Cek reputasi IP ke AbuseIPDB API v2. BUTUH API KEY (gratis, daftar di
abuseipdb.com -> Account -> API).

Rate limit tier gratis: 1000 request/hari (tidak ada limit per-menit resmi,
tapi tetap diberi delay kecil supaya sopan ke server mereka).

CATATAN JUJUR: endpoint & response format sesuai dokumentasi resmi
AbuseIPDB API v2 per pengetahuan saya, TAPI belum bisa saya test langsung
dari sandbox saya (tidak ada akses internet & tidak punya API key).
Disarankan dicoba dengan 1-2 IP dulu sebelum upload massal.
"""

import time

import pandas as pd
import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DELAY_SEC = 1  # jaga-jaga sopan ke API, tidak ada limit ketat per-menit tapi tetap dijeda


def check_ip_abuseipdb(ip, api_key, max_age_days=90):
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=15,
        )
        if resp.status_code == 401:
            return {"IP": ip, "AbuseIPDB_Error": "API key tidak valid (401 Unauthorized)"}
        if resp.status_code == 429:
            return {"IP": ip, "AbuseIPDB_Error": "Rate limit AbuseIPDB tercapai (429) - coba lagi nanti"}
        resp.raise_for_status()

        d = resp.json()["data"]
        return {
            "IP": ip,
            "AbuseIPDB_Confidence_%": d.get("abuseConfidenceScore", 0),
            "AbuseIPDB_Total_Reports": d.get("totalReports", 0),
            "AbuseIPDB_Country": d.get("countryCode"),
            "AbuseIPDB_ISP": d.get("isp"),
            "AbuseIPDB_Error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"IP": ip, "AbuseIPDB_Error": f"Network error: {e}"}
    except (KeyError, ValueError) as e:
        return {"IP": ip, "AbuseIPDB_Error": f"Response tidak sesuai format yang diharapkan: {e}"}


def check_ips_abuseipdb(ip_list, api_key, progress_callback=None):
    if not api_key or not api_key.strip():
        return pd.DataFrame([{"IP": ip, "AbuseIPDB_Error": "API key belum diisi - AbuseIPDB di-skip"} for ip in ip_list])

    results = []
    for i, ip in enumerate(ip_list):
        results.append(check_ip_abuseipdb(ip, api_key))
        if progress_callback:
            progress_callback(i + 1, len(ip_list))
        if i < len(ip_list) - 1:
            time.sleep(DELAY_SEC)
    return pd.DataFrame(results)
