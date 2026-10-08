"""
IOC - VirusTotal Checker
=========================================================
Cek reputasi IP ke VirusTotal API v3. BUTUH API KEY (gratis, daftar di
virustotal.com -> Profile -> API Key).

Rate limit tier gratis: 4 request/menit, 500/hari - kode ini otomatis
throttle (sleep antar request) supaya tidak kena limit, TAPI ini juga
berarti untuk ratusan IP bisa makan waktu lama (mis. 200 IP / 4 per menit
= ~50 menit). Disarankan test dulu dengan sedikit IP.

CATATAN JUJUR: endpoint & response format di bawah ini sesuai dokumentasi
resmi VirusTotal API v3 per pengetahuan saya, TAPI belum bisa saya test
langsung dari sandbox saya (tidak ada akses internet & tidak punya API
key). Format response VT jarang berubah, tapi tetap disarankan dicoba
dengan 1-2 IP dulu sebelum upload massal.
"""

import time

import pandas as pd
import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
RATE_LIMIT_DELAY_SEC = 16  # 4 request/menit = 1 tiap 15 detik, dibulatkan ke atas jaga-jaga


def check_ip_virustotal(ip, api_key):
    """1 IP, return dict hasil. Tidak raise exception - error dikembalikan
    sebagai field 'VT_Error' supaya proses batch tidak berhenti di 1 IP."""
    try:
        resp = requests.get(
            f"{VT_BASE_URL}{ip}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 401:
            return {"IP": ip, "VT_Error": "API key tidak valid (401 Unauthorized)"}
        if resp.status_code == 429:
            return {"IP": ip, "VT_Error": "Rate limit VirusTotal tercapai (429) - coba lagi nanti"}
        if resp.status_code == 404:
            return {"IP": ip, "VT_Malicious": 0, "VT_Suspicious": 0, "VT_Harmless": 0,
                    "VT_Undetected": 0, "VT_Error": None}
        resp.raise_for_status()

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "IP": ip,
            "VT_Malicious": stats.get("malicious", 0),
            "VT_Suspicious": stats.get("suspicious", 0),
            "VT_Harmless": stats.get("harmless", 0),
            "VT_Undetected": stats.get("undetected", 0),
            "VT_Error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"IP": ip, "VT_Error": f"Network error: {e}"}
    except (KeyError, ValueError) as e:
        return {"IP": ip, "VT_Error": f"Response tidak sesuai format yang diharapkan: {e}"}


def check_ips_virustotal(ip_list, api_key, progress_callback=None):
    """Cek banyak IP dengan throttle otomatis supaya tidak kena rate limit.
    progress_callback(i, total): dipanggil tiap 1 IP selesai - buat update
    progress bar di Streamlit."""
    if not api_key or not api_key.strip():
        return pd.DataFrame([{"IP": ip, "VT_Error": "API key belum diisi - VirusTotal di-skip"} for ip in ip_list])

    results = []
    for i, ip in enumerate(ip_list):
        results.append(check_ip_virustotal(ip, api_key))
        if progress_callback:
            progress_callback(i + 1, len(ip_list))
        if i < len(ip_list) - 1:
            time.sleep(RATE_LIMIT_DELAY_SEC)
    return pd.DataFrame(results)
