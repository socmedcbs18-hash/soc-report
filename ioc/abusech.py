"""
IOC - ThreatFox & URLhaus (abuse.ch)
=========================================================
Ditemukan dari README `iocinfo` & `ioc-threat-intel` - TAPI ada
KETIDAKSAMAAN info antar sumber: README ThreatFeed bilang ThreatFox
"None (tanpa API key)", sedangkan README iocinfo (lebih detail & sepertinya
lebih baru) bilang ThreatFox & URLhaus masuk kategori "Free API key
required" (auth.abuse.ch). Saya ikuti yang LEBIH KETAT (anggap butuh Auth-
Key) - lebih aman salah mengharuskan key daripada menjanjikan "gratis
tanpa key" padahal ternyata sekarang butuh.

1 Auth-Key abuse.ch (gratis, daftar di auth.abuse.ch) berlaku untuk
KEDUANYA (ThreatFox & URLhaus) - sesuai catatan README iocinfo.

CATATAN JUJUR: belum bisa saya test langsung (sandbox tidak ada akses
internet). Endpoint sesuai dokumentasi resmi ThreatFox API v1 & URLhaus
API v1 per pengetahuan saya.
"""

import time

import pandas as pd
import requests

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
DELAY_SEC = 1


def check_ip_threatfox(ip, auth_key):
    if not auth_key or not auth_key.strip():
        return {"IP": ip, "ThreatFox_Error": "Auth-Key belum diisi - ThreatFox di-skip"}
    try:
        resp = requests.post(
            THREATFOX_URL,
            json={"query": "search_ioc", "search_term": ip},
            headers={"Auth-Key": auth_key},
            timeout=15,
        )
        resp.raise_for_status()
        d = resp.json()
        if d.get("query_status") != "ok":
            return {"IP": ip, "ThreatFox_Malware": "", "ThreatFox_Confidence": None, "ThreatFox_Error": None}
        rows = d.get("data", [])
        malware = ", ".join(sorted(set(r.get("malware_printable", "") for r in rows if r.get("malware_printable"))))
        max_conf = max((r.get("confidence_level", 0) for r in rows), default=0)
        return {"IP": ip, "ThreatFox_Malware": malware, "ThreatFox_Confidence": max_conf, "ThreatFox_Error": None}
    except requests.exceptions.RequestException as e:
        return {"IP": ip, "ThreatFox_Error": f"Network error: {e}"}
    except (KeyError, ValueError) as e:
        return {"IP": ip, "ThreatFox_Error": f"Response tidak sesuai format: {e}"}


def check_ip_urlhaus(ip, auth_key):
    if not auth_key or not auth_key.strip():
        return {"IP": ip, "URLhaus_Error": "Auth-Key belum diisi - URLhaus di-skip"}
    try:
        resp = requests.post(
            URLHAUS_URL, data={"host": ip}, headers={"Auth-Key": auth_key}, timeout=15,
        )
        resp.raise_for_status()
        d = resp.json()
        if d.get("query_status") != "ok":
            return {"IP": ip, "URLhaus_URL_Count": 0, "URLhaus_Error": None}
        urls = d.get("urls", [])
        return {"IP": ip, "URLhaus_URL_Count": len(urls), "URLhaus_Error": None}
    except requests.exceptions.RequestException as e:
        return {"IP": ip, "URLhaus_Error": f"Network error: {e}"}
    except (KeyError, ValueError) as e:
        return {"IP": ip, "URLhaus_Error": f"Response tidak sesuai format: {e}"}


def check_ips_abusech(ip_list, auth_key, progress_callback=None):
    """Cek ThreatFox + URLhaus sekaligus (1 Auth-Key untuk keduanya)."""
    if not auth_key or not auth_key.strip():
        rows = [{"IP": ip, "ThreatFox_Error": "Auth-Key belum diisi - di-skip",
                 "URLhaus_Error": "Auth-Key belum diisi - di-skip"} for ip in ip_list]
        return pd.DataFrame(rows)

    results = []
    for i, ip in enumerate(ip_list):
        tf = check_ip_threatfox(ip, auth_key)
        uh = check_ip_urlhaus(ip, auth_key)
        merged = {**tf, **{k: v for k, v in uh.items() if k != "IP"}}
        results.append(merged)
        if progress_callback:
            progress_callback(i + 1, len(ip_list))
        if i < len(ip_list) - 1:
            time.sleep(DELAY_SEC)
    return pd.DataFrame(results)
