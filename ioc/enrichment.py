"""
IOC - Enrichment Gratis Tanpa API Key
=========================================================
2 sumber tambahan yang ditemukan dari README iocinfo & ThreatFeed - SAMA
SEKALI tidak butuh API key, langsung jalan begitu ada akses internet:

1. Shodan InternetDB (https://internetdb.shodan.io/{ip}) - open ports,
   CVE yang terdeteksi di IP tersebut. Beda jenis sinyal dari yang lain -
   ini soal EXPOSURE (device kebuka ke internet dengan port/vuln apa),
   bukan soal "sudah pernah dilaporkan jahat".
2. ip-api.com (http://ip-api.com/json/{ip}) - geolokasi, ASN, ISP, flag
   proxy/hosting. Ini KONTEKS, bukan indikator jahat/tidak - membantu
   analyst menilai (mis. IP dari negara asing + hosting provider = lebih
   perlu dicurigai daripada IP kantor sendiri).

CATATAN JUJUR: endpoint ini terkonfirmasi PUBLIK & GRATIS dari 2 README
berbeda (ThreatFeed & iocinfo) yang independen satu sama lain - cukup
kuat sebagai referensi, TAPI tetap belum saya test langsung (sandbox saya
tidak ada akses internet).
"""

import pandas as pd
import requests


def check_ip_shodan_internetdb(ip):
    """Return dict - kalau IP tidak ada di database Shodan (404), itu
    NORMAL (kebanyakan IP tidak ada di Shodan), bukan error."""
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code == 404:
            return {"IP": ip, "Shodan_Ports": "", "Shodan_CVEs": "", "Shodan_Tags": "", "Shodan_Error": None}
        resp.raise_for_status()
        d = resp.json()
        return {
            "IP": ip,
            "Shodan_Ports": ", ".join(str(p) for p in d.get("ports", [])),
            "Shodan_CVEs": ", ".join(d.get("vulns", [])),
            "Shodan_Tags": ", ".join(d.get("tags", [])),
            "Shodan_Error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"IP": ip, "Shodan_Error": f"Network error: {e}"}
    except ValueError as e:
        return {"IP": ip, "Shodan_Error": f"Response tidak sesuai format: {e}"}


def check_ip_geolocation(ip):
    """ip-api.com - geolokasi & konteks (BUKAN indikator jahat/bersih,
    murni informasi tambahan buat analyst)."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        resp.raise_for_status()
        d = resp.json()
        if d.get("status") != "success":
            return {"IP": ip, "Geo_Error": d.get("message", "Lookup gagal")}
        return {
            "IP": ip,
            "Geo_Country": d.get("country"),
            "Geo_City": d.get("city"),
            "Geo_ISP": d.get("isp"),
            "Geo_Org": d.get("org"),
            "Geo_Is_Hosting": d.get("hosting", False),
            "Geo_Is_Proxy": d.get("proxy", False),
            "Geo_Error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"IP": ip, "Geo_Error": f"Network error: {e}"}
    except ValueError as e:
        return {"IP": ip, "Geo_Error": f"Response tidak sesuai format: {e}"}


def check_ips_enrichment(ip_list, progress_callback=None):
    """Jalankan Shodan InternetDB + ip-api.com sekaligus untuk semua IP -
    keduanya gratis tanpa key, jadi selalu dijalankan (tidak seperti VT/
    AbuseIPDB yang opsional). Delay kecil supaya sopan ke kedua layanan."""
    import time
    shodan_rows, geo_rows = [], []
    for i, ip in enumerate(ip_list):
        shodan_rows.append(check_ip_shodan_internetdb(ip))
        geo_rows.append(check_ip_geolocation(ip))
        if progress_callback:
            progress_callback(i + 1, len(ip_list))
        if i < len(ip_list) - 1:
            time.sleep(0.5)
    return pd.DataFrame(shodan_rows), pd.DataFrame(geo_rows)
