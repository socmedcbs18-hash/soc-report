"""
IOC - GitHub Threat Feed Checker
=========================================================
Download daftar IP jahat dari repo GitHub publik (FireHOL blocklist-ipsets)
dan cek apakah IP dari log firewall ada di daftar itu. TIDAK BUTUH API KEY -
cukup akses internet ke raw.githubusercontent.com.

CATATAN JUJUR: kode ini ditulis berdasarkan dokumentasi/struktur repo
FireHOL yang PUBLIK dan dikenal luas, TAPI belum bisa saya test langsung
dari sandbox saya (tidak ada akses internet). Struktur file (baris komentar
diawali '#', 1 IP/CIDR per baris) sudah stabil dari repo ini selama
bertahun-tahun, tapi tetap disarankan dicoba dulu sebelum dipakai produksi.
"""

import ipaddress
import time
from pathlib import Path

import pandas as pd
import requests

CACHE_DIR = Path("database") / "ioc_feed_cache"
CACHE_TTL_HOURS = 24  # feed di-download ulang kalau cache sudah lebih dari 24 jam

# Feed default - SEMUA di-host di GitHub (raw.githubusercontent.com), publik,
# TIDAK BUTUH API KEY. Bisa ditambah/dikurangi sesuai kebutuhan.
DEFAULT_FEEDS = {
    "FireHOL Level 1 (agresif, sering update)":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "FireHOL Level 2 (lebih luas, agak lebih banyak false positive)":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "Feodo Tracker (botnet C2, via ipsum mirror)":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.ipset",
    "CI Army Bad IPs":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ci_badguys.ipset",
    "Feodo Tracker Official (abuse.ch, botnet C2 aktif - direkomendasikan repo ioc-threat-intel)":
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}


def _download_feed(name, url):
    """Download 1 feed, return set of network objects (bisa /32 tunggal
    atau CIDR range). Kalau gagal (network error/404/dst), return None
    dan JANGAN bikin seluruh proses berhenti - feed lain tetap dicoba."""
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        networks = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.add(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue  # baris yang bukan IP/CIDR valid, dilewati diam-diam
        return networks
    except requests.exceptions.RequestException as e:
        print(f"   [WARNING] Gagal download feed '{name}': {e}")
        return None


def get_feeds(selected_feed_names, force_refresh=False):
    """Ambil feed yang dipilih - pakai cache lokal (CSV) kalau masih fresh
    (<24 jam), kalau tidak/expired baru download ulang. Return dict
    {feed_name: set_of_networks}. Feed yang gagal didownload DAN tidak ada
    cache-nya akan dikosongkan (bukan bikin error), supaya feed lain tetap
    bisa dipakai."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    result = {}

    for name in selected_feed_names:
        if name not in DEFAULT_FEEDS:
            continue
        url = DEFAULT_FEEDS[name]
        cache_file = CACHE_DIR / f"{abs(hash(name))}.txt"

        use_cache = (
            not force_refresh and cache_file.exists()
            and (time.time() - cache_file.stat().st_mtime) < CACHE_TTL_HOURS * 3600
        )

        if use_cache:
            networks = set()
            for line in cache_file.read_text().splitlines():
                try:
                    networks.add(ipaddress.ip_network(line.strip(), strict=False))
                except ValueError:
                    continue
            result[name] = networks
        else:
            networks = _download_feed(name, url)
            if networks is not None:
                cache_file.write_text("\n".join(str(n) for n in networks))
                result[name] = networks
            elif cache_file.exists():
                # Download gagal TAPI ada cache lama - lebih baik pakai cache
                # basi daripada tidak ada data sama sekali.
                networks = set()
                for line in cache_file.read_text().splitlines():
                    try:
                        networks.add(ipaddress.ip_network(line.strip(), strict=False))
                    except ValueError:
                        continue
                result[name] = networks
                print(f"   [INFO] Pakai cache lama untuk '{name}' (download terbaru gagal).")
            else:
                result[name] = set()  # tidak ada cache & download gagal - kosongkan, jangan crash

    return result


def check_ips_against_feeds(ip_list, feeds_dict):
    """ip_list: list string IP. feeds_dict: hasil dari get_feeds().
    Return DataFrame: IP, Matched_Feeds (nama feed yang match, dipisah koma),
    Feed_Match_Count."""
    rows = []
    for ip_str in ip_list:
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            rows.append({"IP": ip_str, "Matched_Feeds": "IP tidak valid", "Feed_Match_Count": 0})
            continue

        matched = []
        for feed_name, networks in feeds_dict.items():
            if any(ip_obj in net for net in networks):
                matched.append(feed_name)

        rows.append({
            "IP": ip_str,
            "Matched_Feeds": ", ".join(matched) if matched else "-",
            "Feed_Match_Count": len(matched),
        })
    return pd.DataFrame(rows)
