"""
IOC - Composite Risk Scorer
=========================================================
Gabungkan hasil dari SEMUA sumber (GitHub Feed/Feodo Tracker + VirusTotal +
AbuseIPDB + ThreatFox + URLhaus + Shodan exposure) jadi 1 skor risiko per
IP (0-100, makin tinggi makin berisiko) - metodologi transparan.

Bobot diperbarui terinspirasi dari algoritma scoring `ioc-threat-intel`
(README repo tersebut), disesuaikan dengan sumber yang benar-benar saya
implementasikan:
- VirusTotal malicious ratio: 25%
- AbuseIPDB confidence: 25%
- GitHub Feed / Feodo Tracker match: 20%
- ThreatFox malware match: 15% (bonus besar kalau match - malware feed
  spesifik biasanya akurat, sedikit false positive)
- URLhaus listed: 10%
- Shodan exposure (CVE ditemukan): 5% (BEDA JENIS sinyal - ini soal
  "device rawan diserang", bukan "sudah terbukti jahat" - makanya bobotnya
  kecil, cuma pemberat tambahan)
"""

import pandas as pd


def combine_and_score(feed_df, vt_df=None, abuseipdb_df=None, threatfox_urlhaus_df=None, shodan_df=None):
    """Gabung semua DataFrame (per-IP) jadi 1, hitung skor komposit.
    SEMUA parameter selain feed_df bersifat OPSIONAL (None kalau sumber itu
    tidak diaktifkan) - skor HANYA dihitung dari sumber yang datanya
    tersedia, supaya IP yang cuma dicek sebagian sumber tidak salah dihukum."""
    merged = feed_df.copy()
    for df in [vt_df, abuseipdb_df, threatfox_urlhaus_df, shodan_df]:
        if df is not None and len(df) > 0:
            merged = merged.merge(df, on="IP", how="left")

    def calc_score(row):
        components = []

        # A. Feed match / Feodo Tracker (20%)
        feed_count = row.get("Feed_Match_Count", 0)
        if pd.notna(feed_count):
            feed_score = min(100, feed_count * 50)
            components.append((feed_score, 0.20))

        # B. VirusTotal (25%)
        vt_mal = row.get("VT_Malicious")
        if pd.notna(vt_mal):
            vt_total = (row.get("VT_Malicious", 0) + row.get("VT_Suspicious", 0)
                        + row.get("VT_Harmless", 0) + row.get("VT_Undetected", 0))
            if vt_total and vt_total > 0:
                vt_score = 100 * (row.get("VT_Malicious", 0) + 0.5 * row.get("VT_Suspicious", 0)) / vt_total
                components.append((vt_score, 0.25))

        # C. AbuseIPDB (25%)
        abuse_conf = row.get("AbuseIPDB_Confidence_%")
        if pd.notna(abuse_conf):
            components.append((abuse_conf, 0.25))

        # D. ThreatFox malware match (15%) - kalau ada nama malware, artinya match
        if "ThreatFox_Malware" in row.index:
            tf_error = row.get("ThreatFox_Error")
            tf_skipped = ("ThreatFox_Error" in row.index) and pd.notna(tf_error) and str(tf_error).strip() != ""
            if not tf_skipped:
                tf_malware = row.get("ThreatFox_Malware")
                if pd.notna(tf_malware):
                    tf_score = 100 if str(tf_malware).strip() else 0
                    components.append((tf_score, 0.15))

        # E. URLhaus listed (10%)
        if "URLhaus_URL_Count" in row.index:
            uh_error = row.get("URLhaus_Error")
            uh_skipped = ("URLhaus_Error" in row.index) and pd.notna(uh_error) and str(uh_error).strip() != ""
            if not uh_skipped:
                uh_count = row.get("URLhaus_URL_Count")
                if pd.notna(uh_count):
                    uh_score = min(100, uh_count * 25)
                    components.append((uh_score, 0.10))

        # F. Shodan exposure - CVE ditemukan (5%) - sinyal BEDA JENIS (exposure,
        # bukan "terbukti jahat") - bobot kecil sengaja, cuma pemberat.
        if "Shodan_CVEs" in row.index:
            shodan_error = row.get("Shodan_Error")
            shodan_skipped = ("Shodan_Error" in row.index) and pd.notna(shodan_error) and str(shodan_error).strip() != ""
            if not shodan_skipped:
                shodan_cves = row.get("Shodan_CVEs")
                if pd.notna(shodan_cves) and str(shodan_cves).strip():
                    n_cve = len(str(shodan_cves).split(","))
                    shodan_score = min(100, n_cve * 20)
                    components.append((shodan_score, 0.05))

        if not components:
            return None
        total_w = sum(w for _, w in components)
        return round(sum(v * w for v, w in components) / total_w, 1)

    merged["Risk_Score"] = merged.apply(calc_score, axis=1)

    def classify(score):
        if score is None:
            return "Data Tidak Cukup"
        if score >= 70:
            return "HIGH RISK"
        if score >= 40:
            return "MEDIUM RISK"
        if score > 0:
            return "LOW RISK"
        return "CLEAN"

    merged["Risk_Level"] = merged["Risk_Score"].apply(classify)
    return merged.sort_values("Risk_Score", ascending=False, na_position="last")
