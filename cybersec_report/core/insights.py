"""Finding engine: analytics -> finding -> interpretasi -> rekomendasi.
Hanya memakai evidence dari analytics. Redaksi hati-hati ('mengindikasikan', 'teramati',
'berpotensi', 'berdasarkan data yang tersedia'); tidak mengubah indikasi menjadi fakta compromise."""
from cybersec_report.core.fmt import fmt_int, fmt_pct
from cybersec_report.sources.ips import classify_attack


def finding(domain, level, text, evidence, impact="", recommendation="", action="", prevention="", details=None):
    return {"domain": domain, "severity": level, "finding": text, "evidence": evidence, "impact": impact,
            "recommendation": recommendation, "action": action, "prevention": prevention, "details": details or []}


def build_ips_findings(a, rules, settings, rep_summary=None, mom=None):
    t, loc = a["total_events"], settings.get("number_locale", "id")
    I, P = (lambda x: fmt_int(x, loc)), (lambda x: fmt_pct(x, 2, loc))
    rec, F = a["reconciliation"], []
    if t == 0:
        return [finding("IPS", "INFO", "Tidak ada event serangan pada scope data yang diberikan.", {"total_events": 0})]

    # 1. Volume & containment
    txt = f"Terdapat {I(t)} event serangan pada {a['name']} ({I(rec['raw_records_in_file'])} record mentah), berstatus diblokir oleh IPS."
    if rec["events_excluded_by_action"] > 0:
        txt += (f" Tambahan {I(rec['events_excluded_by_action'])} event berstatus non-blocking tidak dihitung dan perlu ditinjau terpisah.")
    F.append(finding("IPS", "INFO", txt, {"total_events": t, "raw_records": rec["raw_records_in_file"], "excluded_events": rec["events_excluded_by_action"]},
        impact="Kontrol IPS teramati memblokir trafik tersebut. Berdasarkan dataset IPS saja, tidak ditemukan indikasi compromise; "
               "namun dataset IPS saja tidak cukup untuk membuktikan ada atau tidaknya compromise (perlu korelasi dengan EDR/SIEM).",
        recommendation="Pertahankan IPS dalam mode blocking dengan signature database yang terbaru.",
        action="Verifikasi versi signature IPS dan korelasikan dengan alert EDR/SIEM pada asset yang ditarget.",
        prevention="Jadwalkan pembaruan signature dan review kebijakan IPS secara berkala."))

    # 2. Critical
    sev = a["severity"].set_index("Severity")["Count"]
    crit = float(sev.get("Critical", 0))
    if crit > 0:
        top = a["top_by_severity"]["Critical"]
        top = top[top["Attack Name"] != "Others"].head(3)
        parts = []
        for _, r in top.iterrows():
            note = classify_attack(r["Attack Name"], rules)[1]
            parts.append(f"{r['Attack Name']} ({I(r['Count'])})" + (f": {note}" if note else ""))
        F.append(finding("IPS", "HIGH",
            f"{I(crit)} event ({P(crit / t * 100)} dari total) berseverity Critical. Signature terbanyak:",
            {"critical_events": crit, "critical_pct_total": crit / t * 100, "top_critical": top[["Attack Name", "Count"]].to_dict("records")},
            impact="Signature Critical berasosiasi dengan upaya eksploitasi/backdoor; berpotensi berbahaya jika terdapat sistem terekspos yang belum di-patch atau di-hardening. Data ini hanya menunjukkan upaya yang diblokir.",
            recommendation="Prioritaskan review exposure dan patching untuk layanan yang terkait signature Critical di atas.",
            action="Pastikan layanan/protokol terkait tidak terekspos ke internet tanpa kebutuhan bisnis pada asset yang ditarget.",
            prevention="Terapkan hardening dan patch management berkala; batasi exposure layanan seperlunya.", details=parts))

    # 3. Dominasi kategori
    cats = a["categories"]
    cats_known = cats[cats["Category"] != "Uncategorized"]
    if len(cats_known) and cats_known.iloc[0]["Percent"] >= settings["ips"]["category_dominance_threshold_pct"]:
        c = cats_known.iloc[0]
        impact = ("Aktivitas scanning masif mengindikasikan tahap reconnaissance otomatis yang berpotensi mendahului serangan yang lebih terarah."
                  if c["Category"] == "Reconnaissance" else f"Dominasi kategori {c['Category']} perlu dipantau tren dan targetnya.")
        F.append(finding("IPS", "MEDIUM",
            f"Mayoritas event ({P(c['Percent'])}) termasuk kategori {c['Category']} berdasarkan kamus signature.",
            {"category": c["Category"], "events": float(c["Count"]), "pct_total": float(c["Percent"])}, impact=impact,
            recommendation="Pertahankan blocking dan pantau apakah aktivitas dari IP yang sama berlanjut ke signature eksploitasi."))

    # 4. Konsentrasi source IP
    cn, p = a["concentration"], a["source_profile"]
    if cn["top1_source_ip"] and cn["top1_source_ip_pct"] >= settings["ips"]["ip_concentration_threshold_pct"]:
        row = p.iloc[0]
        F.append(finding("IPS", "MEDIUM",
            f"Source IP {row['Source IP']} ({row['Country']}) menyumbang {I(row['Attack Count'])} event ({P(cn['top1_source_ip_pct'])}), signature utama {row['Top Attack']}.",
            {"source_ip": row["Source IP"], "events": float(row["Attack Count"]), "pct_total": cn["top1_source_ip_pct"], "top_attack": row["Top Attack"]},
            impact="Konsentrasi pada satu sumber mengindikasikan aktivitas otomatis yang berulang dari IP tersebut.",
            recommendation="Pertimbangkan rate-limit/blokir IP berulang setelah verifikasi reputasi.",
            action="Periksa reputasi IP tersebut (VirusTotal/AbuseIPDB) dan tinjau apakah IP perlu masuk daftar blokir."))
    if cn["ips_multi_signature"] > 0:
        F.append(finding("IPS", "INFO",
            f"{I(cn['ips_multi_signature'])} source IP menggunakan lebih dari satu signature dan {I(cn['ips_multi_destination'])} IP menyasar lebih dari satu destination.",
            {"ips_multi_signature": cn["ips_multi_signature"], "ips_multi_destination": cn["ips_multi_destination"]}))

    # 5. Target & negara
    d = a["top_destination"].iloc[0]
    F.append(finding("IPS", "MEDIUM", f"Target utama: {d['Dest']} ({P(d['Percent'])} dari total event).",
        {"top_destination": d["Dest"], "events": float(d["Count"]), "pct_total": float(d["Percent"])},
        impact="Asset yang paling sering ditarget memiliki exposure internet yang perlu dikonfirmasi.",
        recommendation="Review exposure service dan hardening pada asset target utama."))
    c = a["top_country"]
    c = c[c["Source Country"] != "Others"]
    if len(c):
        F.append(finding("IPS", "INFO",
            f"Negara sumber terbanyak berdasarkan GeoIP: {c.iloc[0]['Source Country']} ({P(c.iloc[0]['Percent'])}). Negara sumber bukan atribusi pelaku (dapat melalui proxy/VPN/infrastruktur sewaan).",
            {"top_country": c.iloc[0]["Source Country"], "pct_total": float(c.iloc[0]["Percent"])}))

    # 6. Reputasi
    if rep_summary and rep_summary.get("assessed", 0) > 0:
        hi = rep_summary["high_or_critical"]
        F.append(finding("IPS", "HIGH" if hi else "INFO",
            f"Dari {I(rep_summary['assessed'])} source IP yang dinilai reputasinya, {I(hi)} IP berada pada level High/Critical (Internal Normalized Threat Score).",
            rep_summary, impact="Skor bersifat internal dan hanya merepresentasikan data provider yang tersedia; bukan skor resmi vendor.",
            recommendation="Tinjau IP berskor tinggi untuk kandidat blokir permanen." if hi else "",
            action="Gunakan tabel Top Source IP untuk memprioritaskan tindak lanjut." if hi else ""))
    else:
        F.append(finding("IPS", "INFO", "Reputasi source IP belum dinilai pada periode ini (reputation check belum dijalankan atau provider tidak tersedia).", {"assessed": 0}))

    # 7. MoM
    if mom:
        tot = next(r for r in mom if r["Metric"] == "Total events")
        chg = "n/a" if tot["Change %"] is None else P(abs(tot["Change %"]))
        F.append(finding("IPS", "INFO",
            f"Total event {tot['Trend'].split()[1].lower()} {chg} dibanding bulan sebelumnya ({I(tot['Previous'])} → {I(tot['Current'])}).",
            {"mom": mom}))
    return F


def reputation_summary(profile_with_rep):
    assessed = profile_with_rep[profile_with_rep["Threat Score"].notna()]
    return {"assessed": int(len(assessed)),
            "high_or_critical": int(assessed["Risk Level"].isin(["High", "Critical"]).sum()),
            "by_level": assessed["Risk Level"].value_counts().to_dict()}
