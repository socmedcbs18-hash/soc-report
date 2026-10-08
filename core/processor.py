"""
=========================================================
SOC REPORT GENERATOR
Processor Engine (FIXED + EXTENDED)
Version : 4.0
=========================================================
Perubahan dari v3.0:
- build_rule_summary: sebelumnya "master.merge(alert_summary, how='left')" -> baris
  alert/incident yang rule-nya tidak ada di master HILANG dari total report tanpa
  jejak. Sekarang pakai outer merge, baris yang tidak ada di master tetap muncul
  dan ditandai "Not in Master".
- build_priority: sebelumnya asumsi Priority berformat string "P1"/"P2", padahal
  data asli numeric (1.0/2.0/3.0/4.0) -> sort selalu gagal (semua NaN). Diperbaiki.
- build_domain: keyword mapping sekarang diurutkan berdasarkan kolom Priority di
  Domain_Mapping_Splunk.xlsx sebelum dipakai (sebelumnya kolom Priority ada di data
  tapi tidak pernah dipakai untuk sorting).
- build_soc_individual_kpi (BARU): KPI per analyst -> MTTR, MTTC, workload share,
  breach rate, dibandingkan ke SLA.
- build_hypothesis_insight (BARU): insight terstruktur menjawab hipotesis gap
  analysis (conversion rate, signal-to-noise, coverage, dsb) - bukan cuma daftar
  angka, tapi kalimat "so what".
=========================================================
"""

import pandas as pd
import numpy as np
from pathlib import Path

from utils.helpers import clean_severity
from core.mitre_killchain import (
    enrich_incident_mitre_killchain, build_mitre_technique_summary,
    build_mitre_tactic_summary, build_killchain_summary, build_data_quality_report,
    generate_mitre_killchain_insights, build_mitre_hierarchy, build_technique_impact,
    build_mitre_by_killchain_stage, build_killchain_funnel, build_triage_summary,
)

from config.settings import (
    SLA_MTTR_SECONDS,
    NOISE_ALERT_THRESHOLD,
    KEEP_THRESHOLD,
    REVIEW_THRESHOLD,
    TUNE_THRESHOLD,
    HEALTHY_THRESHOLD,
)


class SOCProcessor:

    def __init__(self, data):
        self.master = data["master_rule"].copy()
        self.alert = data["alert"].copy()
        self.incident = data["incident"].copy()
        self.domain = data["domain_mapping"].copy()
        self.nonsplunk = data.get("nonsplunk", None)
        self.task = data.get("task", None)
        self.cti = data.get("cti", None)
        # period_key = label yang DIKETIK USER (mis. "2026-07") - dipakai sebagai
        # KUNCI histori/tracking lintas periode (Monthly Comparison, Severity Trend,
        # dst). HARUS stabil/konsisten walau data yang diupload beda-beda, supaya
        # generate ulang periode yang sama tidak dianggap sebagai periode baru.
        # BEDA dari period_label_text (teks tanggal otomatis dari data asli, cuma
        # untuk kalimat narasi - "periode 01 Jul - 31 Jul 2026").
        self.period_key = data.get("week", "unknown_period")
        self.report = {}
        self.rule_summary = None

    # =====================================================
    # PERIOD INFO (BARU) - dipakai supaya teks insight tidak hardcode "minggu ini"
    # dan tetap benar untuk laporan bulanan / minggu yang lintas bulan.
    # =====================================================

    # =====================================================
    # HELPER TERPUSAT: flag breach - 1 sumber kebenaran untuk SEMUA method
    # yang butuh tahu "tiket ini breach SLA atau tidak", supaya konsisten
    # di skema data manapun (lama: kolom "Breach ?"; baru: FlagBreachResponse/
    # FlagBreachResolution) - dipanggil PALING AWAL di run(), hasilnya dipakai
    # ulang di semua method lain via self.incident["_Breach"].
    # =====================================================

    def _compute_incident_breach_flag(self):
        inc = self.incident
        if "FlagBreachResponse" in inc.columns or "FlagBreachResolution" in inc.columns:
            resp_b = pd.to_numeric(inc.get("FlagBreachResponse", 0), errors="coerce").fillna(0)
            reso_b = pd.to_numeric(inc.get("FlagBreachResolution", 0), errors="coerce").fillna(0)
            self.incident["_Breach"] = (resp_b == 1) | (reso_b == 1)
        elif "Breach ?" in inc.columns:
            self.incident["_Breach"] = inc["Breach ?"].astype(str).str.upper().eq("TRUE")
        else:
            self.incident["_Breach"] = False  # tidak ada info breach sama sekali - jangan menebak

    def build_period_info(self):
        alert_dates = pd.to_datetime(self.alert["Alert Time"], errors="coerce").dropna()

        if len(alert_dates) > 0:
            self.period_start = alert_dates.min()
            self.period_end = alert_dates.max()
        else:
            self.period_start = self.period_end = None

        if self.period_start is not None:
            self.period_label_text = (
                f"periode {self.period_start.strftime('%d %b %Y')} - {self.period_end.strftime('%d %b %Y')}"
            )
        else:
            self.period_label_text = "periode ini"

    # =====================================================
    # READING GUIDE / GLOSSARY (BARU)
    # Supaya saat presentasi ke BoD, setiap angka bisa ditelusuri sumbernya dan
    # setiap sheet/chart jelas menjawab pertanyaan apa - bukan cuma dump data.
    # =====================================================

    def build_reading_guide(self):
        rows = [
            ("Executive Summary",
             "Ringkasan angka kunci 1 halaman untuk BoD.",
             "Dihitung dari sheet 'Rule Summary' (agregat) + data mentah tiket/alert non-Splunk.",
             "-"),
            ("Hypothesis Insight",
             "Insight dalam bentuk kalimat 'so what', menjawab pertanyaan gap-analysis konkret.",
             "Lihat kolom 'Sumber_Data' di sheet itu sendiri - tiap baris insight menyebutkan sheet asalnya.",
             "-"),
            ("Rule Summary",
             "TABEL INDUK - berisi SEMUA rule (baik yang ada di Master Rules maupun yang tidak dikenal), "
             "digabung dengan jumlah alert & incident masing-masing rule di periode ini. "
             "Sheet 'Top Rule', 'Noise', 'Tuning', 'Dormant', 'Unmapped' semuanya adalah HASIL FILTER "
             "dari tabel ini - bukan sumber data terpisah.",
             "Gabungan Master_Rules_Splunk.xlsx + alert_splunk_*.xlsx + insiden_ivanti_*.xlsx, "
             "di-join berdasarkan nama rule yang sudah dinormalisasi.",
             "'Rule mana yang paling banyak alert/incident? Mana yang perlu tuning?'"),
            ("Top Rule",
             "20 rule dengan incident terbanyak - subset dari Rule Summary, diurutkan.",
             "Filter dari Rule Summary, sort by Incident_Count.",
             "'Rule apa yang paling sering jadi insiden nyata?'"),
            ("Noise",
             "Rule dengan alert banyak (>=20) TAPI 0 incident - kandidat untuk di-tuning/dikecualikan "
             "karena kemungkinan besar false positive berulang.",
             "Filter dari Rule Summary, kolom Recommendation = 'Noise'.",
             "'Rule mana yang bikin analyst capek review tapi tidak pernah jadi insiden nyata?'"),
            ("Tuning",
             "Rule dengan Detection Rate rendah (Critical Tuning/Need Tuning/Review) - alert ada, "
             "sebagian kecil jadi incident, kandidat untuk disesuaikan threshold-nya.",
             "Filter dari Rule Summary, kolom Recommendation.",
             "'Rule mana yang perlu di-tuning supaya tidak terlalu sensitif/terlalu longgar?'"),
            ("Dormant",
             "Rule yang terdaftar di Master Rules TAPI tidak trigger sama sekali di periode ini.",
             "Filter dari Rule Summary, kolom Recommendation = 'Dormant'.",
             "'Rule apa yang mungkin sudah tidak relevan / rusak / salah konfigurasi?'"),
            ("Unmapped",
             "Alert/incident yang rule-nya TIDAK ditemukan di Master Rules Splunk sama sekali "
             "(In_Master = False) - bisa karena rule baru, migrasi environment, atau salah nama.",
             "Filter dari Rule Summary, kolom In_Master = False.",
             "'Berapa banyak alert kita yang datanya \"buta\" karena rule-nya belum terdaftar?'"),
            ("Soc Individual Kpi",
             "KPI per analyst SOC: jumlah tiket, workload share, MTTR, MTTC, breach rate. Kolom "
             "'Total_Workload (Insiden+Task)' menggabungkan insiden resmi DENGAN task dari tim lain - "
             "supaya beban kerja SEBENARNYA kelihatan, bukan cuma insiden ter-assign.",
             "DIHITUNG LANGSUNG dari data tiket Ivanti mentah (bukan dari Rule Summary) - "
             "kolom Created On/Responded On/Resolved On per baris tiket, dikelompokkan per Owner, "
             "digabung dengan Task_By_Owner kalau ada data task_soc.",
             "'Siapa yang paling banyak menangani tiket DAN task, dan apakah responsnya sesuai SLA?'"),
            ("Domain",
             "Ringkasan alert & incident per Security Domain (Network/Server/User/dll).",
             "Rule Summary dikelompokkan berdasarkan Domain_Mapping_Splunk.xlsx (keyword matching ke nama rule).",
             "'Domain keamanan mana yang paling banyak insiden - Network, Server, User, dst?'"),
            ("Nonsplunk Coverage",
             "Ringkasan % alert dari device non-Splunk (Akamai/CSPM/Microsoft Defender) yang berhasil "
             "jadi tiket, per device.",
             "Dihitung langsung dari kolom 'Apakah dibuat tiket Ivanti? (Y/N)' di file alert_nonsplunk "
             "- BUKAN hasil matching/estimasi, murni membaca kolom yang sudah diisi manual.",
             "'Device non-Splunk mana yang paling jarang dieskalasi jadi tiket?'"),
            ("Nonsplunk Detail",
             "Baris mentah semua alert non-Splunk periode ini (sebelum diringkas).",
             "Langsung dari file alert_nonsplunk_*.xlsx, digabung semua sheet device.",
             "'Alert non-Splunk spesifik apa saja yang terjadi, dan statusnya?'"),
            ("Breach",
             "Tiket yang melanggar SLA (kolom Breach = TRUE di Ivanti).",
             "Filter langsung dari tiket Ivanti mentah.",
             "'Tiket mana saja yang melanggar SLA, perlu eskalasi?'"),
            ("Task_Summary / Task_By_Owner / Task_Weekly_Regularity",
             "Task pengecekan dari tim lain yang di-assign ke SOC TANPA insiden ter-assign resmi - "
             "selama ini beban kerja ini tidak kelihatan di laporan.",
             "File task_soc_*.xlsx (opsional per minggu) - kolom Owner = SOC analyst pengerja, "
             "Created On/Completed On untuk hitung waktu pengerjaan.",
             "'Seberapa sering & rutin SOC menerima task dari tim lain, dan siapa yang paling banyak menangani?'"),
            ("CTI_Summary / CTI_By_Type / CTI_By_Status / CTI_Trend",
             "Alert threat intelligence eksternal (FortiRecon - Stealer Infection, EASM Change, dst) yang "
             "selama ini cuma di-track manual di Excel tanpa reporting bulanan. KEAMANAN: kolom Password "
             "dari sumber data TIDAK PERNAH ditampilkan - hanya indikator Password_Leaked (ada/tidak).",
             "File CTI FortiRecon mentah (opsional per periode) - True Positive Rate dihitung dari kolom "
             "'Hasil Pengecekan', tren lintas periode dari database/cti_history.csv.",
             "'Berapa banyak alert CTI eksternal, berapa akurat (True Positive Rate), dan trennya naik/turun?'"),
            ("Daily_Trend",
             "Jumlah alert & insiden per TANGGAL dalam periode ini, plus kolom Rule_Kontributor_Terbesar "
             "yang menunjukkan rule apa paling dominan tiap tanggal - supaya lonjakan bisa langsung "
             "ditelusuri penyebabnya.",
             "Alert Time (Splunk) & Created On (Ivanti) mentah, dikelompokkan per tanggal kalender.",
             "'Apakah ada lonjakan alert/insiden di tanggal tertentu, dan rule apa penyebabnya?'"),
            ("Severity_Breakdown",
             "Jumlah tiket dikelompokkan per severity dari sisi IVANTI (Priority tiket, bukan severity "
             "rule Splunk). Untuk severity dari sisi Splunk, lihat kolom Severity di Rule Summary/Bab 2.",
             "Kolom Priority di tiket Ivanti mentah, dipetakan ke label severity (0=Critical, 1=High, "
             "2=Medium, 3=Low - skala 0-based sesuai konfirmasi user).",
             "'Dari semua tiket, berapa proporsi yang analyst tandai benar-benar kritis vs rutin?'"),
            ("Cause_Code_Breakdown",
             "Klasifikasi hasil investigasi tiket berdasarkan Cause Code (field diisi MANUAL oleh analyst "
             "saat menutup tiket, bukan otomatis dari sistem). DEFINISI (disimpulkan dari nama field & "
             "pola data - PERLU DIKONFIRMASI ke tim yang menentukan kriteria field ini): "
             "'Prevented' = kontrol keamanan berhasil mencegah/memblokir ancaman sebelum berdampak. "
             "'Breach - Reported' = ancaman BENAR-BENAR berhasil menembus (ada bukti akses tidak sah/"
             "kompromi), dilaporkan sebagai breach resmi. 'Belum Diklasifikasi' = field ini masih kosong. "
             "SALING EKSKLUSIF - jumlahnya SELALU = Total Tiket, bisa diverifikasi langsung.",
             "Kolom Cause Code di tiket Ivanti mentah - sebelumnya belum pernah dipakai.",
             "'Dari semua tiket, berapa yang berhasil dicegah vs benar-benar jadi breach vs belum dicek?'"),
            ("Status_Summary & Cancelled_Crosstab",
             "Jumlah tiket berstatus Cancelled (kolom Status - DIMENSI TERPISAH dari Cause Code, JANGAN "
             "dijumlahkan ke Cause_Code_Breakdown karena bisa tumpang tindih). Cancelled_Crosstab "
             "menunjukkan rincian: dari tiket Cancelled itu, berapa yang sudah/belum punya Cause Code.",
             "Kolom Status di tiket Ivanti mentah.",
             "'Berapa tiket yang ternyata dibatalkan (indikasi false positive), dan apakah tumpang tindih dengan yang sudah diklasifikasi Cause Code?'"),
            ("Master_Status_Distribution",
             "Persentase rule Enabled vs Disabled vs Belum Ter-mapping - versi chart dari metrik Bab 1.",
             "Dihitung dari Rule_Status & In_Master di Rule Summary.",
             "'Dari semua rule terdaftar, berapa proporsi yang aktif/nonaktif/belum dikenal?'"),
            ("Rule_Recommendation_Distribution",
             "Persentase rule per status (Healthy/Acceptable/Noise/Tuning/Dormant) - versi chart untuk Bab 2. "
             "'Healthy' = Detection Rate >=25%, 'Acceptable' = 10-25% (di atas ambang minimal tapi belum "
             "tinggi - BUKAN berarti sudah optimal).",
             "Dihitung dari kolom Recommendation di Rule Summary.",
             "'Secara keseluruhan, berapa persen rule kita yang benar-benar bagus vs perlu perhatian?'"),
            ("Domain_Recommendation",
             "Silang antara Security Domain dan status Recommendation (Noise/Tuning/Dormant/Healthy) - "
             "domain mana yang paling banyak rule bermasalah.",
             "Rule Summary dikelompokkan per Security_Domain x Recommendation.",
             "'Domain keamanan mana yang paling butuh perhatian tuning?'"),
            ("Cause_Code_By_Domain / Unclassified_By_Status / Closed_No_Causecode_By_Owner",
             "Root-cause dari Outcome: domain mana paling sering Prevented/Breach, status apa yang "
             "membuat tiket belum diklasifikasi, dan analyst mana yang paling banyak tiket Closed "
             "tanpa Cause Code terisi (kelalaian pengisian, bukan pending).",
             "Cause Code & Status di tiket Ivanti mentah, disilang dengan Security_Domain & Owner.",
             "'Kenapa tiket ini Prevented/Breach/belum diklasifikasi, dan siapa yang perlu ditindaklanjuti?'"),
            ("Mismatch_Under_By_Rule / Mismatch_Under_By_Owner",
             "Root-cause dari Severity vs Priority Mismatch: rule mana yang paling sering "
             "under-prioritized, dan analyst mana yang paling sering melakukannya.",
             "Filter dari Severity_Priority_Mismatch (Arah=UNDER), dikelompokkan per rule/Owner.",
             "'Rule/analyst mana yang perlu SOP atau coaching soal prioritas tiket?'"),
            ("Severity_Priority_Mismatch",
             "Tiket dimana severity rule (Splunk) tidak sama dengan priority yang diberikan analyst "
             "(Ivanti). Fokus ke yang UNDER-PRIORITIZED - rule serius tapi priority tiket rendah.",
             "Silang antara kolom Severity di Rule Summary vs Priority di tiket Ivanti mentah, dicocokkan "
             "berdasarkan rule yang sama.",
             "'Apakah tim SOC konsisten memprioritaskan insiden sesuai tingkat keparahan rule-nya?'"),
            ("Entity_Correlation",
             "PIC/pihak TUJUAN tiket (kolom Customer di Ivanti - BUKAN SOC analyst yang mengerjakan, "
             "itu ada di kolom Owner/sheet Soc Individual Kpi) yang terlibat di >=2 rule BERBEDA dalam "
             "periode ini - indikasi aktivitas multi-vektor ke 1 target, bukan kejadian acak tersebar.",
             "Dikelompokkan dari kolom Customer di tiket Ivanti mentah (PIC tujuan tiket), akun sistem/tim "
             "otomatis (mis. 'splunkhwc-alert') sudah difilter keluar.",
             "'Apakah ada 1 orang/akun/perangkat yang jadi TARGET berulang dari berbagai jenis serangan?'"),
            ("Time_By_Hour / Time_By_Day",
             "Distribusi jumlah alert per jam (0-23) dan per hari (Senin-Minggu).",
             "Dihitung dari kolom Alert Time di file alert Splunk mentah.",
             "'Jam/hari apa paling rawan? Apakah shift SOC sudah sesuai pola serangan aktual?'"),
            ("SLA_Metrics",
             "Metrik SLA berdasarkan state machine resmi (Logged -> Active -> Contained -> Resolved): "
             "MTTD (kejadian->Logged), MTTR (Logged->Active), MTTC (Active->Contained - BELUM ADA DATANYA, "
             "menunggu konfirmasi kolom dari tim Ivanti), MTTRV (Active->Resolved). Dipecah per tier "
             "Priority (P0-P3) dan keseluruhan.",
             "MTTD dari Alert Time (Splunk, proxy waktu kejadian) vs Created On (Ivanti, proxy Logged). "
             "MTTR & MTTRV dari Created On/Responded On/Resolved On.",
             "'Seberapa cepat SOC mendeteksi, merespons, dan menyelesaikan insiden - per tingkat prioritas?'"),
            ("Threat_By_Priority / _Domain / _Target",
             "Profil ancaman dikelompokkan per tier priority (P0-Critical s/d P3-Low): rule/threat apa "
             "paling sering, domain (proxy 'asset') mana paling kena, target (Customer, proxy 'asset') "
             "mana paling sering diserang - per tier priority.",
             "Tiket Ivanti mentah (Priority, Summary) disilang dengan Security_Domain dari Rule Summary "
             "dan Customer. CATATAN: 'asset' di sini PROXY, bukan data inventaris aset sungguhan - "
             "export Splunk/Ivanti tidak punya data CMDB/asset.",
             "'Ancaman apa yang paling sering muncul di tingkat kritikal, dan siapa/apa yang jadi sasarannya?'"),
            ("Monthly_Comparison",
             "Perbandingan angka kunci (Total Alert, Total Insiden, Detection Rate, dll) untuk SEMUA "
             "periode yang pernah digenerate - bukan cuma 5-6 terakhir seperti Severity/Attack Surface "
             "Trend. Ini tempat utama untuk lihat perbandingan bulan ke bulan.",
             "database/monthly_summary_history.csv - snapshot otomatis tiap kali report digenerate, "
             "tidak dibatasi jumlah periode.",
             "'Bagaimana perbandingan alert/insiden/detection rate dari bulan ke bulan?'"),
            ("Severity_Trend",
             "Tren jumlah tiket per severity (Critical/High/Medium/Low) LINTAS PERIODE - apakah proporsi "
             "insiden serius naik atau turun dari waktu ke waktu.",
             "Akumulasi dari database/severity_history.csv - snapshot Severity_Breakdown tiap kali report "
             "digenerate, butuh minimal 2 periode histori.",
             "'Apakah tren insiden Critical/High naik atau turun dari bulan ke bulan?'"),
            ("Action_Tracker",
             "Konsolidasi SEMUA rule yang PERNAH ditandai bermasalah (Noise/Tuning) di periode manapun, "
             "dengan status: Masih Terbuka (masih bermasalah periode ini) vs Sudah Membaik (dulu "
             "bermasalah, sekarang tidak lagi) - bukti nyata tindak lanjut sudah berjalan atau belum.",
             "database/rule_history.csv (histori yang sama dipakai Recurring Findings), dibandingkan "
             "status rule di periode TERBARU vs riwayat sebelumnya.",
             "'Dari semua rekomendasi tuning yang pernah diberikan, mana yang sudah ditindaklanjuti dan mana yang belum?'"),
            ("Attack_Surface_Trend",
             "Tren jumlah insiden per Security_Domain LINTAS PERIODE (bukan cuma 1 periode) - domain mana "
             "yang konsisten tinggi terus-menerus (indikasi exposure permanen, bukan insiden acak).",
             "Akumulasi dari database/attack_surface_history.csv - terisi otomatis tiap kali report "
             "digenerate, butuh minimal 2 periode histori untuk mulai bermakna.",
             "'Domain/area mana yang TERUS-MENERUS jadi masalah dari waktu ke waktu, bukan cuma sekali ini?'"),
            ("Priority_Per_Rule",
             "Untuk tiap rule Splunk, breakdown berapa insiden yang jadi P0/P1/P2/P3 - supaya kelihatan "
             "rule mana yang paling banyak menghasilkan insiden kritikal vs rutin.",
             "Tiket Ivanti mentah (Summary, Priority), dikelompokkan per rule.",
             "'Rule Splunk mana yang paling banyak menghasilkan insiden PRIORITY TINGGI (bukan cuma insiden banyak)?'"),
            ("Resolved_Closed_Stats",
             "Statistik waktu dari status Resolved ke Closed - termasuk tiket yang langsung Closed di "
             "waktu bersamaan (potensi tanpa tahap review terpisah).",
             "Kolom Resolved On vs Modified On di tiket Ivanti mentah (Modified On dipakai sebagai proxy "
             "waktu Closed, karena tidak ada kolom 'Closed On' terpisah di export).",
             "'Apakah tiket melalui proses review yang wajar sebelum ditutup, atau langsung ditutup?'"),
            ("Lesson_Learned_Log",
             "Catatan resolusi dari modul TASK (bukan Incident - export Incident Ivanti TIDAK punya kolom "
             "catatan/resolusi bertuliskan bebas, sudah dicek langsung).",
             "Kolom Resolution di file task_soc mentah.",
             "'Apa yang bisa dipelajari dari cara task-task ini diselesaikan?'"),
            ("Recurring Findings",
             "Rule yang tercatat sebagai Noise/Critical Tuning/Need Tuning di >=3 dari 5 periode "
             "TERAKHIR yang pernah di-generate - indikasi masalah berulang, bukan kejadian sekali.",
             "Akumulasi dari database/rule_history.csv - terisi otomatis tiap kali report digenerate, "
             "TIDAK akan muncul kalau baru pertama kali pakai tool ini (belum ada histori).",
             "'Temuan apa yang terus berulang dan butuh tindakan permanen, bukan cuma ditutup manual tiap minggu?'"),
            ("Priority",
             "Jumlah tiket per level prioritas (P1-P4).",
             "Dihitung dari kolom Priority di tiket Ivanti mentah.",
             "'Berapa proporsi tiket kritikal (P1) vs rutin (P4)?'"),
        ]

        self.reading_guide = pd.DataFrame(
            rows, columns=["Sheet / Chart", "Penjelasan", "Sumber & Cara Hitung", "Menjawab Pertanyaan"]
        )

    # =====================================================
    # RECURRING FINDINGS (BARU) - butuh histori antar periode
    # =====================================================
    # Report sebelumnya tidak "ingat" periode lalu - tiap generate berdiri sendiri.
    # Supaya bisa jawab "temuan mana yang BERULANG dan berbahaya", kita simpan
    # snapshot ringkas tiap kali report di-generate ke database/rule_history.csv,
    # lalu bandingkan dengan histori yang sudah terkumpul.

    def build_recurring_findings(self):
        print("Building Recurring Findings...")

        history_path = Path("database") / "rule_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        rs = self.rule_summary
        risky = rs[rs["Recommendation"].isin(["Noise", "Critical Tuning", "Need Tuning"])].copy()
        risky = risky[risky["In_Master"]]  # fokus rule yang memang dikenal, bukan yang masih perlu mapping

        snapshot = pd.DataFrame({
            "Period": self.period_key,
            "Period_End": self.period_end,
            "Rule_ID": risky["Rule_ID"],
            "Rule_Names": risky["Rule_Names"],
            "Recommendation": risky["Recommendation"],
            "Alert_Count": risky["Alert_Count"],
            "Incident_Count": risky["Incident_Count"],
        })

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")  # CSV round-trip jadi string - paksa balik ke datetime
            # Hindari duplikat kalau report periode yang sama di-generate ulang
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, snapshot], ignore_index=True)
        else:
            history = snapshot

        history = self._clean_period_history(history)
        history = history.drop_duplicates(subset=["Period", "Period_End", "Rule_ID"], keep="last")
        history.to_csv(history_path, index=False)

        # Hitung berapa kali tiap rule muncul sebagai Noise/Tuning di 5 periode TERAKHIR
        # (periode diambil dari urutan Period_End, bukan urutan file - supaya benar
        # meskipun laporan dijalankan tidak berurutan)
        recent_periods = (
            history[["Period", "Period_End"]].drop_duplicates()
            .sort_values("Period_End", ascending=False).head(5)["Period"]
        )
        recent = history[history["Period"].isin(recent_periods)]

        recurrence = (
            recent.groupby(["Rule_ID", "Rule_Names"])
            .agg(Muncul_Sebagai_Risiko=("Period", "nunique"), Rekomendasi_Terakhir=("Recommendation", "last"))
            .reset_index()
        )
        recurrence = recurrence[recurrence["Muncul_Sebagai_Risiko"] >= 3]  # >=3 dari 5 periode terakhir
        recurrence["Catatan"] = (
            "Berulang " + recurrence["Muncul_Sebagai_Risiko"].astype(str) +
            " dari " + str(len(recent_periods)) + " periode terakhir - kandidat tindakan permanen "
            "(tuning rule, atau eskalasi kalau ternyata deteksi valid berulang)"
        )

        self.recurring_findings = recurrence.sort_values("Muncul_Sebagai_Risiko", ascending=False)
        self.history_period_count = len(recent_periods)

    # =====================================================
    # ADVANCED INSIGHT #1: Severity vs Priority Mismatch
    # =====================================================
    # Membandingkan severity yang ditandai Splunk pada rule (sisi deteksi) dengan
    # priority yang benar-benar diberikan analyst saat bikin tiket Ivanti (sisi
    # respons). Kalau rule "Critical" tapi tiketnya P3/P4 -> under-prioritized,
    # bahaya karena insiden serius bisa terlambat direspons.

    def build_severity_priority_mismatch(self):
        print("Building Severity vs Priority Mismatch...")

        # Skala priority Ivanti di organisasi ini 0-based: 0=Critical, 1=High,
        # 2=Medium, 3=Low (dikonfirmasi user - sebelumnya salah diasumsikan 1-based)
        priority_to_severity = {0: "Critical", 1: "High", 2: "Medium", 3: "Low"}
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0, "-": -1, "Unknown": -1}

        inc = self.incident.dropna(subset=["Priority"]).copy()
        inc["Priority_Severity"] = inc["Priority"].map(priority_to_severity)

        rule_severity = self.rule_summary.set_index("Normalized Rule")["Severity"].to_dict()
        inc["Rule_Severity"] = inc["Normalized Rule"].map(rule_severity)

        inc = inc.dropna(subset=["Rule_Severity"])
        inc = inc[~inc["Rule_Severity"].isin(["-", "Unknown"])]

        inc["Rank_Priority"] = inc["Priority_Severity"].map(severity_rank)
        inc["Rank_Rule"] = inc["Rule_Severity"].map(severity_rank)

        mismatch = inc[inc["Rank_Priority"] != inc["Rank_Rule"]].copy()
        mismatch["Arah"] = np.where(
            mismatch["Rank_Priority"] < mismatch["Rank_Rule"],
            "UNDER-PRIORITIZED (rule severity lebih tinggi dari priority tiket - berbahaya)",
            "Over-prioritized (priority tiket lebih tinggi dari rule severity - tidak berbahaya, cuma tidak efisien)"
        )

        select_cols = ["Incident", "Rule_Severity", "Priority_Severity", "Arah", "Owner", "Created On"]
        if "Summary" in mismatch.columns:
            select_cols.insert(1, "Summary")
        self.severity_priority_mismatch = mismatch[select_cols].sort_values(
            "Arah", ascending=False)  # "UNDER..." > "Over..." alfabetis - yang berbahaya tampil duluan

        self.mismatch_under_count = (mismatch["Arah"].str.startswith("UNDER")).sum()
        self.mismatch_total_checked = len(inc)

        # Root-cause: rule & analyst mana yang paling sering under-prioritized -
        # supaya bisa ditindaklanjuti (SOP rule tertentu / coaching analyst tertentu)
        under = mismatch[mismatch["Arah"].str.startswith("UNDER")]
        _group_col = "Summary" if "Summary" in under.columns else "Normalized Rule"
        self.mismatch_under_by_rule = (
            under.groupby(_group_col).size().reset_index(name="Jumlah")
            .rename(columns={_group_col: "Summary"})
            .sort_values("Jumlah", ascending=False).head(10)
        )
        self.mismatch_under_by_owner = (
            under.dropna(subset=["Owner"]).groupby("Owner").size().reset_index(name="Jumlah")
            .sort_values("Jumlah", ascending=False)
        )

    # =====================================================
    # ADVANCED INSIGHT #2: Entity berulang lintas rule berbeda
    # =====================================================
    # Kolom "Customer" di Ivanti berisi PIC/pihak TUJUAN tiket - orang/akun yang
    # jadi TARGET atau terdampak insiden (BUKAN SOC analyst yang mengerjakan -
    # itu ada di kolom "Owner", dipakai terpisah di build_soc_individual_kpi).
    # Kalau 1 target yang sama muncul di BEBERAPA rule BERBEDA dalam periode yang
    # sama, itu indikasi pola serangan multi-vektor ke 1 target (mis. akun yang
    # sama kena percobaan login DAN malware DAN policy abuse) - beda dengan
    # kejadian acak yang tersebar ke banyak target berbeda.

    def build_entity_correlation(self):
        print("Building Entity Correlation...")

        inc = self.incident.dropna(subset=["Customer"]).copy()

        # Filter akun sistem/tim otomatis (bukan individu) - heuristik: kata
        # pertama = kata kedua (pola "splunkhwc-alert splunkhwc-alert"), atau
        # mengandung "alert"/"team".
        def is_system_account(name):
            name = str(name).strip()
            parts = name.split()
            if len(parts) == 2 and parts[0].lower() == parts[1].lower():
                return True
            if "alert" in name.lower() or "team" in name.lower():
                return True
            return False

        inc["Is_System"] = inc["Customer"].apply(is_system_account)
        individu = inc[~inc["Is_System"]]

        corr = (
            individu.groupby("Customer")
            .agg(
                Jumlah_Insiden=("Incident", "count"),
                Rule_Berbeda=("Normalized Rule", "nunique"),
                Rules=("Normalized Rule", lambda x: ", ".join(sorted(set(x))[:5])),
            )
            .reset_index()
        )

        self.entity_correlation = corr[corr["Rule_Berbeda"] >= 2].sort_values("Rule_Berbeda", ascending=False)

    # =====================================================
    # ADVANCED INSIGHT #3: Pola waktu (jam & hari)
    # =====================================================

    def build_time_pattern(self):
        print("Building Time Pattern...")

        alert_dates = pd.to_datetime(self.alert["Alert Time"], errors="coerce").dropna()

        by_hour = alert_dates.dt.hour.value_counts().sort_index()
        self.time_by_hour = pd.DataFrame({"Jam": by_hour.index, "Jumlah_Alert": by_hour.values})

        day_map = {0: "Senin", 1: "Selasa", 2: "Rabu", 3: "Kamis", 4: "Jumat", 5: "Sabtu", 6: "Minggu"}
        by_day = alert_dates.dt.dayofweek.map(day_map).value_counts()
        order = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]
        self.time_by_day = pd.DataFrame({"Hari": order, "Jumlah_Alert": [by_day.get(d, 0) for d in order]})

        # Jam kerja: 09:00-18:00 WIB, Senin-Jumat (dikonfirmasi user) - sesuaikan
        # angka .between() di bawah kalau shift SOC berbeda.
        is_weekday = alert_dates.dt.dayofweek < 5
        is_business_hour = alert_dates.dt.hour.between(9, 17)
        off_hours = ~(is_weekday & is_business_hour)

        self.pct_off_hours = round(100 * off_hours.sum() / max(len(alert_dates), 1), 1)
        self.peak_hour = int(by_hour.idxmax()) if len(by_hour) > 0 else None
        self.peak_day = by_day.idxmax() if len(by_day) > 0 else None

    # =====================================================
    # ADVANCED INSIGHT #4: Outcome - Prevention Rate & False Positive Rate
    # =====================================================
    # Kolom "Cause Code" & "Status" di Ivanti ternyata menyimpan hasil AKHIR
    # investigasi tiap tiket - selama ini belum pernah dipakai. Ini bukti
    # efektivitas SOC yang paling langsung dimengerti BoD: berapa yang berhasil
    # DICEGAH vs berapa yang benar-benar jadi BREACH, dan berapa yang ternyata
    # false positive (dibatalkan).

    def build_outcome_insight(self):
        print("Building Outcome Insight (Prevention/Breach/False Positive)...")

        inc = self.incident.drop_duplicates(subset=["Incident"]).copy()
        total = len(inc)

        # Kolom 'Cause Code' TIDAK ADA di format Ivanti terbaru (dikonfirmasi
        # dari inspeksi Export_Data_SOC_2.xlsx) - semua baris otomatis masuk
        # 'Belum Diklasifikasi' (konsisten dengan .fillna() di bawah untuk
        # baris yang memang NaN), BUKAN crash dengan KeyError.
        if "Cause Code" not in inc.columns:
            inc["Cause Code"] = pd.NA

        # ---------------------------------------------------
        # TABEL 1: Klasifikasi berdasarkan Cause Code - SALING EKSKLUSIF,
        # HARUS selalu berjumlah = Total Tiket. Ditulis dinamis (bukan hardcode
        # "Prevented"/"Breach - Reported" saja) supaya kalau ada nilai Cause Code
        # lain di masa depan, tetap kehitung, bukan hilang diam-diam.
        # ---------------------------------------------------
        cause_filled = inc["Cause Code"].fillna("Belum Diklasifikasi")
        cause_counts = cause_filled.value_counts()

        self.cause_code_breakdown = pd.DataFrame({
            "Cause_Code": cause_counts.index,
            "Jumlah_Tiket": cause_counts.values,
        })
        self.cause_code_breakdown["%"] = round(100 * self.cause_code_breakdown["Jumlah_Tiket"] / max(total, 1), 1)

        assert self.cause_code_breakdown["Jumlah_Tiket"].sum() == total, \
            "Sanity check gagal: total Cause Code breakdown harus persis sama dengan Total Tiket"

        prevented = int(cause_counts.get("Prevented", 0))
        breach_reported = int(cause_counts.get("Breach - Reported", 0))
        unclassified = int(cause_counts.get("Belum Diklasifikasi", 0))

        # ---------------------------------------------------
        # TABEL 2: Status Cancelled - DIMENSI TERPISAH dari Cause Code (kolom
        # berbeda: "Status", bukan "Cause Code"). TIDAK dijumlahkan ke tabel 1 -
        # supaya tidak menyesatkan seperti sebelumnya (37+28+67+197=329 != 262).
        # Disertakan cross-tab supaya kelihatan overlap-nya, bukan cuma angka
        # berdiri sendiri yang tidak bisa diverifikasi.
        # ---------------------------------------------------
        status = inc["Status"].astype(str)
        cancelled_mask = status == "Cancelled"
        cancelled = int(cancelled_mask.sum())

        cancelled_cause = inc.loc[cancelled_mask, "Cause Code"].fillna("Belum Diklasifikasi").value_counts()
        self.cancelled_crosstab = pd.DataFrame({
            "Cause_Code_pada_Tiket_Cancelled": cancelled_cause.index,
            "Jumlah": cancelled_cause.values,
        })

        self.outcome_summary = pd.DataFrame([
            ["Total Tiket (basis semua perhitungan di bawah)", total],
        ], columns=["Kategori", "Jumlah"])

        self.status_summary = pd.DataFrame([
            ["Cancelled (dari kolom Status - indikasi false positive)", cancelled,
             round(100 * cancelled / max(total, 1), 1)],
        ], columns=["Kategori", "Jumlah", "%_dari_Total_Tiket"])

        self.prevention_rate = round(100 * prevented / max(prevented + breach_reported, 1), 1)
        self.false_positive_rate = round(100 * cancelled / max(total, 1), 1)
        self.breach_reported = breach_reported
        self.total_tickets_for_outcome = total
        self.unclassified_count = unclassified

        # ---------------------------------------------------
        # ROOT-CAUSE: dari yang "Belum Diklasifikasi", berapa yang sudah CLOSED
        # (kelalaian pengisian - bukan masih pending) vs masih berjalan/cancelled,
        # dan siapa analyst-nya (supaya bisa ditindaklanjuti per orang).
        # ---------------------------------------------------
        unclass_mask = inc["Cause Code"].isna()
        self.unclassified_by_status = (
            inc.loc[unclass_mask, "Status"].value_counts().reset_index()
        )
        self.unclassified_by_status.columns = ["Status", "Jumlah"]

        closed_no_cause = inc[unclass_mask & (inc["Status"].astype(str) == "Closed")]
        self.closed_no_causecode_by_owner = (
            closed_no_cause.dropna(subset=["Owner"]).groupby("Owner").size()
            .reset_index(name="Jumlah_Tiket_Closed_Tanpa_CauseCode")
            .sort_values("Jumlah_Tiket_Closed_Tanpa_CauseCode", ascending=False)
        )
        self.closed_no_causecode_total = len(closed_no_cause)

        # ---------------------------------------------------
        # ROOT-CAUSE: Cause Code per Security Domain - domain mana yang paling
        # sering "Prevented" vs "Breach - Reported".
        # ---------------------------------------------------
        rs_domain = self.rule_summary[["Normalized Rule", "Security_Domain"]]
        inc_domain = inc.merge(rs_domain, on="Normalized Rule", how="left")
        self.cause_code_by_domain = (
            inc_domain.groupby(["Security_Domain", inc_domain["Cause Code"].fillna("Belum Diklasifikasi")])
            .size().unstack(fill_value=0).reset_index()
        )

    # =====================================================
    # SEVERITY BREAKDOWN (BARU) - insiden dikelompokkan per severity
    # =====================================================

    def build_severity_breakdown(self):
        print("Building Severity Breakdown...")

        # PENTING: ini severity dari Priority TIKET IVANTI (sisi respons/analyst),
        # BUKAN severity rule Splunk (sisi deteksi). Untuk severity dari rule
        # Splunk, lihat kolom Severity di sheet Rule Summary.
        priority_to_severity = {0: "Critical", 1: "High", 2: "Medium", 3: "Low"}
        severity_order = ["Critical", "High", "Medium", "Low", "Priority Kosong (Ivanti)"]

        inc = self.incident.copy()
        inc["Severity_Label"] = inc["Priority"].map(priority_to_severity).fillna("Priority Kosong (Ivanti)")

        breakdown = inc.groupby("Severity_Label").agg(Jumlah_Tiket=("Incident", "nunique")).reset_index()
        breakdown["Severity_Label"] = pd.Categorical(breakdown["Severity_Label"], categories=severity_order, ordered=True)
        breakdown = breakdown.sort_values("Severity_Label")
        breakdown["%"] = round(100 * breakdown["Jumlah_Tiket"] / breakdown["Jumlah_Tiket"].sum(), 1)

        self.severity_breakdown = breakdown.reset_index(drop=True)

    # =====================================================
    # DAILY TREND (BARU) - alert & insiden per tanggal dalam periode
    # =====================================================

    def build_daily_trend(self):
        print("Building Daily Trend...")

        alert = self.alert.copy()
        alert["_date"] = pd.to_datetime(alert["Alert Time"], errors="coerce").dt.date
        alert_daily = alert["_date"].value_counts().sort_index()

        inc_dates = pd.to_datetime(self.incident["Created On"], errors="coerce").dropna().dt.date
        inc_daily = inc_dates.value_counts().sort_index()

        all_dates = sorted(set(alert_daily.index) | set(inc_daily.index))

        # Rule kontributor terbesar tiap tanggal - supaya lonjakan bisa langsung
        # ditelusuri penyebabnya, bukan cuma angka totalnya.
        top_rule_per_day, top_rule_pct_per_day = [], []
        for d in all_dates:
            day_alerts = alert[alert["_date"] == d]
            if len(day_alerts) == 0:
                top_rule_per_day.append("-")
                top_rule_pct_per_day.append(0)
                continue
            top = day_alerts["Alert Name"].value_counts().iloc[0:1]
            if len(top) > 0:
                top_rule_per_day.append(top.index[0][:60])
                top_rule_pct_per_day.append(round(100 * top.iloc[0] / len(day_alerts), 1))
            else:
                top_rule_per_day.append("-")
                top_rule_pct_per_day.append(0)

        trend = pd.DataFrame({
            "Tanggal": all_dates,
            "Jumlah_Alert": [int(alert_daily.get(d, 0)) for d in all_dates],
            "Jumlah_Insiden": [int(inc_daily.get(d, 0)) for d in all_dates],
            "Rule_Kontributor_Terbesar": top_rule_per_day,
            "%_dari_Alert_Hari_Itu": top_rule_pct_per_day,
        })

        self.daily_trend = trend

        if len(trend) > 0:
            peak_alert_day = trend.loc[trend["Jumlah_Alert"].idxmax()]
            self.daily_trend_peak = (peak_alert_day["Tanggal"], int(peak_alert_day["Jumlah_Alert"]))
            self.daily_trend_peak_rule = (peak_alert_day["Rule_Kontributor_Terbesar"], peak_alert_day["%_dari_Alert_Hari_Itu"])
        else:
            self.daily_trend_peak = (None, 0)
            self.daily_trend_peak_rule = ("-", 0)

        # Periode > 10 hari (kira-kira bulanan) -> grafik tren UTAMA dipakai
        # mingguan, bukan harian (18-31 titik harian terlalu detail untuk
        # overview bulanan). Detail harian tetap tersedia di daily_trend untuk
        # drill-down (mis. menelusuri lonjakan tanggal tertentu).
        self.is_long_period = (
            self.period_start is not None and self.period_end is not None and
            (self.period_end - self.period_start).days > 10
        )

    # =====================================================
    # WEEKLY TREND (BARU) - agregasi mingguan untuk laporan bulanan
    # =====================================================

    def build_weekly_trend(self):
        print("Building Weekly Trend...")

        if self.daily_trend is None or len(self.daily_trend) == 0:
            self.weekly_trend = pd.DataFrame()
            return

        wt = self.daily_trend.copy()
        wt["_dt"] = pd.to_datetime(wt["Tanggal"])
        iso = wt["_dt"].dt.isocalendar()
        wt["Minggu"] = "W" + iso["week"].astype(str) + " (" + iso["year"].astype(str) + ")"

        agg = wt.groupby("Minggu", sort=False).agg(
            Jumlah_Alert=("Jumlah_Alert", "sum"),
            Jumlah_Insiden=("Jumlah_Insiden", "sum"),
            Tanggal_Mulai=("_dt", "min"),
            Tanggal_Selesai=("_dt", "max"),
        ).reset_index().sort_values("Tanggal_Mulai")

        # Rule kontributor terbesar per minggu (agregat dari alert mentah,
        # bukan cuma rule terbesar di 1 hari puncak).
        alert = self.alert.copy()
        alert["_dt"] = pd.to_datetime(alert["Alert Time"], errors="coerce")
        alert_iso = alert["_dt"].dt.isocalendar()
        alert["Minggu"] = "W" + alert_iso["week"].astype(str) + " (" + alert_iso["year"].astype(str) + ")"

        top_rule_per_week = []
        for wk in agg["Minggu"]:
            week_alerts = alert[alert["Minggu"] == wk]
            top = week_alerts["Alert Name"].value_counts().iloc[0:1]
            top_rule_per_week.append(top.index[0][:60] if len(top) > 0 else "-")
        agg["Rule_Kontributor_Terbesar"] = top_rule_per_week
        agg["Tanggal_Mulai"] = agg["Tanggal_Mulai"].dt.date
        agg["Tanggal_Selesai"] = agg["Tanggal_Selesai"].dt.date

        self.weekly_trend = agg

    # =====================================================
    # TASK SOC (BARU) - task pengecekan dari tim lain, tanpa insiden resmi
    # =====================================================

    def build_task_summary(self):
        print("Building Task Summary...")

        if self.task is None or len(self.task) == 0:
            self.task_summary = pd.DataFrame()
            self.task_by_owner = pd.DataFrame()
            self.task_by_requestor = pd.DataFrame()
            self.task_weekly_regularity = pd.DataFrame()
            self.task_unmatched_owner = pd.DataFrame()
            return

        t = self.task.copy()

        # Modul Task Ivanti pakai nama pendek/username (mis. "alif"), sementara
        # modul Incident pakai nama lengkap ("Alif Elang Abhipraya") - kalau
        # dibiarkan, KPI SOC akan pecah jadi baris terpisah untuk orang yang sama.
        # Cocokkan otomatis: short_name dianggap match kalau muncul sebagai KATA
        # UTUH (bukan substring sembarang) di salah satu nama Owner insiden.
        incident_owners = self.incident["Owner"].dropna().unique().tolist()

        def resolve_owner_name(short_name):
            if pd.isna(short_name):
                return short_name
            short_lower = str(short_name).strip().lower()
            matches = [o for o in incident_owners if short_lower in str(o).lower().split()]
            if len(matches) == 1:
                return matches[0]
            return short_name  # tidak ketemu match tunggal -> biarkan apa adanya, ditandai di bawah

        t["Owner_Raw"] = t["Owner"]
        t["Owner"] = t["Owner"].apply(resolve_owner_name)
        self.task_unmatched_owner = t[t["Owner"] == t["Owner_Raw"]][["Owner_Raw"]].drop_duplicates()
        if len(self.task_unmatched_owner) > 0:
            print(f"   [WARNING] {len(self.task_unmatched_owner)} nama Owner di Task tidak bisa "
                  f"dicocokkan otomatis ke nama lengkap di Incident: "
                  f"{self.task_unmatched_owner['Owner_Raw'].tolist()}")

        completed = t[t["Status"].astype(str).str.upper() == "COMPLETED"]
        avg_turnaround = completed["Turnaround_sec"].mean() if len(completed) > 0 else None

        # SLA breach - langsung dari kolom Ivanti (Response_meet/breach,
        # Resolution_meet/breach), BUKAN dihitung ulang.
        resp_breach = (t["Response_SLA"].astype(str).str.upper() == "BREACHED").sum()
        reso_breach = (t["Resolution_SLA"].astype(str).str.upper() == "BREACHED").sum()

        self.task_summary = pd.DataFrame([
            ["Total Task", len(t)],
            ["Completed", len(completed)],
            ["Belum Selesai", len(t) - len(completed)],
            ["Rata-rata Waktu Pengerjaan (jam)", round(avg_turnaround / 3600, 1) if avg_turnaround else "N/A"],
            ["Response SLA Breach", int(resp_breach)],
            ["Resolution SLA Breach", int(reso_breach)],
        ], columns=["Metrik", "Nilai"])

        self.task_by_owner = (
            t.dropna(subset=["Owner"])
            .groupby("Owner")
            .agg(
                Total_Task=("Task", "count"),
                Completed=("Status", lambda x: (x.astype(str).str.upper() == "COMPLETED").sum()),
                Response_Breach=("Response_SLA", lambda x: (x.astype(str).str.upper() == "BREACHED").sum()),
                Resolution_Breach=("Resolution_SLA", lambda x: (x.astype(str).str.upper() == "BREACHED").sum()),
            )
            .reset_index()
            .sort_values("Total_Task", ascending=False)
        )

        # Breakdown per tim peminta - cuma berguna kalau Requestor_Team beneran terisi
        # (bukan default "Tidak Diketahui" semua)
        if (t["Requestor_Team"] != "Tidak Diketahui").any():
            self.task_by_requestor = (
                t.groupby("Requestor_Team").agg(Total_Task=("Task", "count")).reset_index()
                .sort_values("Total_Task", ascending=False)
            )
        else:
            self.task_by_requestor = pd.DataFrame()

        # Regularitas: task per minggu ISO dalam periode ini - untuk lihat apakah
        # SOC rutin dapat task tiap minggu atau cuma sesekali/menumpuk.
        weeks = t["Created On"].dropna().dt.isocalendar().week
        weekly = weeks.value_counts().sort_index()
        self.task_weekly_regularity = pd.DataFrame({"Minggu_ke": weekly.index, "Jumlah_Task": weekly.values})

    # =====================================================
    # CTI FORTIRECON (BARU) - alert threat intel eksternal
    # =====================================================
    # KEAMANAN: kolom Password dari sumber SUDAH di-drop di loader.py, diganti
    # indikator Password_Leaked (bool) - nilai password asli TIDAK PERNAH sampai
    # ke tahap ini, apalagi ke laporan akhir.

    def build_cti_summary(self):
        print("Building CTI FortiRecon Summary...")

        if self.cti is None or len(self.cti) == 0:
            self.cti_summary = pd.DataFrame()
            self.cti_by_type = pd.DataFrame()
            self.cti_by_status = pd.DataFrame()
            self.cti_true_positive_rate = None
            return

        c = self.cti.copy()
        total = len(c)
        tp = (c["Verification_Result"].astype(str).str.strip().str.lower() == "true positive").sum()
        fp = (c["Verification_Result"].astype(str).str.strip().str.lower() == "false positive").sum()
        pending = total - tp - fp
        closed = (c["Status"].astype(str).str.strip().str.lower() == "closed").sum()
        in_progress = (c["Status"].astype(str).str.strip().str.lower() == "in progress").sum()
        password_leaked = int(c["Password_Leaked"].sum()) if "Password_Leaked" in c.columns else 0

        self.cti_summary = pd.DataFrame([
            ["Total Alert CTI", total],
            ["True Positive", int(tp)],
            ["False Positive", int(fp)],
            ["Belum Diverifikasi", int(pending)],
            ["Closed", int(closed)],
            ["In Progress", int(in_progress)],
            ["Kredensial Bocor Terdeteksi (indikator, bukan nilai)", password_leaked],
        ], columns=["Metrik", "Nilai"])

        self.cti_true_positive_rate = round(100 * tp / max(tp + fp, 1), 1)  # dari yang SUDAH diverifikasi saja

        self.cti_by_type = (
            c.groupby("Alert_Type").size().reset_index(name="Jumlah").sort_values("Jumlah", ascending=False)
        )
        self.cti_by_status = (
            c.groupby("Status").size().reset_index(name="Jumlah").sort_values("Jumlah", ascending=False)
        )

    def build_cti_trend(self):
        print("Building CTI Trend...")

        history_path = Path("database") / "cti_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        if self.cti is None or len(self.cti) == 0:
            snap_total, snap_tp = 0, 0
        else:
            c = self.cti
            snap_total = len(c)
            snap_tp = (c["Verification_Result"].astype(str).str.strip().str.lower() == "true positive").sum()

        snap = pd.DataFrame([{
            "Period": self.period_key,
            "Period_End": self.period_end,
            "Total_CTI_Alert": int(snap_total),
            "True_Positive": int(snap_tp),
        }])

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, snap], ignore_index=True)
        else:
            history = snap
        history = self._clean_period_history(history)
        history = history.drop_duplicates(subset=["Period", "Period_End"], keep="last")
        history.to_csv(history_path, index=False)

        self.cti_trend = history.sort_values("Period_End").reset_index(drop=True)

    # =====================================================
    # RULE SUMMARY  (FIXED: outer merge, tidak ada data hilang)
    # =====================================================

    def build_rule_summary(self):
        print("Building Rule Summary ...")

        # Severity mentah Splunk ternyata tidak selalu 1 kata bersih (ada nilai
        # gabungan "CRITICAL HIGH LOW MEDIUM", sampah "ERROR", bahkan angka) -
        # WAJIB distandarkan dulu sebelum dipakai di mana pun, termasuk untuk
        # perbandingan Severity vs Priority.
        self.alert["Severity_Std"] = self.alert["Severity"].apply(clean_severity)

        alert_summary = (
            self.alert.groupby("Normalized Rule")
            .agg(
                Alert_Count=("Alert Name", "count"),   # jumlah baris/notifikasi alert - INI yang dimaksud "total alert"
                Alert_Volume=("Total", "sum"),          # sum kolom Total: total raw log hits DI BALIK notifikasi (metrik sekunder, bukan "jumlah alert")
                Severity=("Severity_Std", lambda x: x.mode().iloc[0] if not x.mode().empty else "Unknown"),
                Last_Alert=("Alert Time", "max"),
                Alert_Matched=("Matched", "any"),
            )
            .reset_index()
        )

        incident_summary = (
            self.incident.groupby("Normalized Rule")
            .agg(
                Incident_Count=("Incident", "nunique"),
                Breach_Count=("_Breach", "sum"),
                Highest_Priority=("Priority", lambda x: x.dropna().min() if not x.dropna().empty else np.nan),
                Last_Incident=("Created On", "max"),
                Incident_Matched=("Matched", "any"),
            )
            .reset_index()
        )

        # Master bisa punya >1 baris dengan Normalized Rule yang sama (rule duplikat/typo -
        # lihat sheet Duplicate_Master). Kalau tidak di-dedupe dulu, outer merge akan
        # fan-out dan angka Alert_Count/Incident_Count jadi kelipatan (bug baru yang
        # sempat muncul saat testing: total alert 3038 padahal harusnya 3009).
        master_dedup = self.master.drop_duplicates(subset=["Normalized Rule"], keep="first")

        # OUTER merge berantai: master, alert_summary, incident_summary - tidak ada
        # baris yang hilang diam-diam meskipun rule-nya tidak dikenal master.
        summary = master_dedup.merge(alert_summary, on="Normalized Rule", how="outer")
        summary = summary.merge(incident_summary, on="Normalized Rule", how="outer")

        summary["In_Master"] = summary["Rule_ID"].notna()
        summary["Rule_Names"] = summary["Rule_Names"].fillna(summary["Normalized Rule"])
        summary["Rule_ID"] = summary["Rule_ID"].fillna("UNMAPPED")
        summary["Rule_Status"] = summary["Rule_Status"].fillna("Unknown (rule not in master)")

        for c in ["Alert_Count", "Alert_Volume", "Incident_Count", "Breach_Count"]:
            summary[c] = summary[c].fillna(0).astype(int)

        summary["Severity"] = summary["Severity"].fillna("Unknown")
        if "Security_Domain" in summary.columns:
            summary["Security_Domain"] = summary["Security_Domain"].fillna("Others")
            # Normalisasi CASE - "INFRASTRUCTURE" (dari CSV Splunk mentah) dan
            # "Infrastructure" (dari hasil keyword classifier lama) harus
            # dianggap domain YANG SAMA, bukan 2 domain berbeda. Title Case
            # dipilih supaya tetap enak dibaca di chart/laporan.
            summary["Security_Domain"] = summary["Security_Domain"].astype(str).str.strip().str.title()
            if "Security_Sub_Domain" not in summary.columns:
                summary["Security_Sub_Domain"] = "Others"
            else:
                summary["Security_Sub_Domain"] = summary["Security_Sub_Domain"].fillna("Others")
                summary["Security_Sub_Domain"] = summary["Security_Sub_Domain"].astype(str).str.strip().str.title()
        summary["Highest_Priority"] = summary["Highest_Priority"]
        summary["Last_Alert"] = summary["Last_Alert"]
        summary["Last_Incident"] = summary["Last_Incident"]

        summary["Detection_Rate"] = np.where(
            summary["Alert_Count"] == 0, 0,
            round((summary["Incident_Count"] / summary["Alert_Count"]) * 100, 2)
        )

        recommendation = []
        for _, row in summary.iterrows():
            if not row["In_Master"]:
                recommendation.append("Not in Master - needs mapping review")
            elif row["Alert_Count"] == 0 and row["Incident_Count"] == 0:
                recommendation.append("Dormant")
            elif row["Alert_Count"] >= NOISE_ALERT_THRESHOLD and row["Incident_Count"] == 0:
                recommendation.append("Noise")
            elif row["Detection_Rate"] < TUNE_THRESHOLD:
                recommendation.append("Critical Tuning")
            elif row["Detection_Rate"] < REVIEW_THRESHOLD:
                recommendation.append("Need Tuning")
            elif row["Detection_Rate"] < KEEP_THRESHOLD:
                recommendation.append("Review")
            elif row["Detection_Rate"] < HEALTHY_THRESHOLD:
                recommendation.append("Acceptable")
            else:
                recommendation.append("Healthy")
        summary["Recommendation"] = recommendation

        self.rule_summary = summary

        print()
        print("Rule Summary Created")
        print(f"Total Rule Rows : {len(summary)} (termasuk {(~summary['In_Master']).sum()} rule di luar master)")
        print(f"Alert Total (notifikasi)   : {summary['Alert_Count'].sum()} (raw jumlah baris alert={len(self.alert)} - harus sama)")
        print(f"Alert Total (volume/Total) : {summary['Alert_Volume'].sum()} (raw alert.Total.sum()={self.alert['Total'].sum()} - harus sama)")
        print(f"Incident Total  : {summary['Incident_Count'].sum()} (unique incident asli={self.incident['Incident'].nunique()} - harus sama)")

    # =====================================================
    # EXECUTIVE SUMMARY
    # =====================================================

    def build_executive_summary(self):
        print("Building Executive Summary...")

        rs = self.rule_summary
        status = rs["Rule_Status"].astype(str).str.upper()
        gap_rules = rs[(rs["Alert_Count"] > 0) & (rs["Incident_Count"] == 0)]
        tuning_rules = rs["Recommendation"].isin(["Critical Tuning", "Need Tuning", "Review"])

        dashboard = []
        dashboard.append(["Periode", "Periode Laporan", self.period_label_text.replace("periode ", "")])

        # --- Grup 1: Splunk vs Ivanti (Master Rules digabung ke sini) ---
        dashboard.append(["1. Ticket", "Rule Splunk Active", len(rs[status == "ENABLED"])])
        dashboard.append(["1. Ticket", "Belum Ter-mapping (rule asing)", int((~rs["In_Master"]).sum())])
        dashboard.append(["1. Ticket", "Total Alert Splunk (notifikasi)", int(rs["Alert_Count"].sum())])
        dashboard.append(["1. Ticket", "Total Insiden Ivanti (dari Splunk)", int(rs["Incident_Count"].sum())])
        dashboard.append(["1. Ticket", "Gap: Rule Ada Alert TAPI 0 Tiket", len(gap_rules)])
        dashboard.append(["1. Ticket", "Noise Rules (alert banyak, 0 tiket)", len(rs[rs["Recommendation"] == "Noise"])])
        dashboard.append(["1. Ticket", "Dormant Rules (tidak trigger sama sekali)", len(rs[rs["Recommendation"] == "Dormant"])])
        dashboard.append(["1. Ticket", "Rules Butuh Tuning (Critical/Need/Review)", int(tuning_rules.sum())])
        dashboard.append([
            "1. Ticket", "Detection Rate",
            f"{round((rs['Incident_Count'].sum() / max(rs['Alert_Count'].sum(), 1)) * 100, 2)}%"
        ])

        # --- Grup 2: Non-Splunk vs Ivanti ---
        if self.nonsplunk is not None and len(self.nonsplunk) > 0:
            total_ns = len(self.nonsplunk)
            ns_ticket = int((self.nonsplunk["Ticket_Status_Flag"] == "Y").sum())
            ns_not_ticket = int((self.nonsplunk["Ticket_Status_Flag"] == "N").sum())
            ns_unverified = int((self.nonsplunk["Ticket_Status_Flag"] == "BELUM DIVERIFIKASI").sum())
            dashboard.append(["2. Non-Splunk vs Ivanti", "Total Alert Non-Splunk (Akamai/CSPM/Defender)", total_ns])
            dashboard.append(["2. Non-Splunk vs Ivanti", "Jadi Tiket Ivanti", ns_ticket])
            dashboard.append(["2. Non-Splunk vs Ivanti", "Gap: Tidak Jadi Tiket", ns_not_ticket])
            dashboard.append(["2. Non-Splunk vs Ivanti", "Belum Diverifikasi Y/N", ns_unverified])

        # --- Grup 3: Task dari Tim Lain (kerja "tak resmi", tanpa insiden ter-assign) ---
        if self.task is not None and len(self.task) > 0:
            t_completed = (self.task["Status"].astype(str).str.upper() == "COMPLETED").sum()
            dashboard.append(["3. Task dari Tim Lain", "Total Task Diterima", len(self.task)])
            dashboard.append(["3. Task dari Tim Lain", "Completed", int(t_completed)])
            dashboard.append(["3. Task dari Tim Lain", "Belum Selesai", len(self.task) - int(t_completed)])
            if len(self.task_weekly_regularity) > 0:
                dashboard.append(["3. Task dari Tim Lain", "Rata-rata Task per Minggu",
                                   round(self.task_weekly_regularity["Jumlah_Task"].mean(), 1)])

        # dtype=object eksplisit - kalau tidak, pandas akan memaksa SEMUA nilai di
        # kolom Value jadi float64 hanya karena ada 1 baris persentase, sehingga
        # semua angka bulat lain ikut tampil "535.0" dst padahal aslinya integer.
        groups = [row[0] for row in dashboard]
        metrics = [row[1] for row in dashboard]
        values = pd.Series([row[2] for row in dashboard], dtype=object)
        self.executive = pd.DataFrame({"Group": groups, "Metric": metrics, "Value": values})

    # =====================================================
    # TOP RULE
    # =====================================================

    def build_top_rule(self):
        print("Building Top Rule...")
        self.top_rule = (
            self.rule_summary
            .sort_values(["Incident_Count", "Alert_Count"], ascending=False)
            [["Rule_ID", "Rule_Names", "Severity", "Alert_Count", "Alert_Volume", "Incident_Count",
              "Detection_Rate", "Recommendation", "In_Master"]]
            .head(20)
        )

    def build_noise(self):
        self.noise = self.rule_summary[self.rule_summary["Recommendation"] == "Noise"]

    def build_tuning(self):
        self.tuning = self.rule_summary[
            self.rule_summary["Recommendation"].isin(["Critical Tuning", "Need Tuning", "Review"])
        ]

    def build_dormant(self):
        self.dormant = self.rule_summary[self.rule_summary["Recommendation"] == "Dormant"]

    def build_unmapped(self):
        self.unmapped = self.rule_summary[~self.rule_summary["In_Master"]][
            ["Normalized Rule", "Rule_Names", "Alert_Count", "Incident_Count"]
        ].sort_values("Alert_Count", ascending=False)

    # =====================================================
    # SOC INDIVIDUAL KPI (BARU)
    # =====================================================

    # =====================================================
    # SLA METRICS (BARU) - state machine: Logged -> Active -> Contained -> Resolved
    # =====================================================
    # MTTD = kejadian -> Logged (proxy: Alert Time Splunk -> Created On Ivanti)
    # MTTR = Logged -> Active (proxy: Created On -> Responded On, SAMA dengan
    #        MTTR yang sudah dipakai di KPI SOC selama ini - definisinya cocok)
    # MTTC = Active -> Contained - BELUM BISA DIHITUNG, tidak ada kolom
    #        timestamp "Contained" terpisah di data Ivanti (masih dicek ke
    #        tim Ivanti) - kolom disiapkan tapi diisi None + catatan jelas.
    # MTTRV = Active/Contained -> Resolved (proxy: Responded On -> Resolved On)

    def build_sla_metrics(self):
        print("Building SLA Metrics (MTTD/MTTR/MTTC/MTTRV)...")

        inc = self.incident.drop_duplicates(subset=["Incident"]).copy()
        priority_label = {0: "P0-Critical", 1: "P1-High", 2: "P2-Medium", 3: "P3-Low"}
        inc["Priority_Label"] = inc["Priority"].map(priority_label)

        # --- MTTR: prioritaskan "Duration Active (Minutes)" yang SUDAH DIHITUNG
        # Ivanti sendiri (skema baru) - lebih akurat daripada dihitung ulang dari
        # Created On/Responded On. Fallback ke cara lama kalau kolom itu tidak ada
        # (skema lama/format lain).
        if "Duration Active (Minutes)" in inc.columns:
            inc["MTTR_sec"] = pd.to_numeric(inc["Duration Active (Minutes)"], errors="coerce") * 60
        elif "Responded On" in inc.columns:
            inc["MTTR_sec"] = (inc["Responded On"] - inc["Created On"]).dt.total_seconds().clip(lower=0)
        else:
            inc["MTTR_sec"] = None

        # --- MTTD: skema BARU Ivanti TIDAK PUNYA kolom "Alert Time" / timestamp
        # kejadian terpisah lagi - MTTD jadi TIDAK BISA dihitung dari data ini,
        # kecuali skema lama (Alert Time) masih ada.
        if "Alert Time" in inc.columns:
            raw_alert_time = inc["Alert Time"].astype(str)
            try:
                parsed_full = pd.to_datetime(raw_alert_time, errors="coerce", format="mixed")
            except Exception:
                parsed_full = pd.to_datetime(raw_alert_time, errors="coerce")
            if not pd.api.types.is_datetime64_any_dtype(parsed_full):
                parsed_full = pd.to_datetime(pd.Series(parsed_full, index=inc.index), errors="coerce")
            if pd.api.types.is_datetime64_any_dtype(parsed_full) and pd.api.types.is_datetime64_any_dtype(inc["Created On"]):
                day_diff = (parsed_full.dt.normalize() - inc["Created On"].dt.normalize()).dt.days.abs()
                suspicious = parsed_full.isna() | (day_diff > 3)
                if suspicious.any():
                    time_str = raw_alert_time.str.extract(r'(\d{1,2}:\d{2}(?::\d{2})?)')[0]
                    combined_str = inc["Created On"].dt.strftime("%Y-%m-%d") + " " + time_str
                    combined = pd.to_datetime(combined_str, errors="coerce")
                    parsed_full = parsed_full.where(~suspicious, combined)
                inc["_AlertTime"] = parsed_full
                inc["MTTD_sec"] = (inc["Created On"] - inc["_AlertTime"]).dt.total_seconds()
                inc.loc[(inc["MTTD_sec"] < 0) | (inc["MTTD_sec"] > 3 * 86400), "MTTD_sec"] = None
            else:
                inc["MTTD_sec"] = None
        else:
            inc["MTTD_sec"] = None

        inc["MTTC_sec"] = None  # placeholder - kolom "Contained" masih belum ada di skema manapun yang pernah diupload

        # --- MTTRV/Resolution: prioritaskan "Duration Resolved (Minutes)" yang
        # SUDAH DIHITUNG Ivanti (Created On -> Resolved On, per definisi user).
        if "Duration Resolved (Minutes)" in inc.columns:
            inc["MTTRV_sec"] = pd.to_numeric(inc["Duration Resolved (Minutes)"], errors="coerce") * 60
        elif "Resolved On" in inc.columns and "Responded On" in inc.columns:
            inc["MTTRV_sec"] = (inc["Resolved On"] - inc["Responded On"]).dt.total_seconds().clip(lower=0)
        else:
            inc["MTTRV_sec"] = None

        # --- Breach: pakai _Breach yang sudah dihitung terpusat (konsisten
        # di semua skema data - lihat _compute_incident_breach_flag()).
        has_precomputed_breach = "FlagBreachResponse" in inc.columns or "FlagBreachResolution" in inc.columns
        inc["_AnyBreach"] = inc["_Breach"]

        overall = pd.DataFrame([{
            "Priority_Label": "SEMUA",
            "Jumlah_Tiket": len(inc),
            "Avg_MTTD_menit": round(inc["MTTD_sec"].mean() / 60, 1) if inc["MTTD_sec"].notna().any() else "Belum ada data",
            "Avg_MTTR_menit": round(inc["MTTR_sec"].mean() / 60, 1) if inc["MTTR_sec"].notna().any() else None,
            "Avg_MTTC_menit": "Menunggu data",
            "Avg_MTTRV_menit": round(inc["MTTRV_sec"].mean() / 60, 1) if inc["MTTRV_sec"].notna().any() else None,
            "Jumlah_Breach": int(inc["_AnyBreach"].sum()),
            "%_Breach": round(100 * inc["_AnyBreach"].mean(), 1),
        }])

        per_tier = inc.groupby("Priority_Label").agg(
            Jumlah_Tiket=("Incident", "count"),
            Avg_MTTD_menit=("MTTD_sec", lambda x: round(x.mean() / 60, 1) if x.notna().any() else "Belum ada data"),
            Avg_MTTR_menit=("MTTR_sec", lambda x: round(x.mean() / 60, 1) if x.notna().any() else None),
            Avg_MTTRV_menit=("MTTRV_sec", lambda x: round(x.mean() / 60, 1) if x.notna().any() else None),
            Jumlah_Breach=("_AnyBreach", "sum"),
        ).reset_index()
        per_tier["%_Breach"] = round(100 * per_tier["Jumlah_Breach"] / per_tier["Jumlah_Tiket"].clip(lower=1), 1)
        per_tier["Avg_MTTC_menit"] = "Menunggu data"
        per_tier = per_tier[["Priority_Label", "Jumlah_Tiket", "Avg_MTTD_menit", "Avg_MTTR_menit",
                              "Avg_MTTC_menit", "Avg_MTTRV_menit", "Jumlah_Breach", "%_Breach"]]

        self.sla_metrics = pd.concat([overall, per_tier], ignore_index=True)
        self.sla_metrics_note = (
            "MTTC (Mean Time To Contain) BELUM bisa dihitung - tidak ada kolom timestamp "
            "'Contained' terpisah di data Ivanti yang tersedia saat ini. "
            + ("Breach dihitung dari flag yang SUDAH DITENTUKAN Ivanti sendiri (FlagBreachResponse/"
               "FlagBreachResolution), bukan threshold tebakan." if has_precomputed_breach else
               "Breach dihitung pakai threshold internal (data belum punya flag breach dari Ivanti).")
        )
        self.sla_has_precomputed_breach = has_precomputed_breach

    def build_soc_individual_kpi(self):
        print("Building SOC Individual KPI...")

        inc = self.incident.dropna(subset=["Owner"]).copy()

        # --- MTTR & MTTRV: prioritaskan kolom yang SUDAH DIHITUNG Ivanti
        # (skema baru) - fallback ke hitung manual (skema lama) kalau tidak ada.
        if "Duration Active (Minutes)" in inc.columns:
            inc["MTTR_sec"] = pd.to_numeric(inc["Duration Active (Minutes)"], errors="coerce") * 60
        elif "Responded On" in inc.columns:
            inc["MTTR_sec"] = (inc["Responded On"] - inc["Created On"]).dt.total_seconds()
        else:
            inc["MTTR_sec"] = None

        # PENTING: MTTRV (Responded/Active -> Resolved) BUKAN MTTC (Contain) -
        # penamaan ini sudah diluruskan sesuai state machine resmi dari
        # management. MTTC yang SEBENARNYA belum bisa dihitung - lihat catatan
        # di build_sla_metrics().
        if "Duration Resolved (Minutes)" in inc.columns:
            inc["MTTRV_sec"] = pd.to_numeric(inc["Duration Resolved (Minutes)"], errors="coerce") * 60
            inc["Total_Resolution_sec"] = inc["MTTRV_sec"]  # skema baru: Duration Resolved = Created->Resolved langsung
        elif "Responded On" in inc.columns:
            inc["MTTRV_sec"] = (inc["Resolved On"] - inc["Responded On"]).dt.total_seconds()
            inc["Total_Resolution_sec"] = (inc["Resolved On"] - inc["Created On"]).dt.total_seconds()
        else:
            inc["MTTRV_sec"] = None
            inc["Total_Resolution_sec"] = None

        # --- Breach: pakai _Breach yang sudah dihitung terpusat di
        # _compute_incident_breach_flag() (konsisten di semua skema data).
        kpi = (
            inc.groupby("Owner")
            .agg(
                Total_Incident=("Incident", "count"),
                Breach=("_Breach", "sum"),
                Avg_MTTR_sec=("MTTR_sec", "mean"),
                Median_MTTR_sec=("MTTR_sec", "median"),
                Avg_MTTRV_sec=("MTTRV_sec", "mean"),
                Avg_Resolution_sec=("Total_Resolution_sec", "mean"),
            )
            .reset_index()
        )

        total_incident_all = kpi["Total_Incident"].sum()
        kpi["Workload_Share_%"] = round(kpi["Total_Incident"] / max(total_incident_all, 1) * 100, 1)
        kpi["Breach_Rate_%"] = round(kpi["Breach"] / kpi["Total_Incident"] * 100, 2)
        kpi["Within_SLA_MTTR"] = kpi["Avg_MTTR_sec"] <= SLA_MTTR_SECONDS
        kpi["Avg_MTTC_sec"] = "Menunggu data"  # placeholder eksplisit, bukan dihitung salah

        for c in ["Avg_MTTR_sec", "Median_MTTR_sec", "Avg_MTTRV_sec", "Avg_Resolution_sec"]:
            kpi[c] = kpi[c].round(1)

        # Gabungkan Task_Count (kerja "tak resmi" dari tim lain) supaya beban kerja
        # SEBENARNYA kelihatan, bukan cuma insiden ter-assign resmi.
        if hasattr(self, "task_by_owner") and len(self.task_by_owner) > 0:
            kpi = kpi.merge(
                self.task_by_owner[["Owner", "Total_Task"]], on="Owner", how="outer"
            )
            kpi["Total_Incident"] = kpi["Total_Incident"].fillna(0).astype(int)
            kpi["Total_Task"] = kpi["Total_Task"].fillna(0).astype(int)
            kpi["Total_Workload (Insiden+Task)"] = kpi["Total_Incident"] + kpi["Total_Task"]
        else:
            kpi["Total_Task"] = 0
            kpi["Total_Workload (Insiden+Task)"] = kpi["Total_Incident"]

        self.soc_individual_kpi = kpi.sort_values("Total_Workload (Insiden+Task)", ascending=False)

    # =====================================================
    # PRIORITY  (FIXED: Priority numeric, bukan string "P1")
    # =====================================================

    def build_priority(self):
        print("Building Priority...")

        priority = (
            self.incident.dropna(subset=["Priority"])
            .groupby("Priority")
            .agg(Total=("Incident", "nunique"))
            .reset_index()
            .sort_values("Priority")
        )
        priority["Priority_Label"] = "P" + priority["Priority"].astype(int).astype(str)
        self.priority = priority

    def build_breach(self):
        print("Building Breach...")
        breach = self.incident.copy()
        breach = breach[breach["_Breach"]]
        breach = breach.drop_duplicates(subset=["Incident"])
        if "Created On" in breach.columns:
            breach = breach.sort_values(["Priority", "Created On"], ascending=[True, False])
        self.breach = breach.reset_index(drop=True)

    def build_analyst(self):
        # dipertahankan untuk kompatibilitas versi lama; SOC Individual KPI (di atas)
        # adalah versi lebih lengkap dan menggantikan sheet ini di report final.
        analyst = (
            self.incident.dropna(subset=["Owner"])
            .groupby("Owner")
            .agg(
                Total_Incident=("Incident", "count"),
                Breach=("_Breach", "sum"),
            )
            .reset_index()
        )
        analyst["Breach Rate"] = round(analyst["Breach"] / analyst["Total_Incident"] * 100, 2)
        self.analyst = analyst.sort_values("Total_Incident", ascending=False)

    # =====================================================
    # RULE STATUS DISTRIBUTION (BARU) - untuk chart persentase Bab 1 & 2
    # =====================================================

    def build_rule_status_distribution(self):
        print("Building Rule Status Distribution...")

        rs = self.rule_summary

        # Bab 1: Enabled vs Disabled vs Unmapped (dari sisi Master Rules Database)
        status = rs["Rule_Status"].astype(str).str.upper()
        self.master_status_distribution = pd.DataFrame({
            "Status": ["Enabled", "Disabled", "Belum Ter-mapping"],
            "Jumlah": [
                int((status == "ENABLED").sum()),
                int((status == "DISABLED").sum()),
                int((~rs["In_Master"]).sum()),
            ],
        })
        total_m = self.master_status_distribution["Jumlah"].sum()
        self.master_status_distribution["%"] = round(100 * self.master_status_distribution["Jumlah"] / max(total_m, 1), 1)

        # Bab 2: distribusi Recommendation (Healthy/Acceptable/Noise/Tuning/dst)
        rec_counts = rs["Recommendation"].value_counts().reset_index()
        rec_counts.columns = ["Recommendation", "Jumlah"]
        rec_counts["%"] = round(100 * rec_counts["Jumlah"] / max(rec_counts["Jumlah"].sum(), 1), 1)
        self.rule_recommendation_distribution = rec_counts

    # =====================================================
    # NON-SPLUNK COVERAGE (BARU)
    # =====================================================

    def build_nonsplunk_coverage(self):
        print("Building NonSplunk Coverage...")

        if self.nonsplunk is None or len(self.nonsplunk) == 0:
            self.nonsplunk_coverage = pd.DataFrame(
                columns=["Source_Device", "Total_Alert", "Jadi_Tiket", "Tidak_Jadi_Tiket",
                         "Belum_Diverifikasi", "Coverage_%"]
            )
            self.nonsplunk_detail = pd.DataFrame()
            self.nonsplunk_partial_note = None
            return

        ns = self.nonsplunk.copy()

        cov = (
            ns.groupby("Source_Device")
            .agg(
                Total_Alert=("Source_Device", "count"),
                Jadi_Tiket=("Ticket_Status_Flag", lambda x: (x == "Y").sum()),
                Tidak_Jadi_Tiket=("Ticket_Status_Flag", lambda x: (x == "N").sum()),
                Belum_Diverifikasi=("Ticket_Status_Flag", lambda x: (x == "BELUM DIVERIFIKASI").sum()),
            )
            .reset_index()
        )
        cov["Coverage_%"] = round(cov["Jadi_Tiket"] / cov["Total_Alert"] * 100, 1)

        # CTI Advisory - SUBSET dari Tidak_Jadi_Tiket (N), BUKAN kategori tambahan
        # (kalau dijumlah manual: Total = Jadi_Tiket + Tidak_Jadi_Tiket + Belum_Diverifikasi,
        # CTI dan Gap_Murni adalah RINCIAN dari Tidak_Jadi_Tiket saja).
        if "Reason" in ns.columns:
            cti_mask = ns["Reason"].astype(str).str.contains("CTI", case=False, na=False)
            not_ticket_mask = ns["Ticket_Status_Flag"] == "N"
            cov = cov.merge(
                ns[not_ticket_mask].groupby("Source_Device").apply(
                    lambda g: pd.Series({
                        "CTI_dari_N": g["Reason"].astype(str).str.contains("CTI", case=False, na=False).sum(),
                    })
                ).reset_index(),
                on="Source_Device", how="left"
            )
            cov["CTI_dari_N"] = cov["CTI_dari_N"].fillna(0).astype(int)
            cov["Gap_Murni_dari_N"] = cov["Tidak_Jadi_Tiket"] - cov["CTI_dari_N"]
        else:
            cov["CTI_dari_N"] = 0
            cov["Gap_Murni_dari_N"] = cov["Tidak_Jadi_Tiket"]

        self.nonsplunk_coverage = cov
        self.nonsplunk_detail = ns

        # -------------------------------------------------
        # Deteksi PARTIAL PERIOD: bandingkan tanggal awal data non-Splunk vs
        # tanggal awal data Splunk di periode yang sama. Kalau non-Splunk mulai
        # BELAKANGAN (mis. baru mulai di-list pertengahan minggu/bulan), tandai
        # eksplisit supaya tidak disalahartikan sebagai "sepi alert".
        # -------------------------------------------------
        self.nonsplunk_partial_note = None

        ns_dates = ns["Alert_Time_Std"].dropna()
        splunk_dates = pd.to_datetime(self.alert["Alert Time"], errors="coerce").dropna()

        if len(ns_dates) > 0 and len(splunk_dates) > 0:
            ns_min, ns_max = ns_dates.min(), ns_dates.max()
            splunk_min, splunk_max = splunk_dates.min(), splunk_dates.max()

            gap_days_start = (ns_min - splunk_min).days
            gap_days_end = (splunk_max - ns_max).days

            if gap_days_start > 1 or gap_days_end > 1:
                self.nonsplunk_partial_note = (
                    f"PERINGATAN DATA PARTIAL: periode Splunk = {splunk_min.date()} s/d {splunk_max.date()}, "
                    f"tapi data alert non-Splunk cuma tersedia {ns_min.date()} s/d {ns_max.date()} "
                    f"({gap_days_start} hari di awal periode TIDAK ter-cover). "
                    "Angka coverage/total di sheet Nonsplunk Coverage BUKAN representasi 1 periode penuh - "
                    "jangan dibandingkan langsung ke periode berikutnya sampai tracking sudah konsisten dari hari pertama."
                )
                print(f"   [WARNING] {self.nonsplunk_partial_note}")

    # =====================================================
    # SECURITY DOMAIN (FIXED: keyword diurutkan pakai kolom Priority)
    # =====================================================

    def build_domain(self):
        print("Building Security Domain...")

        rs = self.rule_summary.copy()

        # Sekarang Security_Domain/Security_Sub_Domain SUDAH ikut dari Master_Rules_Splunk.xlsx
        # (kolom permanen, hasil klasifikasi keyword yang dilakukan SEKALI saat rule didaftarkan -
        # bukan dihitung ulang tiap laporan). Ini yang membuat klasifikasi domain KONSISTEN dari
        # minggu ke minggu / bulan ke bulan, bukan berubah-ubah tergantung urutan keyword.
        if "Security_Domain" not in rs.columns:
            rs["Security_Domain"] = "Others"
            rs["Security_Sub_Domain"] = "Others"

        # Fallback: keyword matching HANYA untuk rule yang belum terklasifikasi ("Others") atau
        # rule baru yang belum sempat ditambahkan Security_Domain-nya di Master_Rules_Splunk.xlsx.
        # Kalau ini sering muncul, sebaiknya kolom Security_Domain di master di-update manual.
        need_fallback = rs["Security_Domain"].isin(["Others", None]) | rs["Security_Domain"].isna()
        if need_fallback.any() and self.domain is not None and len(self.domain) > 0:
            keyword = self.domain.copy()
            if "Priority" in keyword.columns:
                keyword["Priority"] = pd.to_numeric(keyword["Priority"], errors="coerce")
                keyword = keyword.dropna(subset=["Priority", "Keyword"]).sort_values("Priority", ascending=False)

            for _, row in keyword.iterrows():
                mask = need_fallback & rs["Rule_Names"].astype(str).str.contains(str(row["Keyword"]), case=False, na=False)
                rs.loc[mask, "Security_Domain"] = row["Security_Domain"]
                rs.loc[mask, "Security_Sub_Domain"] = row["Security_Sub_Domain"]

        self.rule_summary = rs

        self.domain_summary = (
            rs.groupby("Security_Domain")
            .agg(Alert=("Alert_Count", "sum"), Incident=("Incident_Count", "sum"))
            .reset_index()
            .sort_values("Incident", ascending=False)
        )

    # =====================================================
    # DOMAIN x RECOMMENDATION (BARU) - domain mana paling butuh tuning
    # =====================================================

    def build_domain_recommendation(self):
        print("Building Domain x Recommendation...")

        rs = self.rule_summary
        self.domain_recommendation = (
            rs.groupby(["Security_Domain", "Recommendation"]).size()
            .unstack(fill_value=0).reset_index()
        )
        risky_cols = [c for c in ["Noise", "Critical Tuning", "Need Tuning", "Review"] if c in self.domain_recommendation.columns]
        if risky_cols:
            self.domain_recommendation["Total_Perlu_Tuning"] = self.domain_recommendation[risky_cols].sum(axis=1)
            self.domain_recommendation = self.domain_recommendation.sort_values("Total_Perlu_Tuning", ascending=False)

    # =====================================================
    # HYPOTHESIS-DRIVEN INSIGHT (BARU)
    # Menjawab pertanyaan gap-analysis yang dibahas sebelumnya, bukan cuma angka.
    # =====================================================

    # =====================================================
    # ADVANCED #5: THREAT PROFILING per P1/P2/P3
    # =====================================================
    # "Asset" di-proxy-kan ke Security_Domain (tidak ada data inventaris aset
    # sungguhan di export Splunk/Ivanti). "Target" pakai Customer (PIC tujuan
    # tiket). "Pola serangan" = rule yang sama berulang di 1 tier priority.

    def build_threat_profiling(self):
        print("Building Threat Profiling...")

        priority_label = {0: "P0-Critical", 1: "P1-High", 2: "P2-Medium", 3: "P3-Low"}
        inc = self.incident.dropna(subset=["Priority"]).copy()
        inc["Priority_Label"] = inc["Priority"].map(priority_label)

        rs_domain = self.rule_summary[["Normalized Rule", "Security_Domain"]]
        inc = inc.merge(rs_domain, on="Normalized Rule", how="left")
        inc["Security_Domain"] = inc["Security_Domain"].fillna("Others")

        # Top rule (threat) per tier priority
        _threat_col = "Summary" if "Summary" in inc.columns else "Normalized Rule"
        self.threat_by_priority = (
            inc.groupby(["Priority_Label", _threat_col]).size().reset_index(name="Jumlah")
            .rename(columns={_threat_col: "Summary"})
            .sort_values(["Priority_Label", "Jumlah"], ascending=[True, False])
            .groupby("Priority_Label").head(5).reset_index(drop=True)
        )

        # Domain (proxy asset) paling sering kena per tier priority
        if len(inc) > 0:
            self.threat_by_priority_domain = inc.pivot_table(
                index="Security_Domain", columns="Priority_Label", values="Incident",
                aggfunc="count", fill_value=0
            ).reset_index()
        else:
            self.threat_by_priority_domain = pd.DataFrame()

        # Versi PARALEL pakai kolom 'Security Domain' LANGSUNG dari Ivanti
        # (bukan keyword-mapping) - TERPISAH, sesuai arahan user "pakai
        # keduanya terpisah untuk tujuan berbeda". Ini yang harus dicek
        # kalau versi keyword-mapping di atas "Others" semua karena
        # 'Summary' tidak ada di file.
        if "Security Domain" in self.incident.columns and len(inc) > 0:
            inc_direct = self.incident.dropna(subset=["Priority"]).copy()
            inc_direct["Priority_Label"] = inc_direct["Priority"].map(priority_label)
            inc_direct["_SD_Direct"] = inc_direct["Security Domain"].astype(str).str.strip().str.title()
            inc_direct["_SD_Direct"] = inc_direct["_SD_Direct"].replace({"Nan": "Tidak Diketahui", "": "Tidak Diketahui"})
            self.threat_by_priority_domain_direct = inc_direct.pivot_table(
                index="_SD_Direct", columns="Priority_Label", values="Incident",
                aggfunc="count", fill_value=0
            ).reset_index().rename(columns={"_SD_Direct": "Security_Domain"})
        else:
            self.threat_by_priority_domain_direct = pd.DataFrame()

        # Target (proxy asset) paling sering kena per tier priority - exclude akun sistem
        def is_system_account(name):
            name = str(name).strip()
            parts = name.split()
            if len(parts) == 2 and parts[0].lower() == parts[1].lower():
                return True
            return "alert" in name.lower() or "team" in name.lower()

        inc_person = inc.dropna(subset=["Customer"]).copy()
        inc_person = inc_person[~inc_person["Customer"].apply(is_system_account)]
        self.threat_by_priority_target = (
            inc_person.groupby(["Priority_Label", "Customer"]).size().reset_index(name="Jumlah")
            .sort_values(["Priority_Label", "Jumlah"], ascending=[True, False])
            .groupby("Priority_Label").head(3).reset_index(drop=True)
        )

        # Subject (Internal/External) - BARU, dari kolom "Incident Type" yang
        # baru ada di skema Ivanti terbaru (mis. "Internal - Cybersecurity",
        # "Informational - Cybersecurity"). Dicek apakah teksnya mengandung
        # kata "internal"/"external" - kalau tidak ada indikasi sama sekali,
        # masuk "Tidak Diketahui" (JUJUR, bukan ditebak).
        if "Incident Type" in inc.columns:
            def classify_internal_external(v):
                s = str(v).lower()
                if "internal" in s:
                    return "Internal"
                if "external" in s:
                    return "External"
                return "Tidak Diketahui"
            inc["_Subject_Origin"] = inc["Incident Type"].apply(classify_internal_external)
            self.subject_internal_external = (
                inc.groupby("_Subject_Origin").size().reset_index(name="Jumlah")
                .sort_values("Jumlah", ascending=False)
            )
        else:
            self.subject_internal_external = pd.DataFrame()

    # =====================================================
    # ATTACK PATTERN TREND (BARU) - tracking Internal/External LINTAS BULAN,
    # bukan cuma snapshot 1 periode - sesuai masukan management: "masukin
    # data perbulan historical untuk melihat tren attack" (strategic view
    # untuk laporan bulanan, bukan cuma angka 1 bulan berdiri sendiri).
    # =====================================================

    def build_attack_pattern_trend(self):
        print("Building Attack Pattern Trend...")

        history_path = Path("database") / "attack_pattern_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        if self.subject_internal_external is None or len(self.subject_internal_external) == 0:
            snap = pd.DataFrame([{"Period": self.period_key, "Period_End": self.period_end,
                                   "_Subject_Origin": "Tidak Diketahui", "Jumlah": 0}])
        else:
            snap = self.subject_internal_external.copy()
            snap["Period"] = self.period_key
            snap["Period_End"] = self.period_end

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, snap], ignore_index=True)
        else:
            history = snap
        history = self._clean_period_history(history)
        history = history.drop_duplicates(subset=["Period", "Period_End", "_Subject_Origin"], keep="last")
        history.to_csv(history_path, index=False)

        self.attack_pattern_trend = (
            history.pivot_table(index="Period", columns="_Subject_Origin", values="Jumlah",
                                 aggfunc="sum", fill_value=0)
        )
        period_order = history[["Period", "Period_End"]].drop_duplicates().sort_values("Period_End")["Period"]
        self.attack_pattern_trend = self.attack_pattern_trend.reindex(period_order).reset_index()
        self.attack_pattern_trend_period_count = len(period_order)

    # =====================================================
    # HELPER: bersihkan histori dari duplikat "Period" LEGACY - kasus dari
    # SEBELUM period_key diperbaiki (baris lama tersimpan pakai teks tanggal
    # otomatis "periode 31 May - 30 Jun 2026", baris baru pakai label bersih
    # "2026-06" - padahal Period_End-nya SAMA PERSIS, seharusnya 1 periode).
    # Dipanggil di SEMUA history reader (Monthly Comparison, Severity Trend,
    # Attack Surface, Recurring Findings) supaya konsisten.
    # =====================================================

    @staticmethod
    def _clean_period_history(history):
        if "Period_End" not in history.columns or len(history) == 0:
            return history
        canonical = {}
        for period_end, group in history.groupby("Period_End"):
            labels = group["Period"].astype(str).unique().tolist()
            # Prioritaskan label yang TIDAK diawali "periode " (itu tanda teks
            # tanggal otomatis lama) - kalau semua berawalan itu, pakai yang
            # terakhir muncul.
            clean_labels = [l for l in labels if not l.lower().startswith("periode ")]
            canonical[period_end] = clean_labels[0] if clean_labels else labels[-1]
        history = history.copy()
        history["Period"] = history["Period_End"].map(canonical)
        return history

    # =====================================================
    # ADVANCED #6: ATTACK SURFACE TRACKING (lintas periode)
    # =====================================================
    # Melacak domain & target yang TERUS-MENERUS jadi masalah lintas periode -
    # perluasan dari Entity_Correlation & Domain_Recommendation yang sifatnya
    # cuma 1 periode. Butuh histori (sama seperti Recurring Findings).

    def build_attack_surface_tracking(self):
        print("Building Attack Surface Tracking...")

        history_path = Path("database") / "attack_surface_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        domain_snap = self.domain_summary.copy()
        domain_snap["Period"] = self.period_key
        domain_snap["Period_End"] = self.period_end

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, domain_snap], ignore_index=True)
        else:
            history = domain_snap
        history = self._clean_period_history(history)
        history = history.drop_duplicates(subset=["Period", "Period_End", "Security_Domain"], keep="last")
        history.to_csv(history_path, index=False)

        recent_periods = (
            history[["Period", "Period_End"]].drop_duplicates()
            .sort_values("Period_End", ascending=False).head(5)["Period"]
        )
        recent = history[history["Period"].isin(recent_periods)]

        self.attack_surface_trend = (
            recent.pivot_table(index="Security_Domain", columns="Period", values="Incident", aggfunc="sum", fill_value=0)
        ).reset_index()
        self.attack_surface_period_count = len(recent_periods)

    # =====================================================
    # ADVANCED #9: SEVERITY TREND (lintas periode) - BARU
    # =====================================================
    # Severity_Breakdown yang sudah ada cuma snapshot 1 periode. Ini melacak
    # Critical/High/Medium/Low NAIK-TURUN dari periode ke periode - sama pola
    # histori seperti Attack Surface Tracking & Recurring Findings.

    # =====================================================
    # MONTHLY COMPARISON (BARU) - tracking SEMUA periode yang pernah
    # digenerate, bukan cuma 5-6 terakhir seperti Severity/Attack Surface
    # Trend. Ini jawaban langsung untuk "dimana lihat perbandingan tiap bulan?"
    # =====================================================

    def build_monthly_comparison(self):
        print("Building Monthly Comparison...")

        history_path = Path("database") / "monthly_summary_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        rs = self.rule_summary
        snap = pd.DataFrame([{
            "Period": self.period_key,
            "Period_End": self.period_end,
            "Total_Alert": int(rs["Alert_Count"].sum()),
            "Total_Incident": int(rs["Incident_Count"].sum()),
            "Detection_Rate_%": round((rs["Incident_Count"].sum() / max(rs["Alert_Count"].sum(), 1)) * 100, 2),
            "Total_Alert_NonSplunk": len(self.nonsplunk) if self.nonsplunk is not None else 0,
            "Total_Task": len(self.task) if self.task is not None else 0,
            "Noise_Rules": len(rs[rs["Recommendation"] == "Noise"]),
            "Dormant_Rules": len(rs[rs["Recommendation"] == "Dormant"]),
        }])

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, snap], ignore_index=True)
        else:
            history = snap
        history = self._clean_period_history(history)
        history = history.drop_duplicates(subset=["Period", "Period_End"], keep="last")
        history.to_csv(history_path, index=False)

        self.monthly_comparison = history.sort_values("Period_End").reset_index(drop=True)
        self.monthly_comparison_period_count = len(self.monthly_comparison)

    def build_severity_trend(self):
        print("Building Severity Trend...")

        history_path = Path("database") / "severity_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        sev_snap = self.severity_breakdown.copy()
        sev_snap["Period"] = self.period_key
        sev_snap["Period_End"] = self.period_end

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, sev_snap], ignore_index=True)
        else:
            history = sev_snap
        history = self._clean_period_history(history)
        history = history.drop_duplicates(subset=["Period", "Period_End", "Severity_Label"], keep="last")
        history.to_csv(history_path, index=False)

        recent_periods = (
            history[["Period", "Period_End"]].drop_duplicates()
            .sort_values("Period_End", ascending=False).head(6)["Period"]
        )
        recent = history[history["Period"].isin(recent_periods)]

        self.severity_trend = (
            recent.pivot_table(index="Period", columns="Severity_Label", values="Jumlah_Tiket",
                                aggfunc="sum", fill_value=0)
        )
        # urutkan berdasarkan Period_End asli, bukan alfabetis
        period_order = recent[["Period", "Period_End"]].drop_duplicates().sort_values("Period_End")["Period"]
        self.severity_trend = self.severity_trend.reindex(period_order).reset_index()
        self.severity_trend_period_count = len(recent_periods)

    # =====================================================
    # ADVANCED #10: ACTION / IMPROVEMENT TRACKER - BARU
    # =====================================================
    # Konsolidasi SEMUA temuan yang butuh tindak lanjut (Noise, Tuning,
    # Unmapped) jadi 1 tracker dengan status: MASIH TERBUKA (masih muncul di
    # periode ini) vs SUDAH MEMBAIK (dulu bermasalah, sekarang TIDAK lagi
    # muncul di kategori itu) - pakai rule_history.csv yang sudah ada.

    def build_action_tracker(self):
        print("Building Action Tracker...")

        history_path = Path("database") / "rule_history.csv"

        if not history_path.exists():
            self.action_tracker = pd.DataFrame()
            self.action_tracker_summary = pd.DataFrame()
            return

        history = pd.read_csv(history_path)
        history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")

        all_periods = history[["Period", "Period_End"]].drop_duplicates().sort_values("Period_End")
        if len(all_periods) == 0:
            self.action_tracker = pd.DataFrame()
            self.action_tracker_summary = pd.DataFrame()
            return

        latest_period = all_periods.iloc[-1]["Period"]
        current_flagged = set(
            history[history["Period"] == latest_period]["Rule_ID"].dropna()
        )
        ever_flagged = history.groupby("Rule_ID").agg(
            Rule_Names=("Rule_Names", "last"),
            First_Flagged_Period=("Period_End", "min"),
            Periods_Flagged=("Period", "nunique"),
            Last_Recommendation=("Recommendation", "last"),
        ).reset_index()

        ever_flagged["Status"] = ever_flagged["Rule_ID"].apply(
            lambda rid: "🔴 Masih Terbuka" if rid in current_flagged else "✅ Sudah Membaik"
        )
        ever_flagged["First_Flagged_Period"] = ever_flagged["First_Flagged_Period"].dt.date

        self.action_tracker = ever_flagged.sort_values(
            ["Status", "Periods_Flagged"], ascending=[True, False]
        ).reset_index(drop=True)

        total = len(ever_flagged)
        improved = (ever_flagged["Status"] == "✅ Sudah Membaik").sum()
        still_open = (ever_flagged["Status"] == "🔴 Masih Terbuka").sum()
        self.action_tracker_summary = pd.DataFrame([
            ["Total Rule Pernah Ditandai Bermasalah", total],
            ["Sudah Membaik (tidak muncul lagi periode ini)", int(improved)],
            ["Masih Terbuka (masih Noise/Tuning periode ini)", int(still_open)],
            ["Improvement Rate", f"{round(100*improved/max(total,1),1)}%"],
        ], columns=["Metrik", "Nilai"])

    # =====================================================
    # ADVANCED #7: PRIORITY INSIDEN PER RULE SPLUNK
    # =====================================================

    def build_priority_per_rule(self):
        print("Building Priority per Rule...")

        priority_label = {0: "P0-Critical", 1: "P1-High", 2: "P2-Medium", 3: "P3-Low"}
        inc = self.incident.dropna(subset=["Priority"]).copy()
        inc["Priority_Label"] = inc["Priority"].map(priority_label)

        _rule_col = "Summary" if "Summary" in inc.columns else "Normalized Rule"
        self.priority_per_rule = (
            inc.groupby([_rule_col, "Priority_Label"]).size().unstack(fill_value=0).reset_index()
            .rename(columns={_rule_col: "Rule/Summary"})
        )
        priority_cols = [c for c in ["P0-Critical", "P1-High", "P2-Medium", "P3-Low"] if c in self.priority_per_rule.columns]
        if priority_cols:
            self.priority_per_rule["Total"] = self.priority_per_rule[priority_cols].sum(axis=1)
            self.priority_per_rule = self.priority_per_rule.sort_values("Total", ascending=False)

    # =====================================================
    # ADVANCED #8: RESOLVED -> CLOSED TIMELINE + LESSON LEARNED (dari Task)
    # =====================================================
    # "Lesson learned" TIDAK bisa dibuat dari data Incident (tidak ada kolom
    # catatan/resolusi bertuliskan bebas di export Ivanti untuk modul Incident -
    # sudah dicek langsung). Dipakai dari modul Task yang punya field Resolution.

    def build_resolved_closed_timeline(self):
        print("Building Resolved->Closed Timeline...")

        inc = self.incident.copy()
        closed = inc[inc["Status"].astype(str) == "Closed"].dropna(subset=["Resolved On"])
        # Prioritaskan "Closed On" (skema baru - timestamp Closed eksplisit,
        # lebih akurat) daripada "Modified On" (skema lama - proxy kasar).
        closed_col = "Closed On" if "Closed On" in closed.columns else ("Modified On" if "Modified On" in closed.columns else None)
        if closed_col and len(closed) > 0:
            closed = closed.copy()
            closed[closed_col] = pd.to_datetime(closed[closed_col], errors="coerce")
            closed["Resolved_to_Closed_sec"] = (closed[closed_col] - closed["Resolved On"]).dt.total_seconds()
            closed["Resolved_to_Closed_sec"] = closed["Resolved_to_Closed_sec"].clip(lower=0)
            self.resolved_closed_stats = pd.DataFrame([
                ["Total Tiket Closed", len(closed)],
                ["Rata-rata Resolved->Closed (menit)", round(closed["Resolved_to_Closed_sec"].mean() / 60, 1)],
                ["Median Resolved->Closed (menit)", round(closed["Resolved_to_Closed_sec"].median() / 60, 1)],
                ["Langsung Closed tanpa jeda (0 menit) - potensi tanpa review", int((closed["Resolved_to_Closed_sec"] == 0).sum())],
            ], columns=["Metrik", "Nilai"])
        else:
            self.resolved_closed_stats = pd.DataFrame()

        # Lesson learned dari Task (Details/Resolution) - kalau ada
        if self.task is not None and len(self.task) > 0 and "Resolution" in self.task.columns:
            lessons = self.task.dropna(subset=["Resolution"])[["Task", "Subject", "Resolution", "Owner"]]
            self.lesson_learned_log = lessons[lessons["Resolution"].astype(str).str.len() > 5]
        else:
            self.lesson_learned_log = pd.DataFrame()

    def build_hypothesis_insight(self):
        print("Building Hypothesis Insight...")

        rs = self.rule_summary
        rows = []  # (Hipotesis, Temuan, Sumber_Data)
        p = self.period_label_text  # contoh: "periode 01 Jul 2026 - 31 Jul 2026"

        total_alert = rs["Alert_Count"].sum()
        total_incident = rs["Incident_Count"].sum()
        conv_rate = round(total_incident / max(total_alert, 1) * 100, 2)
        rows.append((
            "H1 - Conversion Rate",
            f"Dari {int(total_alert)} alert event {p}, {int(total_incident)} berhasil jadi tiket "
            f"({conv_rate}% conversion rate).",
            "Sheet 'Rule Summary', kolom Alert_Count & Incident_Count (dijumlahkan semua baris)"
        ))

        gap_rules = rs[(rs["Alert_Count"] > 0) & (rs["Incident_Count"] == 0)]
        top_gap = gap_rules.sort_values("Alert_Count", ascending=False).iloc[0]["Rule_Names"] if len(gap_rules) > 0 else "-"
        rows.append((
            "H1b - Gap Rules",
            f"{len(gap_rules)} rule terdeteksi alert TAPI tidak satupun jadi tiket {p}. "
            f"Rule dengan alert terbanyak tanpa tiket: {top_gap}",
            "Sheet 'Rule Summary', filter Alert_Count > 0 DAN Incident_Count = 0 (bisa direplikasi dengan Filter Excel)"
        ))

        noise = rs[rs["Recommendation"] == "Noise"]
        rows.append((
            "H3 - Signal-to-Noise",
            f"{len(noise)} rule masuk kategori Noise (alert >= {NOISE_ALERT_THRESHOLD} tapi 0 insiden) "
            "- kandidat tuning threshold/exclusion.",
            "Sheet 'Noise' (sudah difilter dari Rule Summary, kolom Recommendation = 'Noise')"
        ))

        unmapped_alert = rs.loc[~rs["In_Master"], "Alert_Count"].sum()
        rows.append((
            "H4 - Detection Coverage",
            f"{int(unmapped_alert)} alert event ({round(100*unmapped_alert/max(total_alert,1),1)}%) "
            f"{p} berasal dari rule yang TIDAK ada di Master Rules - kemungkinan rule baru, "
            "hasil migrasi environment, atau salah nama - perlu direview manual.",
            "Sheet 'Unmapped' (baris Rule Summary dengan In_Master = False)"
        ))

        dormant = rs[rs["Recommendation"] == "Dormant"]
        rows.append((
            "H6 - Dormant Rules",
            f"{len(dormant)} rule terdaftar di master TAPI tidak trigger sama sekali {p} "
            "- cek apakah rule masih relevan / masih Enabled di Splunk.",
            "Sheet 'Dormant' (kolom Recommendation = 'Dormant')"
        ))

        if hasattr(self, "nonsplunk_coverage") and len(self.nonsplunk_coverage) > 0:
            nc = self.nonsplunk_coverage
            total_ns = nc["Total_Alert"].sum()
            total_ticket_ns = nc["Jadi_Tiket"].sum()
            total_cti = nc["CTI_dari_N"].sum()
            total_gap_murni = nc["Gap_Murni_dari_N"].sum()
            worst = nc.sort_values("Coverage_%").iloc[0]
            rows.append((
                "H2 - NonSplunk Coverage",
                f"Dari {int(total_ns)} alert non-Splunk (Akamai/CSPM/Microsoft Defender) {p}, "
                f"{int(total_ticket_ns)} jadi tiket ({round(100*total_ticket_ns/max(total_ns,1),1)}%). "
                f"Sisanya yang tidak jadi tiket: {int(total_cti)} adalah advisory/CTI (subset, bukan tambahan), "
                f"{int(total_gap_murni)} benar-benar gap murni. Device dengan coverage terendah: "
                f"{worst['Source_Device']} ({worst['Coverage_%']}%).",
                "Sheet 'Nonsplunk Coverage' (kolom CTI_dari_N & Gap_Murni_dari_N adalah RINCIAN dari "
                "Tidak_Jadi_Tiket - JANGAN dijumlah tambahan ke Total_Alert)"
            ))

        if hasattr(self, "soc_individual_kpi") and len(self.soc_individual_kpi) > 0:
            top = self.soc_individual_kpi.iloc[0]
            slowest = self.soc_individual_kpi.sort_values("Avg_MTTR_sec", ascending=False).iloc[0]
            rows.append((
                "H-KPI - Workload & SLA",
                f"Analyst dengan beban tiket terbanyak {p}: {top['Owner']} ({top['Total_Incident']} tiket, "
                f"{top['Workload_Share_%']}% dari total). MTTR rata-rata terlambat: {slowest['Owner']} "
                f"({slowest['Avg_MTTR_sec']:.0f} detik, SLA={SLA_MTTR_SECONDS} detik).",
                "Sheet 'Soc Individual Kpi' (dihitung dari kolom Created On/Responded On/Resolved On di tiket Ivanti mentah)"
            ))

        # H-CTI: alert non-Splunk yang sifatnya advisory/CTI (bukan insiden aktif)
        if self.nonsplunk is not None and len(self.nonsplunk) > 0 and "Reason" in self.nonsplunk.columns:
            cti = self.nonsplunk[self.nonsplunk["Reason"].astype(str).str.contains("CTI", case=False, na=False)]
            if len(cti) > 0:
                rows.append((
                    "H-CTI - Threat Intelligence Advisory",
                    f"{len(cti)} item {p} adalah advisory/CTI report (bukan insiden aktif, mis. laporan CVE atau "
                    "profil malware dari Microsoft Defender) - PERLU DIREVIEW manual apakah applicable ke environment "
                    "kita, bukan otomatis ditutup sebagai 'tidak jadi tiket'.",
                    "Sheet 'Nonsplunk Detail', filter kolom Reason mengandung 'CTI'"
                ))

        # H-TH: rule dormant sebagai kandidat threat hunting proaktif
        if len(dormant) > 0:
            rows.append((
                "H-TH - Kandidat Threat Hunting",
                f"{len(dormant)} rule Dormant {p} adalah kandidat aktivitas Threat Hunting proaktif - "
                "tim TH bisa mengecek manual apakah pola serangan terkait rule ini memang tidak terjadi, "
                "atau rule-nya yang gagal mendeteksi (blind spot).",
                "Sheet 'Dormant' (subset Rule Summary, kolom Recommendation = 'Dormant')"
            ))

        # H-Recurring: temuan yang berulang lintas periode (butuh histori)
        if hasattr(self, "recurring_findings") and len(self.recurring_findings) > 0:
            rf = self.recurring_findings
            worst = rf.iloc[0]
            rows.append((
                "H-Recurring - Temuan Berulang (Berbahaya)",
                f"{len(rf)} rule tercatat sebagai Noise/Tuning di >=3 dari {self.history_period_count} periode "
                f"terakhir - BUKAN kejadian sekali, ini pola berulang. Paling sering: {worst['Rule_Names']} "
                f"({worst['Muncul_Sebagai_Risiko']}x). Lihat sheet 'Recurring Findings' untuk daftar lengkap.",
                "Dihitung dari database/rule_history.csv (akumulasi snapshot tiap kali report di-generate)"
            ))

        # H-Mismatch: severity Splunk vs priority Ivanti tidak konsisten
        if hasattr(self, "mismatch_under_count") and self.mismatch_total_checked > 0:
            pct = round(100 * self.mismatch_under_count / self.mismatch_total_checked, 1)
            rows.append((
                "H-Mismatch - Severity vs Priority",
                f"Dari {self.mismatch_total_checked} tiket yang bisa dicek, {self.mismatch_under_count} "
                f"({pct}%) UNDER-PRIORITIZED - rule-nya bersifat Critical/High tapi tiketnya dikasih "
                "priority rendah. Ini risiko nyata: insiden serius bisa terlambat direspons karena "
                "dianggap tidak urgent.",
                "Sheet 'Severity_Priority_Mismatch' (baris dengan Arah = 'UNDER-PRIORITIZED')"
            ))

        # H-Entity: individu yang muncul di banyak rule berbeda
        if hasattr(self, "entity_correlation") and len(self.entity_correlation) > 0:
            top_entity = self.entity_correlation.iloc[0]
            rows.append((
                "H-Entity - Target Multi-Vektor (PIC Tujuan Tiket)",
                f"{len(self.entity_correlation)} PIC/target tiket {p} (kolom Customer - BUKAN SOC analyst "
                f"pengerja) terlibat di >=2 rule BERBEDA. Paling menonjol: {top_entity['Customer']} - "
                f"{top_entity['Rule_Berbeda']} rule berbeda ({top_entity['Jumlah_Insiden']} tiket). "
                "Kandidat investigasi akun/perangkat TARGET ini secara menyeluruh, bukan per-tiket terpisah.",
                "Sheet 'Entity_Correlation' (dikelompokkan dari kolom Customer = PIC tujuan tiket di Ivanti)"
            ))

        # H-TimePattern: jam/hari rawan
        if hasattr(self, "peak_hour") and self.peak_hour is not None:
            rows.append((
                "H-TimePattern - Pola Waktu Alert",
                f"Jam paling rawan: {self.peak_hour:02d}:00. Hari paling rawan: {self.peak_day}. "
                f"{self.pct_off_hours}% alert {p} terjadi DI LUAR jam kerja (09:00-18:00 WIB, Senin-Jumat) "
                "- relevan untuk evaluasi penempatan shift SOC.",
                "Sheet 'Time_By_Hour' & 'Time_By_Day' (dihitung dari kolom Alert Time)"
            ))

        # H-Outcome: prevention rate vs breach, dan false positive rate
        if hasattr(self, "total_tickets_for_outcome") and self.total_tickets_for_outcome > 0:
            total = self.total_tickets_for_outcome
            rows.append((
                "H-Outcome - Prevention Rate & False Positive",
                f"Dari total {total} tiket {p} (basis semua angka di bawah): {self.prevention_rate}% dari tiket "
                f"yang SUDAH diklasifikasi Cause Code berhasil DICEGAH (Prevented), {self.breach_reported} tiket "
                f"benar-benar 'Breach - Reported', dan {self.unclassified_count} tiket ({round(100*self.unclassified_count/total,1)}%) "
                f"BELUM diklasifikasi Cause Code sama sekali - 3 angka ini kalau dijumlah = {total} (persis Total Tiket). "
                f"TERPISAH dari itu: {self.false_positive_rate}% dari total tiket berstatus Cancelled (kolom "
                "Status, bukan Cause Code - bisa tumpang tindih dengan kategori manapun di atas, lihat sheet "
                "Cancelled_Crosstab untuk rinciannya) - indikasi false positive.",
                "Sheet 'Cause_Code_Breakdown' (3 kategori, jumlah = Total Tiket) + 'Status_Summary' & "
                "'Cancelled_Crosstab' (dimensi terpisah, JANGAN dijumlah ke Cause_Code_Breakdown)"
            ))

        # H-Threat: profil ancaman paling menonjol per tier priority
        if hasattr(self, "threat_by_priority") and len(self.threat_by_priority) > 0:
            top_critical = self.threat_by_priority[self.threat_by_priority["Priority_Label"] == "P0-Critical"]
            if len(top_critical) > 0:
                text = (f"Threat P0-Critical paling sering: '{top_critical.iloc[0]['Summary'][:60]}' "
                        f"({top_critical.iloc[0]['Jumlah']}x).")
            else:
                top_high = self.threat_by_priority[self.threat_by_priority["Priority_Label"] == "P1-High"]
                text = (f"Tidak ada insiden P0-Critical {p}. Threat P1-High paling sering: "
                        f"'{top_high.iloc[0]['Summary'][:60]}' ({top_high.iloc[0]['Jumlah']}x)." if len(top_high) > 0
                        else f"Belum ada pola threat menonjol {p}.")
            rows.append((
                "H-Threat - Profil Ancaman per Priority",
                text,
                "Sheet 'Threat_By_Priority', 'Threat_By_Priority_Domain', 'Threat_By_Priority_Target' "
                "('asset'/'target' = proxy dari Security_Domain & Customer, bukan data inventaris aset sungguhan)"
            ))

        # H-MonthlyComparison: perbandingan total alert/insiden antar bulan
        if hasattr(self, "monthly_comparison") and self.monthly_comparison_period_count >= 2:
            mc = self.monthly_comparison
            first, last = mc.iloc[0], mc.iloc[-1]
            alert_change = last["Total_Alert"] - first["Total_Alert"]
            rows.append((
                "H-MonthlyComparison - Perbandingan Antar Bulan",
                f"Sudah ada {self.monthly_comparison_period_count} periode tersimpan untuk dibandingkan. "
                f"Total alert dari periode paling awal ({first['Period']}: {int(first['Total_Alert'])}) ke "
                f"paling baru ({last['Period']}: {int(last['Total_Alert'])}) "
                f"{'naik' if alert_change > 0 else 'turun' if alert_change < 0 else 'stabil'} "
                f"{abs(int(alert_change))} alert. Lihat tab 'Perbandingan Bulanan' untuk grafik lengkap.",
                "Sheet 'Monthly_Comparison' (database/monthly_summary_history.csv, SEMUA periode tersimpan)"
            ))

        # H-SeverityTrend: tren severity naik/turun lintas periode
        if hasattr(self, "severity_trend") and len(self.severity_trend) >= 2:
            st_df = self.severity_trend
            high_cols = [c for c in ["Critical", "High"] if c in st_df.columns]
            if high_cols:
                first_high = st_df[high_cols].iloc[0].sum()
                last_high = st_df[high_cols].iloc[-1].sum()
                arah = "NAIK" if last_high > first_high else ("TURUN" if last_high < first_high else "STABIL")
                rows.append((
                    "H-SeverityTrend - Tren Critical/High Lintas Periode",
                    f"Dari {len(st_df)} periode terakhir, jumlah tiket Critical+High {arah} "
                    f"({int(first_high)} -> {int(last_high)}). "
                    + ("Perlu perhatian - proporsi insiden serius makin banyak." if arah == "NAIK"
                       else "Tren membaik." if arah == "TURUN" else "Belum ada perubahan berarti."),
                    "Sheet 'Severity_Trend' (histori severity lintas periode, database/severity_history.csv)"
                ))

        # H-ActionTracker: improvement rate dari rule yang pernah ditandai bermasalah
        if hasattr(self, "action_tracker_summary") and len(self.action_tracker_summary) > 0:
            improved_row = self.action_tracker_summary[
                self.action_tracker_summary["Metrik"].str.contains("Improvement Rate")
            ]
            still_open_row = self.action_tracker_summary[
                self.action_tracker_summary["Metrik"].str.contains("Masih Terbuka")
            ]
            if len(improved_row) > 0:
                rows.append((
                    "H-ActionTracker - Improvement Rate",
                    f"{improved_row.iloc[0]['Nilai']} rule yang pernah ditandai bermasalah (Noise/Tuning) "
                    f"SUDAH TIDAK muncul lagi di periode ini - indikasi tuning/tindak lanjut berhasil. "
                    f"Masih ada {still_open_row.iloc[0]['Nilai']} rule yang TERUS bermasalah, perlu ditindaklanjuti.",
                    "Sheet 'Action_Tracker' (status per rule: Masih Terbuka vs Sudah Membaik, "
                    "dari database/rule_history.csv)"
                ))

        # H-AttackSurface: domain yang konsisten jadi masalah lintas periode
        if hasattr(self, "attack_surface_trend") and len(self.attack_surface_trend) > 0 and self.attack_surface_period_count >= 2:
            period_cols = [c for c in self.attack_surface_trend.columns if c != "Security_Domain"]
            trend = self.attack_surface_trend.copy()
            trend["_total"] = trend[period_cols].sum(axis=1)
            top_domain = trend.sort_values("_total", ascending=False).iloc[0]
            rows.append((
                "H-AttackSurface - Domain Konsisten Bermasalah",
                f"Dari {self.attack_surface_period_count} periode terakhir, domain paling konsisten tinggi "
                f"insidennya: {top_domain['Security_Domain']} (total {int(top_domain['_total'])} insiden). "
                "Kalau domain yang sama terus muncul teratas tiap periode, itu indikasi exposure permanen, "
                "bukan insiden acak - pertimbangkan mitigasi struktural (hardening, WAF, dst), bukan tuning rule saja.",
                "Sheet 'Attack_Surface_Trend' (histori domain lintas periode, database/attack_surface_history.csv)"
            ))

        # H-ResolvedClosed: potensi tiket ditutup tanpa review
        if hasattr(self, "resolved_closed_stats") and len(self.resolved_closed_stats) > 0:
            no_gap = self.resolved_closed_stats[self.resolved_closed_stats["Metrik"].str.contains("tanpa jeda")]
            if len(no_gap) > 0:
                rows.append((
                    "H-ResolvedClosed - Potensi Tanpa Review",
                    f"{int(no_gap.iloc[0]['Nilai'])} tiket langsung Closed di waktu yang SAMA dengan Resolved "
                    "(0 menit jeda) - berpotensi tidak melalui tahap review terpisah sebelum ditutup. "
                    "Bukan berarti salah, tapi layak dicek proses closing tiketnya.",
                    "Sheet 'Resolved_Closed_Stats' (dari Resolved On vs Modified On di tiket Ivanti)"
                ))

        # H-DailyTrend: lonjakan alert di tanggal tertentu
        if hasattr(self, "daily_trend_peak") and self.daily_trend_peak[0] is not None:
            peak_date, peak_val = self.daily_trend_peak
            peak_rule, peak_rule_pct = self.daily_trend_peak_rule
            avg_daily = round(self.daily_trend["Jumlah_Alert"].mean(), 1)
            rows.append((
                "H-DailyTrend - Lonjakan Harian",
                f"Tanggal dengan alert terbanyak: {peak_date} ({peak_val} alert, rata-rata harian "
                f"periode ini {avg_daily}). {peak_rule_pct}% dari lonjakan itu berasal dari 1 rule: "
                f"'{peak_rule}' - bukan serangan tersebar, tapi dominan dari 1 sumber. Cek rule ini dulu.",
                "Sheet 'Daily_Trend', kolom Rule_Kontributor_Terbesar (dihitung per tanggal)"
            ))

        # H-TaskWorkload: beban kerja "tak resmi" dari task tim lain
        if self.task is not None and len(self.task) > 0:
            top_task_owner = self.task_by_owner.iloc[0] if len(self.task_by_owner) > 0 else None
            avg_per_week = round(self.task_weekly_regularity["Jumlah_Task"].mean(), 1) if len(self.task_weekly_regularity) > 0 else 0
            text = (
                f"{len(self.task)} task pengecekan dari tim lain {p} - rata-rata {avg_per_week} task/minggu "
                "(beban kerja ini TIDAK tercatat sebagai insiden ter-assign resmi)."
            )
            if top_task_owner is not None:
                text += f" Analyst dengan task terbanyak: {top_task_owner['Owner']} ({top_task_owner['Total_Task']} task)."
            rows.append((
                "H-TaskWorkload - Beban Kerja Tak Resmi",
                text,
                "Sheet 'Task_Summary', 'Task_By_Owner', 'Task_Weekly_Regularity' (dari file task_soc mentah)"
            ))

        # H-CTIFortiRecon: alert threat intel eksternal
        if self.cti is not None and len(self.cti) > 0:
            top_type = self.cti_by_type.iloc[0] if len(self.cti_by_type) > 0 else None
            text = (
                f"{len(self.cti)} alert CTI FortiRecon {p} - {self.cti_true_positive_rate}% True Positive "
                "(dari yang sudah diverifikasi)."
            )
            if top_type is not None:
                text += f" Jenis alert paling sering: {top_type['Alert_Type']} ({top_type['Jumlah']}x)."
            pw = self.cti["Password_Leaked"].sum() if "Password_Leaked" in self.cti.columns else 0
            if pw > 0:
                text += f" {int(pw)} kasus terindikasi kredensial bocor (nilai password TIDAK ditampilkan di laporan ini)."
            rows.append((
                "H-CTIFortiRecon - Threat Intel Eksternal",
                text,
                "Sheet 'CTI_Summary', 'CTI_By_Type' (dari file CTI FortiRecon mentah - password sudah dimasking)"
            ))

        if hasattr(self, "nonsplunk_partial_note") and self.nonsplunk_partial_note:
            rows.insert(0, ("PERINGATAN - Data NonSplunk Partial", self.nonsplunk_partial_note,
                             "Dihitung otomatis dari tanggal min/max di sheet 'Nonsplunk Detail' vs 'Rule Summary'"))

        self.hypothesis_insight = pd.DataFrame(rows, columns=["Hipotesis", "Temuan", "Sumber_Data"])

    # =====================================================
    # RUN
    # =====================================================

    def build_mitre_killchain(self):
        """MITRE ATT&CK Tactic/Technique + Cyber Kill Chain stage summary,
        plus Security Domain LANGSUNG dari kolom baru (dipakai TERPISAH
        dari self.domain yang berasal dari keyword-mapping - sesuai arahan
        user: 'pakai keduanya terpisah untuk tujuan berbeda').

        GRACEFUL FALLBACK: kalau file yang diupload belum punya kolom
        'Incident MITRE'/'Incident KillChain'/'Security Domain' (format
        Ivanti lama), semua ini kosong tanpa error - fitur baru ini
        opsional, tidak memaksa upload ulang data lama."""
        has_mitre_cols = "Incident MITRE" in self.incident.columns or "Incident KillChain" in self.incident.columns

        if has_mitre_cols:
            enriched = enrich_incident_mitre_killchain(self.incident)
            # Disimpan MENTAH (per-insiden, termasuk kolom _Triage) supaya
            # app.py bisa HITUNG ULANG chart MITRE/KillChain secara dinamis
            # kalau user toggle filter True Positive saja <-> semua tiket -
            # BUKAN di-generate ulang, cuma di-filter ulang di UI layer.
            self.mitre_enriched_raw = enriched
            self.triage_summary = build_triage_summary(enriched)
            self.mitre_technique_summary = build_mitre_technique_summary(enriched)
            self.mitre_tactic_summary = build_mitre_tactic_summary(enriched)
            self.killchain_summary = build_killchain_summary(enriched)
            self.mitre_killchain_dq = build_data_quality_report(enriched)
            self.mitre_killchain_insights = generate_mitre_killchain_insights(
                self.mitre_technique_summary, self.mitre_tactic_summary,
                self.killchain_summary, len(self.incident)
            )
            # --- Sesuai MoM BoD ---
            self.mitre_hierarchy = build_mitre_hierarchy(enriched)
            self.technique_impact = build_technique_impact(enriched, self.mitre_technique_summary)
            # Baseline: % High/Critical atau breach di SELURUH insiden (TANPA
            # filter technique) - dipakai sebagai pembanding "lebih berbahaya
            # dari rata-rata atau tidak" di caption UI.
            _baseline_high = 0
            if "Severity" in enriched.columns:
                _baseline_high = enriched["Severity"].astype(str).str.strip().str.lower().isin(["high", "critical"]).sum()
            _baseline_breach = 0
            for col in ["FlagBreachResponse", "FlagBreachReso"]:
                if col in enriched.columns:
                    _baseline_breach = max(_baseline_breach, (enriched[col].astype(str) == "1").sum())
            self.technique_impact_baseline = round(max(_baseline_high, _baseline_breach) / max(len(enriched), 1), 3)
            self.killchain_funnel = build_killchain_funnel(enriched)
            # Drill-down TERSEDIA UNTUK SEMUA stage yang punya data (bukan
            # cuma yang tertinggi) - user bisa eksplorasi stage manapun, tidak
            # dibatasi cuma stage dengan Count terbesar. killchain_top_stage
            # tetap disimpan sebagai DEFAULT pilihan (yang paling relevan
            # dilihat pertama), bukan satu-satunya yang bisa dilihat.
            self.killchain_stage_drilldown = {}  # {stage_name: {"technique":df, "tactic":df, "n":int, "hierarchy":df, "tactic_unique_n":dict, "technique_unique_n":dict}}
            for _, row in self.killchain_summary.iterrows():
                if row["Count"] > 0:
                    tech, tac, n, hier, tac_uniq, tech_uniq = build_mitre_by_killchain_stage(enriched, row["Stage"])
                    self.killchain_stage_drilldown[row["Stage"]] = {
                        "technique": tech, "tactic": tac, "n": n, "hierarchy": hier,
                        "tactic_unique_n": tac_uniq, "technique_unique_n": tech_uniq,
                    }

            if self.killchain_summary["Count"].sum() > 0:
                top_stage_row = self.killchain_summary.sort_values("Count", ascending=False).iloc[0]
                self.killchain_top_stage = top_stage_row["Stage"]
            else:
                self.killchain_top_stage = None
        else:
            self.mitre_enriched_raw = pd.DataFrame()
            self.triage_summary = pd.DataFrame(columns=["Triage", "Count", "Percent"])
            self.mitre_technique_summary = pd.DataFrame(columns=["Technique", "Label", "Count"])
            self.mitre_tactic_summary = pd.DataFrame(columns=["Tactic", "Label", "Count"])
            self.killchain_summary = pd.DataFrame(columns=["Stage", "Count"])
            self.mitre_killchain_dq = pd.DataFrame(columns=["Ticket", "Kolom", "Nilai Bermasalah"])
            self.mitre_killchain_insights = []
            self.mitre_hierarchy = pd.DataFrame(columns=["Tactic", "Technique", "SubTechnique", "Count"])
            self.technique_impact = pd.DataFrame(columns=["Technique", "Label", "Count", "High_Severity_or_Breach_Count", "Impact_%"])
            self.technique_impact_baseline = None
            self.killchain_funnel = pd.DataFrame(columns=["Stage", "Reached_At_Least"])
            self.killchain_top_stage = None
            self.killchain_stage_drilldown = {}

        # Security Domain LANGSUNG dari kolom baru - TERPISAH dari
        # self.domain (keyword-mapping). Tetap dinormalisasi Title Case
        # supaya konsisten dengan konvensi self.domain yang sudah ada.
        if "Security Domain" in self.incident.columns:
            sd = self.incident["Security Domain"].astype(str).str.strip().str.title()
            sd = sd.replace({"Nan": "Tidak Diketahui", "": "Tidak Diketahui"})
            self.security_domain_direct = (
                sd.value_counts().reset_index()
                .rename(columns={"index": "Security_Domain", "Security Domain": "Security_Domain", "count": "Jumlah"})
            )
            self.security_domain_direct.columns = ["Security_Domain", "Jumlah"]
        else:
            self.security_domain_direct = pd.DataFrame(columns=["Security_Domain", "Jumlah"])

        self.build_security_domain_direct_trend()

    def build_security_domain_direct_trend(self):
        """Histori LINTAS BULAN untuk Security Domain kolom LANGSUNG -
        pola SAMA seperti build_attack_pattern_trend(), TAPI file histori
        TERPISAH (security_domain_direct_history.csv) supaya tidak campur
        dengan Attack Surface Trend (yang berasal dari keyword-mapping).
        Ini mengisi gap yang ditemukan user: kolom Security Domain baru
        sebelumnya cuma snapshot 1 periode, tidak ada trend-nya."""
        history_path = Path("database") / "security_domain_direct_history.csv"
        history_path.parent.mkdir(exist_ok=True)

        if self.security_domain_direct is None or len(self.security_domain_direct) == 0:
            snap = pd.DataFrame([{"Period": self.period_key, "Period_End": self.period_end,
                                   "Security_Domain": "Tidak Diketahui", "Jumlah": 0}])
        else:
            snap = self.security_domain_direct.copy()
            snap["Period"] = self.period_key
            snap["Period_End"] = self.period_end

        if history_path.exists():
            history = pd.read_csv(history_path)
            history["Period_End"] = pd.to_datetime(history["Period_End"], errors="coerce")
            history = history[history["Period"] != self.period_key]
            history = pd.concat([history, snap], ignore_index=True)
        else:
            history = snap
        history = history.drop_duplicates(subset=["Period", "Period_End", "Security_Domain"], keep="last")
        history.to_csv(history_path, index=False)

        self.security_domain_direct_trend = (
            history.pivot_table(index="Period", columns="Security_Domain", values="Jumlah",
                                 aggfunc="sum", fill_value=0)
        )
        period_order = history[["Period", "Period_End"]].drop_duplicates().sort_values("Period_End")["Period"]
        self.security_domain_direct_trend = self.security_domain_direct_trend.reindex(period_order).reset_index()
        self.security_domain_direct_trend_period_count = len(period_order)

    def run(self):
        self._compute_incident_breach_flag()
        self.build_period_info()
        self.build_reading_guide()
        self.build_rule_summary()
        self.build_domain()  # harus setelah rule_summary, sebelum insight
        self.build_domain_recommendation()  # harus setelah build_domain
        self.build_rule_status_distribution()
        self.build_nonsplunk_coverage()
        self.build_task_summary()
        self.build_cti_summary()
        self.build_cti_trend()
        self.build_executive_summary()
        self.build_top_rule()
        self.build_noise()
        self.build_tuning()
        self.build_dormant()
        self.build_unmapped()
        self.build_sla_metrics()
        self.build_soc_individual_kpi()
        self.build_priority()
        self.build_breach()
        self.build_analyst()
        self.build_recurring_findings()
        self.build_action_tracker()
        self.build_severity_priority_mismatch()
        self.build_entity_correlation()
        self.build_time_pattern()
        self.build_outcome_insight()
        self.build_severity_breakdown()
        self.build_monthly_comparison()
        self.build_severity_trend()
        self.build_daily_trend()
        self.build_weekly_trend()
        self.build_threat_profiling()
        self.build_attack_pattern_trend()
        self.build_mitre_killchain()
        self.build_attack_surface_tracking()
        self.build_priority_per_rule()
        self.build_resolved_closed_timeline()
        self.build_hypothesis_insight()

        # Urutan dict = urutan sheet Excel & bab Streamlit/PPT - disusun mengikuti
        # narasi 8 bab: (0) meta, (1) Master Rules, (2) Splunk vs Ivanti, (3) Non-
        # Splunk, (4) Task, (5) Tren Alert, (6) Efektivitas & Severity, (7) Temuan
        # Berulang, (8) KPI SOC (paling akhir, sesuai permintaan user).
        self.report = {
            # --- Meta ---
            "reading_guide": self.reading_guide,
            "executive": self.executive,
            "hypothesis_insight": self.hypothesis_insight,

            # --- Bab 1: Master Rules Database ---
            "unmapped": self.unmapped,
            "master_status_distribution": self.master_status_distribution,

            # --- Bab 2: Splunk vs Ivanti ---
            "rule_summary": self.rule_summary,
            "rule_recommendation_distribution": self.rule_recommendation_distribution,
            "top_rule": self.top_rule,
            "noise": self.noise,
            "tuning": self.tuning,
            "dormant": self.dormant,
            "domain": self.domain_summary,
            "domain_recommendation": self.domain_recommendation,
            "entity_correlation": self.entity_correlation,

            # --- Bab 3: Non-Splunk vs Ivanti ---
            "nonsplunk_coverage": self.nonsplunk_coverage,
            "nonsplunk_detail": self.nonsplunk_detail,

            # --- Bab 4: Task dari Tim Lain ---
            "task_summary": self.task_summary,
            "task_by_owner": self.task_by_owner,
            "task_by_requestor": self.task_by_requestor,
            "task_weekly_regularity": self.task_weekly_regularity,
            "task_unmatched_owner": self.task_unmatched_owner,

            # --- CTI FortiRecon (BARU) ---
            "cti_summary": self.cti_summary,
            "cti_by_type": self.cti_by_type,
            "cti_by_status": self.cti_by_status,
            "cti_trend": self.cti_trend,
            "cti_detail": self.cti if self.cti is not None else pd.DataFrame(),

            # --- Bab 5: Tren Alert ---
            "daily_trend": self.daily_trend,
            "weekly_trend": self.weekly_trend,
            "is_long_period": self.is_long_period,
            "time_by_hour": self.time_by_hour,
            "time_by_day": self.time_by_day,

            # --- Bab 6: Efektivitas & Severity ---
            "severity_breakdown": self.severity_breakdown,
            "outcome_summary": self.outcome_summary,
            "cause_code_breakdown": self.cause_code_breakdown,
            "cause_code_by_domain": self.cause_code_by_domain,
            "status_summary": self.status_summary,
            "cancelled_crosstab": self.cancelled_crosstab,
            "unclassified_by_status": self.unclassified_by_status,
            "closed_no_causecode_by_owner": self.closed_no_causecode_by_owner,
            "severity_priority_mismatch": self.severity_priority_mismatch,
            "mismatch_under_by_rule": self.mismatch_under_by_rule,
            "mismatch_under_by_owner": self.mismatch_under_by_owner,
            "resolved_closed_stats": self.resolved_closed_stats,
            "lesson_learned_log": self.lesson_learned_log,

            # --- Bab 7: Temuan Berulang ---
            "recurring_findings": self.recurring_findings,
            "action_tracker": self.action_tracker,
            "action_tracker_summary": self.action_tracker_summary,
            "severity_trend": self.severity_trend,
            "monthly_comparison": self.monthly_comparison,

            # --- Bab 8: Threat Profiling & Attack Surface (BARU) ---
            "threat_by_priority": self.threat_by_priority,
            "threat_by_priority_domain": self.threat_by_priority_domain,
            "threat_by_priority_domain_direct": self.threat_by_priority_domain_direct,
            "threat_by_priority_target": self.threat_by_priority_target,
            "subject_internal_external": self.subject_internal_external,
            "attack_pattern_trend": self.attack_pattern_trend,
            "mitre_technique_summary": self.mitre_technique_summary,
            "mitre_tactic_summary": self.mitre_tactic_summary,
            "killchain_summary": self.killchain_summary,
            "mitre_killchain_dq": self.mitre_killchain_dq,
            "mitre_killchain_insights": self.mitre_killchain_insights,
            "mitre_enriched_raw": self.mitre_enriched_raw,
            "triage_summary": self.triage_summary,
            "mitre_hierarchy": self.mitre_hierarchy,
            "technique_impact": self.technique_impact,
            "technique_impact_baseline": self.technique_impact_baseline,
            "killchain_funnel": self.killchain_funnel,
            "killchain_top_stage": self.killchain_top_stage,
            "killchain_stage_drilldown": self.killchain_stage_drilldown,
            "security_domain_direct": self.security_domain_direct,
            "security_domain_direct_trend": self.security_domain_direct_trend,
            "attack_surface_trend": self.attack_surface_trend,
            "priority_per_rule": self.priority_per_rule,

            # --- Bab 9: KPI SOC per Analyst (paling akhir) ---
            "sla_metrics": self.sla_metrics,
            "soc_individual_kpi": self.soc_individual_kpi,
            "priority": self.priority,
            "breach": self.breach,
            "analyst": self.analyst,
        }

        print("\n==============================")
        print("REPORT SUMMARY")
        print("==============================")
        for k, v in self.report.items():
            if hasattr(v, "__len__"):
                print(f"{k:20} : {len(v)} rows")
            else:
                print(f"{k:20} : {v}")

        return self.report
