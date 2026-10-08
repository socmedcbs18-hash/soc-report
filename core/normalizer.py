"""
=========================================================
SOC Weekly Report
Normalizer Module (FIXED)
=========================================================
Perbaikan dari versi sebelumnya:
- normalize() lama hanya membuang bracket & simbol, TIDAK membuang prefix kategori
  ("Access - ", "Threat - ", dst) maupun suffix ("- Rule", "- Severity 3"). Akibatnya
  exact match ke master rule gagal ~100% (dibuktikan: 0% alert, 1% incident match
  di data week 27).
- exact_match() lama mengembalikan teks itu sendiri kalau tidak ketemu match, sehingga
  kegagalan match tidak kelihatan. Sekarang kegagalan match ditandai eksplisit lewat
  kolom "Matched" (True/False) supaya bisa dihitung sebagai metrik kualitas data.
=========================================================
"""

from utils.helpers import clean_rule_name


class RuleNormalizer:

    def __init__(self, data):
        self.data = data
        self.master_lookup = {}

    # =====================================================
    # Build Master Lookup
    # =====================================================

    def build_lookup(self):
        master = self.data["master_rule"].copy()

        master["Normalized Rule"] = master["Rule_Names"].apply(clean_rule_name)

        # Kalau ada 2 rule master dengan hasil normalisasi sama (mis. typo minor),
        # simpan yang pertama tapi jangan sampai bikin exception - hanya warning.
        dup = master[master["Normalized Rule"].duplicated(keep=False)]
        if len(dup) > 0:
            print(f"   [WARNING] {len(dup)} master rule punya nama ternormalisasi yang sama (lihat sheet Duplicate_Master).")

        self.master_lookup = dict(
            zip(master["Normalized Rule"], master["Rule_Names"])
        )

        self.data["master_rule"] = master

    # =====================================================
    # Exact Matching (eksplisit, tidak menyamarkan kegagalan)
    # =====================================================

    def exact_match(self, normalized):
        return self.master_lookup.get(normalized, None)

    # =====================================================
    # Run
    # =====================================================

    def run(self):
        print("Normalizing Rule Name...")

        self.build_lookup()

        alert = self.data["alert"].copy()
        incident = self.data["incident"].copy()

        alert["Normalized Rule"] = alert["Alert Name"].apply(clean_rule_name)
        if "Summary" in incident.columns:
            incident["Normalized Rule"] = incident["Summary"].apply(clean_rule_name)
        else:
            # Kolom 'Summary' tidak ada di file ini (dikonfirmasi user: tim
            # Ivanti lupa menambahkan di export ini) - JANGAN dipaksa ada,
            # JANGAN error. Rule mapping utk periode ini tidak bisa akurat
            # tanpa Summary - ditandai eksplisit "Unknown Rule (No Summary)"
            # supaya kelihatan di laporan sebagai data yang belum lengkap,
            # bukan diam-diam dianggap 0 insiden per rule.
            print("   [WARNING] Kolom 'Summary' tidak ada di file insiden ini - "
                  "Rule Name mapping TIDAK BISA dihitung akurat untuk periode ini. "
                  "Semua insiden ditandai 'Unknown Rule (No Summary)'.")
            incident["Normalized Rule"] = "Unknown Rule (No Summary)"

        alert["Matched_Master_Name"] = alert["Normalized Rule"].apply(self.exact_match)
        incident["Matched_Master_Name"] = incident["Normalized Rule"].apply(self.exact_match)

        alert["Matched"] = alert["Matched_Master_Name"].notna()
        incident["Matched"] = incident["Matched_Master_Name"].notna()

        # Rule_Name final: pakai nama master kalau matched, kalau tidak pakai versi
        # ternormalisasi sendiri TAPI ditandai supaya kelihatan di report (bukan disamarkan).
        alert["Rule_Name"] = alert["Matched_Master_Name"].fillna(alert["Normalized Rule"])
        incident["Rule_Name"] = incident["Matched_Master_Name"].fillna(incident["Normalized Rule"])

        n_alert_match = alert["Matched"].sum()
        n_incident_match = incident["Matched"].sum()

        print(f"   Alert matched to master   : {n_alert_match}/{len(alert)} "
              f"({round(100*n_alert_match/max(len(alert),1),1)}%)")
        print(f"   Incident matched to master: {n_incident_match}/{len(incident)} "
              f"({round(100*n_incident_match/max(len(incident),1),1)}%)")

        self.data["alert"] = alert
        self.data["incident"] = incident

        return self.data
