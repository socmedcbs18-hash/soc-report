"""
=========================================================
SOC Report Generator
Validator Module
=========================================================
"""

import pandas as pd


class Validator:

    def __init__(self, data):

        self.data = data

    # =====================================================
    # Unknown Rule
    # =====================================================

    def validate_unknown_rule(self):
        # FIXED: sebelumnya membandingkan alert["Normalized Rule"] (sudah dibersihkan)
        # dengan master["Rule_Names"] (belum dibersihkan) - dua sisi tidak sepadan,
        # jadi hampir semua baris selalu keluar sebagai "unknown". Sekarang pakai
        # kolom "Matched" yang dihasilkan RuleNormalizer, yang membandingkan
        # normalized vs normalized secara konsisten.

        print("Checking Unknown Rule...")

        alert = self.data["alert"].copy()
        incident = self.data["incident"].copy()

        alert_unknown = alert[~alert["Matched"]][["Alert Name", "Normalized Rule"]]
        alert_unknown["Source"] = "Alert"

        if "Summary" in incident.columns:
            incident_unknown = incident[~incident["Matched"]][["Summary", "Normalized Rule"]]
            incident_unknown.rename(columns={"Summary": "Alert Name"}, inplace=True)
        else:
            # Sama seperti di RuleNormalizer - kolom 'Summary' tidak ada di
            # file ini, jadi tidak ada teks asli buat ditampilkan di sheet
            # Unknown Rule. "Normalized Rule" tetap ada (isinya "Unknown
            # Rule (No Summary)" dari RuleNormalizer).
            incident_unknown = incident[~incident["Matched"]][["Normalized Rule"]].copy()
            incident_unknown["Alert Name"] = "(Summary tidak tersedia di file ini)"
        incident_unknown["Source"] = "Incident"

        unknown = pd.concat([alert_unknown, incident_unknown], ignore_index=True)
        unknown = unknown.drop_duplicates()

        self.data["unknown_rule"] = unknown

        print(f"Unknown Rule : {len(unknown)}")

    # =====================================================
    # Missing Priority
    # =====================================================

    def validate_priority(self):

        print("Checking Priority...")

        incident = self.data["incident"]

        missing = incident[
            incident["Priority"]
            .isna()
        ]

        self.data["missing_priority"] = missing

        print(
            f"Missing Priority : {len(missing)}"
        )

    # =====================================================
    # Missing Owner
    # =====================================================

    def validate_owner(self):

        print("Checking Owner...")

        incident = self.data["incident"]

        missing = incident[
            incident["Owner"]
            .isna()
        ]

        self.data["missing_owner"] = missing

        print(
            f"Missing Owner : {len(missing)}"
        )

    # =====================================================
    # Missing Severity
    # =====================================================

    def validate_severity(self):

        print("Checking Severity...")

        alert = self.data["alert"]

        missing = alert[
            alert["Severity"]
            .isna()
        ]

        self.data["missing_severity"] = missing

        print(
            f"Missing Severity : {len(missing)}"
        )

    # =====================================================
    # Duplicate Master Rule
    # =====================================================

    def validate_duplicate_master(self):

        print("Checking Duplicate Master Rule...")

        master = self.data["master_rule"]

        duplicate = master[
            master["Rule_Names"]
            .duplicated(
                keep=False
            )
        ]

        self.data["duplicate_master"] = duplicate

        print(
            f"Duplicate Rule : {len(duplicate)}"
        )

    # =====================================================
    # Alert vs Incident
    # =====================================================

    def validate_alert_incident(self):

        print("Comparing Alert vs Incident...")

        alert = (

            self.data["alert"]

            .groupby(
                "Normalized Rule"
            )

            .agg(

                Alert_Count=(
                    "Total",
                    "sum"
                )

            )

        )

        incident = (

            self.data["incident"]

            .groupby(
                "Normalized Rule"
            )

            .agg(

                Incident_Count=(
                    "Incident",
                    "count"
                )

            )

        )

        compare = (

            alert

            .merge(

                incident,

                how="outer",

                left_index=True,

                right_index=True

            )

            .fillna(0)

            .reset_index()

        )

        compare["Difference"] = (

            compare["Alert_Count"]

            -

            compare["Incident_Count"]

        )

        self.data["alert_incident_compare"] = compare

        print(
            f"Compared Rule : {len(compare)}"
        )

    # =====================================================
    # Mapping Quality
    # =====================================================

    def mapping_quality(self):

        print("Calculating Mapping Quality...")

        total_alert = len(
            self.data["alert"]
        )

        unknown = len(
            self.data["unknown_rule"]
        )

        matched = total_alert - unknown

        accuracy = 0

        if total_alert > 0:

            accuracy = round(

                matched

                /

                total_alert

                *

                100,

                2

            )

        quality = pd.DataFrame({

            "Metric": [

                "Alert Total",

                "Matched",

                "Unknown",

                "Accuracy (%)"

            ],

            "Value": [

                total_alert,

                matched,

                unknown,

                accuracy

            ]

        })

        self.data["mapping_quality"] = quality

    # =====================================================
    # Summary
    # =====================================================

    def validation_summary(self):

        summary = pd.DataFrame({

            "Check": [

                "Unknown Rule",

                "Missing Priority",

                "Missing Owner",

                "Missing Severity",

                "Duplicate Master Rule"

            ],

            "Total": [

                len(self.data["unknown_rule"]),

                len(self.data["missing_priority"]),

                len(self.data["missing_owner"]),

                len(self.data["missing_severity"]),

                len(self.data["duplicate_master"])

            ]

        })

        self.data["validation_summary"] = summary

    # =====================================================
    # RUN
    # =====================================================

    def run(self):

        print()

        print("=" * 60)

        print("VALIDATION")

        print("=" * 60)

        self.validate_unknown_rule()

        self.validate_priority()

        self.validate_owner()

        self.validate_severity()

        self.validate_duplicate_master()

        self.validate_alert_incident()

        self.mapping_quality()

        self.validation_summary()

        print("Validation Complete")

        print()

        return self.data