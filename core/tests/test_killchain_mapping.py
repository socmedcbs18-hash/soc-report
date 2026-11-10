"""Tes mapping rule -> Kill Chain/MITRE, severity Exploitation=Critical, gap alert vs tiket,
Valid Accounts, validasi ATT&CK v20. Semua data SINTETIS (bukan data riil)."""
import unittest

import pandas as pd

from core.rule_mapping import lookup_rule, rule_stages, apply_rule_mapping
from core.mitre_killchain import validate_technique
from core.killchain_analysis import (
    normalize_severity, add_effective_severity, build_killchain_alert_breakdown,
    build_valid_accounts_insight, use_ticket_labels,
)
from utils.helpers import normalize_incident_columns

WEBSHELL = "APPLICATIONS - [ALTO-ESV3] TTX WebShell Altoconnect Detail - Rule"


class TestSummaryAlias(unittest.TestCase):
    def test_incident_name_becomes_summary(self):
        df = normalize_incident_columns(pd.DataFrame({"Ticket Number": ["1"], "Incident Name": ["Rule A"], "Priority": ["1"]}))
        self.assertEqual(df["Summary"].tolist(), ["Rule A"])


class TestRuleMapping(unittest.TestCase):
    def test_known_rule(self):
        r = lookup_rule(WEBSHELL)
        self.assertEqual(r["kc"], "Installation")
        self.assertEqual(rule_stages(WEBSHELL), ["Installation"])
        self.assertEqual(r["severity_rek"], "critical")

    def test_unknown_rule_is_none(self):
        self.assertIsNone(lookup_rule("rule yang tidak ada sama sekali"))

    def test_apply_keeps_ticket_label_for_unknown_and_nan_name(self):
        d = pd.DataFrame({"Summary": [WEBSHELL, "zzz", None],
                          "Incident MITRE": ["[]", "[T1110]", "[]"],
                          "Incident KillChain": ["[Reconnaissance]", "[Delivery]", "[]"]})
        o = apply_rule_mapping(d)
        self.assertEqual(o.loc[0, "Incident KillChain"], "[Installation]")
        self.assertEqual(o.loc[0, "Incident KillChain (Ivanti)"], "[Reconnaissance]")
        self.assertEqual(o.loc[1, "Incident KillChain"], "[Delivery]")
        self.assertEqual(len(o), 3)


class TestSeverity(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_severity("CRITICAL"), "Critical")
        self.assertEqual(normalize_severity("-"), "Tidak diketahui")
        self.assertEqual(normalize_severity(None), "Tidak diketahui")

    def test_exploitation_and_later_become_critical(self):
        df = pd.DataFrame({"Severity": ["low", "low", "high", "medium"],
                           "_KillChain_Stages": [["Exploitation"], ["Reconnaissance"], ["Command & Control"], []]})
        o = add_effective_severity(df)
        self.assertEqual(o["_Severity_Efektif"].tolist(), ["Critical", "Low", "Critical", "Medium"])
        self.assertEqual(o["_Severity_Naik"].tolist(), [True, False, True, False])


class TestAlertBreakdown(unittest.TestCase):
    def test_gap(self):
        alert = pd.DataFrame({"Alert Name": [WEBSHELL] * 5})
        inc = pd.DataFrame({"Incident": ["1", "2"], "Summary": [WEBSHELL] * 2})
        stage, rule = build_killchain_alert_breakdown(alert, inc)
        row = stage[stage["Kelompok"] == "Installation"].iloc[0]
        self.assertEqual((row["Alert"], row["Tiket"], row["Gap_Alert_minus_Tiket"]), (5, 2, 3))

    def test_empty_alert_does_not_crash(self):
        stage, _ = build_killchain_alert_breakdown(pd.DataFrame(), pd.DataFrame({"Incident": ["1"], "Summary": [WEBSHELL]}))
        self.assertEqual(int(stage["Tiket"].sum()), 1)


class TestValidAccounts(unittest.TestCase):
    def test_fp_heavy_rule_flagged(self):
        n = 12
        df = pd.DataFrame({"Incident": [str(i) for i in range(n)], "Summary": ["Rule VA"] * n,
                           "_MITRE_Techniques": [["T1078"]] * n,
                           "_MITRE_Techniques_Tiket": [["T1078"]] * n,
                           "_Triage": ["False Positive"] * 10 + ["True Positive"] * 2})
        summ, rules = build_valid_accounts_insight(df)
        self.assertEqual(summ["total_tiket"], n)
        self.assertEqual(rules.iloc[0]["Perlu_Tuning"], "Ya")


class TestAttackValidation(unittest.TestCase):
    def test_revoked_has_replacement(self):
        v = validate_technique("T1562.001")
        self.assertEqual(v["status"], "revoked")
        self.assertEqual(v["pengganti"], "T1685")
        self.assertEqual(validate_technique("T1078")["status"], "ok")


class TestUseTicketLabels(unittest.TestCase):
    def test_swap(self):
        df = pd.DataFrame({c: [["a"]] for c in ["_KillChain_Stages", "_KillChain_Invalid", "_MITRE_Tactics", "_MITRE_Techniques", "_MITRE_Invalid"]})
        for c in list(df.columns):
            df[c + "_Tiket"] = [["b"]]
        self.assertEqual(use_ticket_labels(df)["_KillChain_Stages"].iloc[0], ["b"])
        self.assertIs(use_ticket_labels(df[["_KillChain_Stages"]]).columns.tolist()[0], "_KillChain_Stages")


if __name__ == "__main__":
    unittest.main()


class TestStateMachineDurations(unittest.TestCase):
    def _inc(self):
        t0 = pd.Timestamp("2026-10-01 10:00:00")
        m = lambda x: t0 + pd.Timedelta(minutes=x)
        return pd.DataFrame({
            "Created On": [t0, t0, t0, t0],
            "Responded On": [m(1), m(6), None, m(2)],           # tiket 2 > 5 menit; tiket 3 tanpa Active
            "Contained On": [m(11), m(16), None, m(1)],         # tiket 4: Contained lebih awal dari Active
            "Resolved On": [m(12), m(30), m(40), m(50)],
            "Closed On": [m(13), m(31), m(41), m(51)],
        })

    def test_intervals_follow_state_machine(self):
        from core.processor import compute_state_durations
        d = compute_state_durations(self._inc())
        self.assertEqual(d["MTTR_sec"].iloc[0], 60)
        self.assertEqual(d["MTTC_sec"].iloc[0], 600)      # Active -> Contained
        self.assertEqual(d["MTTRV_sec"].iloc[0], 60)      # Contained -> Resolved
        self.assertEqual(d["Resolusi_Total_sec"].iloc[1], 1800)
        self.assertTrue(pd.isna(d["MTTC_sec"].iloc[3]))   # urutan terbalik tidak dihitung
        self.assertTrue(pd.isna(d["MTTR_sec"].iloc[2]))
        self.assertEqual(int(d.attrs["quality"].set_index("Pemeriksaan").loc["Punya Contained On", "Jumlah"]), 3)

    def test_without_contained_column_falls_back(self):
        from core.processor import compute_state_durations
        d = compute_state_durations(self._inc().drop(columns=["Contained On"]))
        self.assertTrue(d["MTTC_sec"].isna().all())
        self.assertFalse(d.attrs["mttrv_from_contained"])
        self.assertEqual(d["MTTRV_sec"].iloc[1], 1800)

    def test_breach_is_created_to_active_over_5_minutes(self):
        from core.processor import SOCProcessor
        p = SOCProcessor.__new__(SOCProcessor)
        p.incident = self._inc()
        p._compute_incident_breach_flag()
        self.assertEqual(p.incident["_Breach"].tolist(), [False, True, False, False])


class TestProposedLabels(unittest.TestCase):
    NAME = "Infrastructure - [ALTO-ESV3] AKR Repeated Denied Access to ADAMA & WEBMONI - Rule"

    def test_proposed_rule_label_applied_and_flagged(self):
        import core.rule_mapping as rm
        d = pd.DataFrame({"Summary": [self.NAME], "Incident MITRE": ["[]"], "Incident KillChain": ["[Delivery]"]})
        old = rm._APPLY_PROPOSED
        try:
            rm._APPLY_PROPOSED = True
            o = rm.apply_rule_mapping(d)
            self.assertEqual(o.loc[0, "Incident KillChain"], "[Reconnaissance]")
            self.assertEqual(o.loc[0, "_Label_Source"], rm.SRC_PROPOSED)
            rm._APPLY_PROPOSED = False
            o = rm.apply_rule_mapping(d)
            self.assertEqual(o.loc[0, "Incident KillChain"], "[Delivery]")
        finally:
            rm._APPLY_PROPOSED = old


class TestTicketContext(unittest.TestCase):
    EX = "Applications - [ESV3] - O365 Exfiltration via File Download - Rule"

    def _r(self, rule, desc, mitre="[TA0009, T1530]", kc="[Actions on Objectives]"):
        from core.ticket_context import refine_ticket
        return refine_ticket(rule, desc, mitre, kc)

    def test_internal_download_not_a_killchain_stage(self):
        m, k, c, ch = self._r(self.EX, "count: 109 signature: FileDownloaded user: ryan@alto.id")
        self.assertEqual((m, k, ch), ("[TA0009, T1530]", "[]", True))

    def test_internal_sync_cleared(self):
        m, k, c, ch = self._r(self.EX, "count: 95 signature: FileSyncDownloadedFull user: novi@alto.id")
        self.assertEqual((m, k), ("[]", "[]"))

    def test_external_and_anonymous_keep_aoo(self):
        for u in ("niconsamuel10@gmail.com", "urn:spo:tenantanon#abc"):
            m, k, c, ch = self._r(self.EX, f"count: 5 signature: FileDownloaded user: {u}")
            self.assertEqual((k, ch), ("[Actions on Objectives]", False))

    def test_missing_identity_keeps_rule_label_but_says_so(self):
        m, k, c, ch = self._r(self.EX, "The alert condition ... was triggered.")
        self.assertEqual((k, ch), ("[Actions on Objectives]", False))
        self.assertIn("belum bisa diverifikasi", c)

    def test_cynet_subrule_from_description(self):
        rule = "Infrastructure - [ALTO-ESV3] Cynet - Unauthorized File Operation Attempt - Rule"
        d = "Host ID 1  Rule Name IOF - Credentials Theft - MasterKey - Not Signed Process - AF  Process Command Line x"
        self.assertEqual(self._r(rule, d, "[TA0040, T1485]", "[Actions on Objectives]")[:2], ("[TA0006, T1555]", "[Exploitation]"))
        d = "Rule Name IOF - Ransomware Extension Found - KWABN  Process Command Line x"
        self.assertEqual(self._r(rule, d)[1], "[Actions on Objectives]")
        d = "Rule Name IOF - Tar - Extracting Files From Remote Host  Process Command Line x"
        self.assertEqual(self._r(rule, d)[:2], ("[]", "[]"))


class TestOutcomeAwareStaging(unittest.TestCase):
    def _kc(self, name):
        import core.rule_mapping as rm
        d = pd.DataFrame({"Summary": [name], "Incident MITRE": ["[]"], "Incident KillChain": ["[Exploitation]"]})
        return rm.apply_rule_mapping(d).loc[0, "Incident KillChain"]

    def test_failed_or_blocked_attempt_is_delivery_not_exploitation(self):
        for n in ["Applications - [ESV3] - O365 High Number Of Failed Authentications for User - Rule",
                  "Infrastructure - [ALTO-ESV3] Akamai WAF - SQL Injection Attempt Detected. - Rule"]:
            self.assertEqual(self._kc(n), "[Delivery]", n)

    def test_webmoni_denied_scan_is_reconnaissance(self):
        self.assertEqual(self._kc("Infrastructure - [ALTO-ESV3] AKR - WebMoni - Public IP Traffic Detection - Rule"),
                         "[Reconnaissance]")
