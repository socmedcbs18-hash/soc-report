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
