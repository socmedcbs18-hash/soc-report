"""Regresi: export Ivanti Sept 2026 memakai 'IncidentMitre'/'IncidentKillChain' (tanpa spasi) - harus terbaca
sebagai 'Incident MITRE'/'Incident KillChain'. Data uji SINTETIS."""
import unittest

import pandas as pd

from core.mitre_killchain import enrich_incident_mitre_killchain, MITRE_TECHNIQUE_NAMES, MITRE_TACTIC_NAMES
from utils.helpers import normalize_incident_columns


def _frame(mitre="IncidentMitre", kc="IncidentKillChain"):
    return pd.DataFrame({"Ticket Number": ["1", "2", "3"], "Priority": ["1", "2", "3"],
                         mitre: ["[TA0006, T1110.001]", "[T1078,T1078.004]", None],
                         kc: ["[Delivery]", "[Exploitation, Installation]", "[]"],
                         "Triage": ["True Positive", "False Positive", None]})


class TestIncidentColumns(unittest.TestCase):
    def test_new_header_is_aliased_and_parsed(self):
        df = normalize_incident_columns(_frame())
        self.assertIn("Incident MITRE", df.columns)
        self.assertIn("Incident KillChain", df.columns)
        self.assertNotIn("IncidentMitre", df.columns)
        e = enrich_incident_mitre_killchain(df)
        self.assertEqual(e["_MITRE_Tactics"].tolist(), [["TA0006"], [], []])
        self.assertEqual(e["_MITRE_Techniques"].tolist()[1], ["T1078", "T1078.004"])
        self.assertEqual(e["_KillChain_Stages"].tolist(), [["Delivery"], ["Exploitation", "Installation"], []])
        self.assertEqual(e["_Triage"].tolist(), ["True Positive", "False Positive", "Unknown"])

    def test_old_header_still_works_and_variants(self):
        for m, k in (("Incident MITRE", "Incident KillChain"), ("incident_mitre", "Incident_KillChain"), ("INCIDENT MITRE", "incidentkillchain")):
            df = normalize_incident_columns(_frame(m, k))
            self.assertIn("Incident MITRE", df.columns, m)
            self.assertIn("Incident KillChain", df.columns, k)

    def test_does_not_overwrite_existing_canonical_column(self):
        f = _frame("Incident MITRE", "Incident KillChain")
        f["IncidentMitre"] = "[T9999]"
        df = normalize_incident_columns(f)
        self.assertEqual(df["Incident MITRE"].iloc[0], "[TA0006, T1110.001]")

    def test_command_and_control_is_valid_stage_before_actions(self):
        from core.mitre_killchain import (KILLCHAIN_STAGE_ORDER, build_data_quality_report, build_killchain_funnel,
                                          build_killchain_summary)
        f = _frame()
        f["IncidentKillChain"] = ["[Command & Control]", "[command & control, Installation]", "[Actions on Objectives]"]
        e = enrich_incident_mitre_killchain(normalize_incident_columns(f))
        self.assertEqual(e["_KillChain_Stages"].tolist()[0], ["Command & Control"])
        self.assertEqual(e["_KillChain_Invalid"].tolist(), [[], [], []])
        self.assertEqual(KILLCHAIN_STAGE_ORDER[-2:], ["Command & Control", "Actions On Objectives"])
        s = build_killchain_summary(e).set_index("Stage")["Count"]
        self.assertEqual(int(s["Command & Control"]), 2)
        self.assertEqual(list(build_killchain_summary(e)["Stage"]), KILLCHAIN_STAGE_ORDER)
        fn = build_killchain_funnel(e).set_index("Stage")["Reached_At_Least"]
        self.assertEqual(int(fn["Command & Control"]), 3)   # 2 tiket C2 + 1 tiket Actions (tahap lebih lanjut)
        self.assertEqual(len(build_data_quality_report(e)), 0)

    def test_new_names_present(self):
        for t in ("T1059", "T1071.001", "T1090", "T1583.004", "T1580", "T1201"):
            self.assertIn(t, MITRE_TECHNIQUE_NAMES)
        self.assertIn("TA0011", MITRE_TACTIC_NAMES)


if __name__ == "__main__":
    unittest.main()
