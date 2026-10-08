import tempfile
import unittest

import pandas as pd

from cybersec_report.core import analytics
from cybersec_report.core.audit import AuditLog
from cybersec_report.tests._helpers import FIXTURE, make_pipeline


class TestIPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pl = make_pipeline()
        cls.a = cls.pl.sections[0]
        cls.raw = pd.read_csv(FIXTURE, sep=";")

    def test_ips_total(self):
        # total attack = SUM(count), BUKAN jumlah baris; dibandingkan dengan perhitungan independen
        self.assertEqual(self.a["total_events"], float(self.raw["count"].sum()))
        self.assertEqual(self.a["total_events"], 939.0)
        self.assertEqual(self.a["reconciliation"]["raw_records_in_file"], 547)
        self.assertNotEqual(self.a["total_events"], len(self.raw))

    def test_severity_sum(self):
        self.assertEqual(self.a["severity"]["Count"].sum(), self.a["total_events"])
        got = self.a["severity"].set_index("Severity")["Count"].to_dict()
        want = self.raw.groupby("severity")["count"].sum().rename(str.title).to_dict()
        for k, v in want.items():
            self.assertEqual(got[k], v)

    def test_percentage_sum(self):
        for name, df in [("dest", self.a["top_destination"]), ("country", self.a["top_country"])] + \
                        list(self.a["top_by_severity"].items()):
            self.assertAlmostEqual(df["Percent"].sum(), 100.0, places=6, msg=str(name))

    def test_percentage_denominator_is_context(self):
        crit = self.a["top_by_severity"]["Critical"]
        total_critical = float(self.raw[self.raw.severity == "critical"]["count"].sum())
        top = crit.iloc[0]
        self.assertAlmostEqual(top["Percent"], top["Count"] / total_critical * 100, places=9)
        self.assertNotAlmostEqual(top["Percent"], top["Count"] / self.a["total_events"] * 100, places=3)

    def test_top_attack(self):
        top = self.a["top_attacks"].iloc[0]
        self.assertEqual(top["Attack Name"], "Nmap.Script.Scanner")
        self.assertEqual(top["Count"], 235)
        # Top-N: 16 attack unik -> Top 5 + Others
        self.assertEqual(len(self.a["top_attacks"]), 6)
        self.assertEqual(self.a["top_attacks"].iloc[-1]["Attack Name"], "Others")

    def test_top_n_small_list_shows_all_without_others(self):
        s = pd.Series({"a": 5, "b": 3, "c": 2})
        df = analytics.top_n_table(s, "X", 5)
        self.assertEqual(list(df["X"]), ["a", "b", "c"])

    def test_cross_validation_passes(self):
        self.assertEqual(self.pl.cross["overall"], "PASS")

    def test_audit_trail(self):
        log: AuditLog = self.pl.audit
        e = log.find("IPS (All Devices)", "total_events")
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["value"], 939.0)
        self.assertEqual(e[0]["calculation"], "SUM(count)")
        self.assertTrue(e[0]["source_file"].endswith("IPS_Sep_2026.csv"))
        self.assertIn("action", e[0]["filter"])
        import json
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            pass
        log.save(f.name)
        with open(f.name, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertGreater(len(data["entries"]), 20)

    def test_environment_split_sums_to_total(self):
        pl = make_pipeline()
        pl.settings["ips"]["split_by"] = "environment"
        pl.norm = pl.norm.assign(environment=pl.norm["device"].map({"P1FWX0209": "DCI", "P2FWX0109": "NTT"}))
        pl.analyze()
        self.assertEqual([s["environment"] for s in pl.sections], ["DCI", "NTT"])
        self.assertEqual(sum(s["total_events"] for s in pl.sections), 939.0)

    def test_split_per_hostname_is_default(self):
        pl = make_pipeline(split_by="device")
        self.assertEqual([s["name"] for s in pl.sections], ["IPS P1FWX0209", "IPS P2FWX0109"])
        self.assertEqual([s["hostname"] for s in pl.sections], ["P1FWX0209", "P2FWX0109"])
        self.assertEqual(sum(s["total_events"] for s in pl.sections), 939.0)
        self.assertEqual(pl.sections[0]["total_events"], 914.0)
        self.assertEqual(pl.sections[0]["label"], "P1FWX0209")
        self.assertTrue(all(c["status"] == "PASS" for c in pl.cross["checks"]))

    def test_hostname_label_shows_environment_when_mapped(self):
        pl = make_pipeline(split_by="device")
        pl.norm = pl.norm.assign(environment=pl.norm["device"].map({"P1FWX0209": "DCI"}).fillna("Unmapped"))
        pl.analyze()
        self.assertEqual([s["label"] for s in pl.sections], ["P1FWX0209 · DCI", "P2FWX0109"])

    def test_environment_mode_without_mapping_falls_back_not_guess(self):
        pl = make_pipeline()
        pl.settings["ips"]["split_by"] = "environment"
        pl.analyze()
        self.assertEqual([s["name"] for s in pl.sections], ["IPS (All Devices)"])


if __name__ == "__main__":
    unittest.main()
