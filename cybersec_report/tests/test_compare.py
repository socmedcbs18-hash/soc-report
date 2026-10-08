import tempfile
import unittest
from pathlib import Path

import pandas as pd

from cybersec_report.core.compare import compare_sections
from cybersec_report.tests._helpers import FIXTURE, make_pipeline


def shifted_pipeline():
    """'Oktober' sintetis: P1FWX0209 saja, count setengahnya, satu signature dihapus, satu IP baru."""
    df = pd.read_csv(FIXTURE, sep=None, engine="python", dtype=str)
    df = df[df["devname"] == "P1FWX0209"].copy()
    df["count"] = (df["count"].astype(float) // 2).clip(lower=1).astype(int).astype(str)
    df = df[df["attack"] != "Bladabindi.Botnet"]
    new = df.iloc[[0]].copy()
    new["srcip"], new["attack"], new["count"], new["severity"] = "203.0.113.77", "Brand.New.Exploit", "9", "critical"
    df = pd.concat([df, new])
    tmp = Path(tempfile.mkdtemp()) / "IPS_Oct_2026.csv"
    df.to_csv(tmp, index=False)
    return make_pipeline(tmp, split_by="device")


class TestCompare(unittest.TestCase):
    def test_compare_two_months(self):
        sep = make_pipeline(split_by="device").sections[0]
        octo = shifted_pipeline().sections[0]
        c = compare_sections(sep, octo)
        k = c["kpi"].set_index("Metric")
        self.assertEqual(k.loc["Total events", "A"], 914.0)
        self.assertEqual(k.loc["Total events", "B"], octo["total_events"])
        self.assertEqual(k.loc["Total events", "Δ"], octo["total_events"] - 914.0)
        att = c["attacks"].set_index("Attack")
        self.assertEqual(att.loc["Bladabindi.Botnet", "Trend"], "✕ Gone")
        self.assertEqual(att.loc["Brand.New.Exploit", "Trend"], "★ New")
        self.assertEqual(att.loc["Brand.New.Exploit", "Severity"], "Critical")
        ips = c["source_ips"].set_index("Source IP")
        self.assertEqual(ips.loc["203.0.113.77", "Status"], "Baru di B")
        self.assertEqual(c["warnings"], [])
        # jumlah A di tabel attack = total A (tidak ada event hilang saat merge)
        self.assertEqual(c["attacks"]["A"].sum(), 914.0)
        self.assertEqual(c["countries"]["A"].sum(), 914.0)

    def test_different_hostname_warns(self):
        pl = make_pipeline(split_by="device")
        c = compare_sections(pl.sections[0], pl.sections[1])
        self.assertEqual(len(c["warnings"]), 1)
        self.assertIn("Hostname berbeda", c["warnings"][0])

    def test_identical_is_stable(self):
        a = make_pipeline(split_by="device").sections[0]
        c = compare_sections(a, a)
        self.assertTrue((c["kpi"]["Δ"] == 0).all())
        self.assertTrue((c["kpi"]["Trend"] == "→ Stable").all())


if __name__ == "__main__":
    unittest.main()
