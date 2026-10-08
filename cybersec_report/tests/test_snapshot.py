import tempfile
import unittest
from pathlib import Path

import pandas as pd

from cybersec_report.core import snapshot as S
from cybersec_report.tests._helpers import make_pipeline


class TestSnapshot(unittest.TestCase):
    def test_roundtrip_matches_live(self):
        pl = make_pipeline()
        vm = pl.view_model()
        d = Path(tempfile.mkdtemp())
        path = S.save_snapshot(vm, directory=d)
        self.assertEqual(path.name, "IPS_2026-09.json")
        back = S.load_snapshot(path)
        a, b = vm["sections"][0], back["sections"][0]
        self.assertEqual(a["total_events"], b["total_events"], 939)
        for key in ("severity", "top_attacks", "top_destination", "top_country", "source_profile"):
            pd.testing.assert_frame_equal(a[key].reset_index(drop=True), b[key].reset_index(drop=True),
                                          check_dtype=False, check_exact=False)
        for sev in a["top_by_severity"]:
            pd.testing.assert_frame_equal(a["top_by_severity"][sev], b["top_by_severity"][sev], check_dtype=False)
        self.assertEqual(vm["findings"][a["name"]], back["findings"][a["name"]])
        self.assertEqual(back["period"]["report_month"], 9)
        self.assertEqual(back["period"]["start_date"].isoformat(), "2026-09-01")

    def test_list_skips_corrupt_and_sorts(self):
        pl = make_pipeline()
        d = Path(tempfile.mkdtemp())
        S.save_snapshot(pl.view_model(), directory=d)
        (d / "IPS_2026-08.json").write_text("{rusak", encoding="utf-8")
        rows = S.list_snapshots(d)
        self.assertEqual([r["label"] for r in rows], ["IPS-September-2026 (format lama, semua hostname)"])
        self.assertEqual(rows[0]["total_events"], 939)

    def test_nan_reputation_survives(self):
        pl = make_pipeline()
        vm = pl.view_model()
        path = S.save_snapshot(vm, directory=Path(tempfile.mkdtemp()))
        prof = S.load_snapshot(path)["rep"][vm["sections"][0]["name"]]["profile"]
        self.assertTrue(prof["Threat Score"].isna().all())
        self.assertEqual(set(prof["Risk Level"]), {"Not assessed"})


if __name__ == "__main__":
    unittest.main()
