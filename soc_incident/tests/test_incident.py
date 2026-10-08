import tempfile
import unittest
from pathlib import Path

import pandas as pd

from soc_incident import loader, processor as P, snapshot as S
from soc_incident.tests._helpers import CUTOVER, make_df, make_raw


class TestLoader(unittest.TestCase):
    def test_missing_required_column_is_reported_not_guessed(self):
        raw = make_raw().drop(columns=["Priority"])
        with self.assertRaises(loader.LoaderError) as cm:
            loader.normalize(raw, loader.detect_mapping(raw.columns))
        self.assertIn("priority", str(cm.exception))

    def test_duplicates_dropped_with_note(self):
        raw = make_raw()
        raw = pd.concat([raw, raw.iloc[:3]])
        df, notes = loader.normalize(raw, loader.detect_mapping(raw.columns))
        self.assertEqual(len(df), 110)
        self.assertTrue(any("duplikat" in n for n in notes))

    def test_system_customer_flag(self):
        df = make_df()
        self.assertTrue(df.loc[df["customer"] == "Alert Splunk", "is_auto"].all())
        self.assertFalse(df.loc[df["customer"] == "Budi Santoso", "is_auto"].any())


class TestCutover(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = make_df()

    def test_detected_at_first_new_style_ticket(self):
        det = P.detect_cutover(self.df)
        first_new = self.df[self.df["created"] >= CUTOVER].iloc[0]
        self.assertEqual(det["cutover"], first_new["created"])
        self.assertEqual(det["first_ticket"], int(first_new["ticket"]))
        self.assertLess(det["last_old_ticket"], det["first_ticket"])

    def test_none_when_single_style(self):
        old_only = self.df[self.df["created"] < CUTOVER]
        new_only = self.df[self.df["created"] >= CUTOVER]
        self.assertIsNone(P.detect_cutover(old_only)["cutover"])
        self.assertIsNone(P.detect_cutover(new_only)["cutover"])

    def test_tiny_tail_is_not_a_cutover(self):
        small = pd.concat([self.df[self.df["created"] < CUTOVER], self.df[self.df["created"] >= CUTOVER].head(5)])
        self.assertIsNone(P.detect_cutover(small)["cutover"])


class TestAnalyze(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = make_df()
        cls.res = P.analyze(cls.df)

    def test_eras_sum_to_total(self):
        r = self.res
        self.assertEqual(r["eras"], ["old", "new"])
        self.assertEqual(r["stats"]["old"]["tickets"] + r["stats"]["new"]["tickets"], r["total"]["tickets"], 110)
        self.assertEqual(int(r["daily"]["Total"].sum()), 110)
        self.assertEqual(int(r["owners"]["Total"].sum()), 110)
        self.assertEqual(int(r["hourly"]["Total"].sum()), 110)

    def test_priority_table_matches_raw(self):
        raw = self.df.groupby("priority").size()
        got = self.res["priority"].sum(axis=1)
        self.assertEqual(sorted(got.tolist()), sorted(raw.tolist()))

    def test_breach_count_from_flag(self):
        want = int((self.df["breach_resp"] > 0).sum())
        self.assertEqual(self.res["total"]["breach_n"], want)
        self.assertEqual(len(self.res["breaches"]), want)
        self.assertEqual(self.res["stats"]["old"]["breach_n"] + self.res["stats"]["new"]["breach_n"], want)

    def test_weekly_starts_on_sunday_and_sums(self):
        ws = P._week_start(self.df["created"])
        self.assertTrue((ws.dt.dayofweek == 6).all())
        self.assertEqual(int(self.res["weekly"]["Tiket"].sum()), 110)
        self.assertEqual(int(self.res["weekly"]["Ada cutover"].sum()), 1)

    def test_per_day_uses_each_eras_own_duration(self):
        o = self.res["stats"]["old"]
        self.assertAlmostEqual(o["per_day"], o["tickets"] / o["days"])
        self.assertAlmostEqual(o["days"], (CUTOVER - pd.Timestamp("2026-09-01")).total_seconds() / 86400, delta=1.0)

    def test_schema_shows_fields_stopped(self):
        sc = self.res["schema"].set_index("Field")
        self.assertEqual(sc.loc["Sub_Issue", "Terisi era baru"], 0.0)
        self.assertGreater(sc.loc["Sub_Issue", "Terisi era lama"], 90)

    def test_category_tables_only_old_era(self):
        self.assertEqual(int(self.res["sub_issue"]["Tiket"].sum()), self.res["stats"]["old"]["tickets"])

    def test_insights_hedged_and_flag_limits(self):
        txt = " ".join(i["text"] for i in self.res["insights"])
        self.assertIn("MTTC", txt)
        self.assertIn("belum bisa dipastikan", txt)
        import re
        for forbidden in (r"kompromi", r"diretas", r"serangan berhasil", r"\bpasti\b"):
            self.assertIsNone(re.search(forbidden, txt.lower()), forbidden)
        self.assertTrue(any(i["level"] == "watch" and i["topic"] == "Prioritas" for i in self.res["insights"]))
        self.assertTrue(any(i["level"] == "limit" and i["topic"] == "Resolusi" for i in self.res["insights"]))

    def test_headline_does_not_sum_p1_across_eras(self):
        h = P.executive_headlines(self.res)[0]
        self.assertIn("tidak dijumlahkan", h)

    def test_manual_cutover_and_invalid_override(self):
        r = P.analyze(self.df, cutover=pd.Timestamp("2026-09-20 00:00"))
        self.assertEqual(r["cutover"], pd.Timestamp("2026-09-20"))
        self.assertTrue(r["cutover_manual"])
        bad = P.analyze(self.df, cutover=pd.Timestamp("2026-12-01"))
        self.assertEqual(bad["eras"], ["all"])
        self.assertTrue(any("diabaikan" in n for n in bad["notes"]))
        none = P.analyze(self.df, cutover=None, single_era="new")
        self.assertEqual(none["eras"], ["new"])

    def test_other_month_tickets_excluded_with_note(self):
        df = make_df()
        extra = df.iloc[:2].copy()
        extra["created"] = pd.Timestamp("2026-08-30 10:00")
        extra["ticket"] = [1, 2]
        r = P.analyze(pd.concat([df, extra]))
        self.assertEqual(r["total"]["tickets"], 110)
        self.assertTrue(any("di luar bulan" in n for n in r["notes"]))

    def test_excel_export_has_no_customer_or_email(self):
        out = Path(tempfile.mkdtemp()) / "x.xlsx"
        P.to_excel(self.res, out)
        x = pd.ExcelFile(out)
        self.assertIn("Tiket", x.sheet_names)
        cols = x.parse("Tiket").columns
        self.assertNotIn("customer", cols)
        self.assertNotIn("email", [c.lower() for c in cols])


class TestSnapshotCompare(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        sep = P.analyze(make_df())
        octo = P.analyze(make_df(month=10, new_only=True, n_new=120, seed=3), cutover=None, single_era="new")
        self.sep, self.oct = sep, octo
        self.ps = S.save_snapshot(sep, "sep.xlsx", P.executive_headlines(sep), self.dir)
        self.po = S.save_snapshot(octo, "oct.xlsx", P.executive_headlines(octo), self.dir)

    def test_roundtrip_and_list(self):
        snap = S.load_snapshot(self.ps)
        self.assertEqual(snap["total"]["tickets"], 110)
        self.assertEqual(snap["eras"], ["old", "new"])
        self.assertEqual([x["label"] for x in S.list_snapshots(self.dir)], ["SOC-Incident-Oktober-2026", "SOC-Incident-September-2026"])

    def test_snapshot_has_no_ticket_level_data(self):
        txt = self.ps.read_text(encoding="utf-8")
        for needle in ("Budi Santoso", "x@alto.id", "Alert Splunk"):
            self.assertNotIn(needle, txt)

    def test_compare_latest_era_uses_new_era_of_september(self):
        a, b = S.load_snapshot(self.ps), S.load_snapshot(self.po)
        c = S.compare_months(a, b, "latest")
        t = {r["key"]: r for r in c["table"]}
        self.assertEqual(t["tickets"]["A"], self.sep["stats"]["new"]["tickets"])
        self.assertEqual(t["tickets"]["B"], 120)
        self.assertFalse(any("tidak ditandai" in n for n in c["notes"]))  # kedua sisi era baru
        self.assertTrue(any("baru berjalan" in n for n in c["notes"]))   # era baru September baru ±13 hari -> peringatan laju per hari

    def test_compare_total_warns_when_month_has_two_eras(self):
        c = S.compare_months(S.load_snapshot(self.ps), S.load_snapshot(self.po), "total")
        self.assertTrue(any("dua state machine" in n for n in c["notes"]))

    def test_compare_warns_when_month_not_marked_new(self):
        unk = P.analyze(make_df(month=10, new_only=True, n_new=40, seed=4), cutover=None, single_era="all")
        p = S.save_snapshot(unk, "u.xlsx", [], Path(tempfile.mkdtemp()))
        c = S.compare_months(S.load_snapshot(self.ps), S.load_snapshot(p), "latest")
        self.assertTrue(any("tidak ditandai" in n for n in c["notes"]))

    def test_delete_only_inside_snapshot_dir(self):
        self.assertTrue(S.delete_snapshot(self.ps, self.dir))
        outside = Path(tempfile.mkdtemp()) / "x.json"
        outside.write_text("{}")
        with self.assertRaises(ValueError):
            S.delete_snapshot(outside, self.dir)
        self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
