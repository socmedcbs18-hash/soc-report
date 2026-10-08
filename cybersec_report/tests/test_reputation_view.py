import tempfile
import unittest
from pathlib import Path

import pandas as pd

from cybersec_report.core import reputation as R
from cybersec_report.tests._helpers import FakeSession, Resp, make_pipeline
from cybersec_report.tests.test_ui_smoke import StubStreamlit, UIHarness
from cybersec_report.threat_intel import VirusTotalProvider


def vt_resp(mal):
    return Resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": 1, "harmless": 70, "undetected": 20},
                                              "as_owner": "ACME NET"}}})


def run_rep(pl, n=10):
    prov = VirusTotalProvider(api_key="k", session=FakeSession(lambda u, p: vt_resp(12 if "66.240.205.34" in u else 0)),
                              sleep=lambda s: None)
    pl.run_reputation({"virustotal": True}, n, cache_path=tempfile.mktemp(suffix=".sqlite"), sleep=lambda s: None, providers=[prov])
    return pl


class TestReputationEvidence(unittest.TestCase):
    def test_profile_has_evidence_and_interpretation(self):
        pl = run_rep(make_pipeline())
        prof = pl.rep[pl.sections[0]["name"]]["profile"]
        bad = prof[prof["Source IP"] == "66.240.205.34"].iloc[0]
        self.assertEqual(bad["Risk Level"], "Critical")
        self.assertEqual(bad["VT Engines"], 103)
        self.assertIn("VirusTotal: 12 malicious + 1 suspicious dari 103 engine", bad["Evidence"])
        self.assertNotIn("AbuseIPDB", bad["Evidence"])          # provider yang tidak dipanggil tidak boleh muncul
        self.assertEqual(bad["Interpretation"], "Sangat mencurigakan menurut provider")
        self.assertEqual(bad["AS / ISP"], "ACME NET")
        clean = prof[(prof["TI Status"] == "CHECKED") & (prof["Source IP"] != "66.240.205.34")].iloc[0]
        self.assertEqual(clean["Risk Level"], "Low")            # 0 malicious + 0,5 x 1 suspicious = skor 5 -> Low
        self.assertEqual(clean["Interpretation"], "Tidak terindikasi menurut provider")

    def test_unchecked_ip_is_not_assessed_not_safe(self):
        pl = make_pipeline()
        prof = pl.rep[pl.sections[0]["name"]]["profile"]
        self.assertEqual(set(prof["Interpretation"]), {"Belum dicek (bukan berarti aman)"})


class TestActionBreakdown(unittest.TestCase):
    def test_all_dropped_in_fixture(self):
        pl = make_pipeline()
        ab = pd.concat([a["action_breakdown"] for a in pl.sections])
        self.assertEqual(ab["Action"].unique().tolist(), ["dropped"])
        self.assertEqual(ab["Events"].sum(), 939)
        self.assertTrue(ab["Counted"].all())

    def test_detected_rows_are_visible_but_not_counted(self):
        raw = Path(__file__).parent / "fixtures" / "IPS_Sep_2026.csv"
        df = pd.read_csv(raw, sep=None, engine="python", dtype=str)
        df.loc[df.index[:10], "action"] = "detected"
        tmp = Path(tempfile.mkdtemp()) / "IPS_Sep_2026.csv"
        df.to_csv(tmp, index=False)
        pl = make_pipeline(tmp)
        ab = pd.concat([a["action_breakdown"] for a in pl.sections]).groupby(["Action", "Counted"])["Events"].sum()
        self.assertTrue(ab[("detected", False)] > 0)
        self.assertEqual(sum(a["total_events"] for a in pl.sections) + ab[("detected", False)], 939)


class TestViewWithReputation(UIHarness, unittest.TestCase):
    def test_dashboard_renders_saved_snapshot_with_reputation(self):
        from cybersec_report.core import snapshot
        pl = run_rep(make_pipeline())
        snapshot.save_snapshot(pl.view_model())
        stub = StubStreamlit()
        self._run(stub)
        self.assertNotIn("error", stub.calls)
        self.assertNotIn("exception", stub.calls)
        html = "".join(stub.html)
        self.assertIn("IP dicek", html)
        self.assertIn("dropped", html)

    def test_old_snapshot_without_new_columns_still_renders(self):
        from cybersec_report.core import snapshot
        pl = make_pipeline()
        vm = pl.view_model()
        for a in vm["sections"]:
            a.pop("action_breakdown", None)
            p = vm["rep"][a["name"]]["profile"]
            vm["rep"][a["name"]]["profile"] = p[[c for c in p.columns if c in ("Source IP", "Country", "Attack Count", "Unique Attack",
                                                 "Unique Destination", "Critical", "High", "Top Attack", "VT Malicious",
                                                 "AbuseIPDB Score", "Threat Score", "Risk Level", "TI Status")]]
        snapshot.save_snapshot(vm)
        stub = StubStreamlit()
        self._run(stub)
        self.assertNotIn("exception", stub.calls)




class TestCachedReputation(unittest.TestCase):
    def test_second_upload_reuses_cache_without_any_api_call(self):
        cache = tempfile.mktemp(suffix=".sqlite")
        pl1 = make_pipeline(split_by="device")
        sess = FakeSession(lambda u, p: vt_resp(3))
        prov = VirusTotalProvider(api_key="k", session=sess, sleep=lambda s: None)
        pl1.run_reputation({"virustotal": True}, 5, cache_path=cache, sleep=lambda s: None, providers=[prov])
        n_calls = len(sess.calls)
        self.assertGreater(n_calls, 0)
        # "upload" kedua: pipeline baru, tanpa provider apa pun
        pl2 = make_pipeline(split_by="device")
        used = pl2.apply_cached_reputation(cache_path=cache)
        self.assertEqual(used, len({ip for ip in pl1.lookup["results"] if pl1.lookup["results"][ip]["providers"]}))
        prof = pl2.rep[pl2.sections[0]["name"]]["profile"]
        checked = prof[prof["TI Status"] == "CHECKED"]
        self.assertGreater(len(checked), 0)
        self.assertTrue((checked["VT Malicious"] == 3).all())
        self.assertEqual(len(sess.calls), n_calls)   # tidak ada request baru

    def test_run_reputation_keeps_cached_ips_outside_limit(self):
        cache = tempfile.mktemp(suffix=".sqlite")
        pl = make_pipeline(split_by="none")
        sess = FakeSession(lambda u, p: vt_resp(0))
        prov = VirusTotalProvider(api_key="k", session=sess, sleep=lambda s: None)
        pl.run_reputation({"virustotal": True}, 10, cache_path=cache, sleep=lambda s: None, providers=[prov])
        prov2 = VirusTotalProvider(api_key="k", session=FakeSession(lambda u, p: vt_resp(0)), sleep=lambda s: None)
        pl.run_reputation({"virustotal": True}, 5, cache_path=cache, sleep=lambda s: None, providers=[prov2])
        prof = pl.rep[pl.sections[0]["name"]]["profile"]
        self.assertEqual(int((prof["TI Status"] == "CHECKED").sum()), 10)   # 10 lama tetap tampil walau batas turun jadi 5
        self.assertEqual(prov2.session.calls, [])


if __name__ == "__main__":
    unittest.main()
