import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from cybersec_report.core import reputation as R
from cybersec_report.core.config_loader import load_scoring, load_settings
from cybersec_report.core.scoring import compute_threat_score, risk_level
from cybersec_report.report.narrative import ai_payload
from cybersec_report.tests._helpers import FakeSession, Resp, make_pipeline
from cybersec_report.threat_intel import AbuseIPDBProvider, VirusTotalProvider
from cybersec_report.threat_intel.base import ProviderAuthError, ProviderError


def vt_ok(mal=0):
    return Resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": 0, "harmless": 80, "undetected": 5}}}})


def ab_ok(score=0, reports=0, last=None):
    return Resp(200, {"data": {"abuseConfidenceScore": score, "totalReports": reports, "lastReportedAt": last, "countryCode": "XX"}})


def engine(responder, vt=True, ab=True, key="k", cache=None, strategy="all"):
    import copy
    settings = copy.deepcopy(load_settings())
    settings["reputation"]["strategy"] = strategy
    sess = FakeSession(responder)
    sleeps = []
    provs = []
    if vt:
        provs.append(VirusTotalProvider(api_key=key, session=sess, sleep=sleeps.append, max_retries=1, backoff=0.01))
    if ab:
        provs.append(AbuseIPDBProvider(api_key=key, session=sess, sleep=sleeps.append, max_retries=1, backoff=0.01))
    cache = cache or R.ReputationCache(tempfile.mktemp(suffix=".sqlite"))
    return R.ReputationEngine(provs, cache, settings, sleep=sleeps.append), sess, sleeps


def ok_responder(url, params):
    return vt_ok(1) if "virustotal" in url else ab_ok(10, 2)


class TestReputation(unittest.TestCase):
    def test_private_ip_never_queried(self):
        eng, sess, _ = engine(ok_responder)
        out = eng.lookup(["10.0.0.1", "192.168.1.1", "bukan-ip", "8.8.8.8"])
        self.assertEqual(out["results"]["10.0.0.1"]["status"], "PRIVATE_IP")
        self.assertEqual(out["results"]["bukan-ip"]["status"], "INVALID_IP")
        self.assertEqual(out["stats"]["private_skipped"], 2)
        self.assertEqual(len(sess.calls), 2)  # hanya 8.8.8.8 x 2 provider
        self.assertTrue(all("10.0.0.1" not in str(c) for c in sess.calls))

    def test_reputation_cache(self):
        eng, sess, _ = engine(ok_responder)
        eng.lookup(["8.8.8.8"])
        first = len(sess.calls)
        out = eng.lookup(["8.8.8.8"])
        self.assertEqual(len(sess.calls), first)  # tidak ada request ulang
        self.assertEqual(out["stats"]["providers"]["virustotal"]["cached"], 1)

    def test_cache_ttl_expiry(self):
        now = [1000.0]
        cache = R.ReputationCache(tempfile.mktemp(suffix=".sqlite"), clock=lambda: now[0])
        cache.put("virustotal", "1.1.1.1", {"malicious": 1})
        self.assertIsNotNone(cache.get("virustotal", "1.1.1.1", 24))
        now[0] += 25 * 3600
        self.assertIsNone(cache.get("virustotal", "1.1.1.1", 24))

    def test_missing_api_key(self):
        eng, sess, _ = engine(ok_responder, key=None)
        out = eng.lookup(["8.8.8.8"])  # tidak boleh crash
        self.assertEqual(len(sess.calls), 0)
        self.assertEqual(out["results"]["8.8.8.8"]["status"], "UNAVAILABLE")
        self.assertIn("API key not configured", out["stats"]["providers"]["virustotal"]["state"])
        self.assertTrue(any("API key not configured" in l for l in out["log"]))

    def test_api_failure_isolated_per_provider(self):
        def responder(url, params):
            return Resp(500) if "virustotal" in url else ab_ok(50, 5)
        eng, _, _ = engine(responder)
        out = eng.lookup(["8.8.8.8"])
        r = out["results"]["8.8.8.8"]
        self.assertEqual(r["status"], "PARTIAL")
        self.assertIn("virustotal", r["errors"])
        self.assertIn("abuseipdb", r["providers"])
        # kegagalan tidak boleh di-cache
        self.assertIsNone(eng.cache.get("virustotal", "8.8.8.8", 24))

    def test_auth_error_disables_provider_and_stops_hammering(self):
        def responder(url, params):
            return Resp(401) if "virustotal" in url else ab_ok()
        eng, sess, _ = engine(responder)
        eng.lookup(["8.8.8.8", "8.8.4.4", "1.1.1.1"])
        vt_calls = [c for c in sess.calls if "virustotal" in c[0]]
        self.assertEqual(len(vt_calls), 1)

    def test_circuit_breaker(self):
        eng, sess, _ = engine(lambda u, p: Resp(500) if "virustotal" in u else ab_ok(), ab=True)
        ips = [f"8.8.8.{i}" for i in range(1, 11)]
        out = eng.lookup(ips)
        self.assertIn("disabled", out["stats"]["providers"]["virustotal"]["state"])
        self.assertLess(len([c for c in sess.calls if "virustotal" in c[0]]), 10 * 2)

    def test_retry_backoff_on_429(self):
        seq = [Resp(429, headers={"Retry-After": "3"}), vt_ok(2)]
        sess, sleeps = FakeSession(lambda u, p: seq.pop(0)), []
        prov = VirusTotalProvider(api_key="k", session=sess, sleep=sleeps.append, max_retries=2, backoff=0.5)
        self.assertEqual(prov.query_ip("8.8.8.8")["malicious"], 2)
        self.assertEqual(len(sess.calls), 2)
        self.assertGreaterEqual(sleeps[0], 3)  # menghormati Retry-After

    def test_provider_error_types(self):
        with self.assertRaises(ProviderAuthError):
            VirusTotalProvider(api_key="k", session=FakeSession(lambda u, p: Resp(403)), sleep=lambda s: None).query_ip("8.8.8.8")
        with self.assertRaises(ProviderError):
            VirusTotalProvider(api_key="k", session=FakeSession(lambda u, p: Resp(404)), sleep=lambda s: None).query_ip("8.8.8.8")

    def test_rate_limiter_spacing(self):
        t, slept = [0.0], []
        rl = R.RateLimiter(4, sleep=slept.append, clock=lambda: t[0])  # 4 rpm -> 15 detik
        rl.wait(); rl.wait()
        self.assertAlmostEqual(slept[0], 15.0)

    def test_scoring_bands_and_weights(self):
        cfg = load_scoring()
        now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.assertEqual(risk_level(0, cfg["bands"]), "Low")
        self.assertEqual(risk_level(19, cfg["bands"]), "Low")
        self.assertEqual(risk_level(20, cfg["bands"]), "Guarded")
        self.assertEqual(risk_level(59, cfg["bands"]), "Medium")
        self.assertEqual(risk_level(80, cfg["bands"]), "Critical")
        self.assertEqual(risk_level(None, cfg["bands"]), "Not assessed")
        clean = compute_threat_score({"virustotal": {"malicious": 0, "suspicious": 0}, "abuseipdb": {"abuseConfidenceScore": 0, "totalReports": 0, "lastReportedAt": None}}, cfg, now)
        self.assertEqual(clean["score"], 0.0)
        bad = compute_threat_score({"virustotal": {"malicious": 12, "suspicious": 0},
                                    "abuseipdb": {"abuseConfidenceScore": 100, "totalReports": 40, "lastReportedAt": "2026-09-30T00:00:00+00:00"}}, cfg, now)
        self.assertEqual(bad["score"], 100.0)
        self.assertEqual(bad["level"], "Critical")
        only_ab = compute_threat_score({"abuseipdb": {"abuseConfidenceScore": 100, "totalReports": 40, "lastReportedAt": "2026-09-30T00:00:00+00:00"}}, cfg, now)
        self.assertEqual(only_ab["score"], 100.0)  # bobot dinormalisasi ke komponen yang tersedia
        self.assertIsNone(compute_threat_score({}, cfg)["score"])

    def test_ip_selection_includes_top_volume_and_top_critical(self):
        pl = make_pipeline()
        sel = R.select_ips_for_lookup(pl.sections[0]["source_profile"], 10)
        self.assertEqual(len(sel), 10)
        self.assertIn("187.108.1.142", sel)   # volume terbesar (Low severity)
        self.assertIn("66.240.205.34", sel)   # Critical terbanyak
        self.assertEqual(len(R.select_ips_for_lookup(pl.sections[0]["source_profile"], 0)), 461)

    def test_ai_payload_privacy(self):
        pl = make_pipeline()
        blob = str(ai_payload(pl.sections[0]))
        for forbidden in ["187.108.1.142", "10.138.137.22", "altoconnect", "P1FWX0209"]:
            self.assertNotIn(forbidden, blob)

    def test_env_key_loading_without_dotenv_dependency(self):
        from cybersec_report.core.config_loader import get_api_key
        os.environ["VT_API_KEY"] = "abc"
        self.assertEqual(get_api_key("VT_API_KEY"), "abc")
        del os.environ["VT_API_KEY"]
        os.environ.pop("DOES_NOT_EXIST_KEY", None)
        self.assertIsNone(get_api_key("DOES_NOT_EXIST_KEY"))


IPS = [f"8.8.8.{i}" for i in range(1, 11)]


def quota_resp():
    return Resp(429, {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}})


class TestFailover(unittest.TestCase):
    def test_one_provider_until_quota_then_switch(self):
        """10 IP: VT melayani 4 IP, lalu kuota habis -> 6 IP sisanya ke AbuseIPDB. AbuseIPDB TIDAK dipakai untuk 4 IP pertama."""
        n = {"vt": 0}

        def responder(url, params):
            if "virustotal" in url:
                n["vt"] += 1
                return vt_ok(3) if n["vt"] <= 4 else quota_resp()
            return ab_ok(40, 3)
        eng, sess, _ = engine(responder, strategy="failover")
        out = eng.lookup(IPS)
        vt_calls = [c for c in sess.calls if "virustotal" in c[0]]
        ab_calls = [c for c in sess.calls if "abuseipdb" in c[0]]
        self.assertEqual(len(vt_calls), 5)        # 4 sukses + 1 yang memicu kuota; TIDAK dicoba lagi sesudahnya
        self.assertEqual(len(ab_calls), 6)        # IP ke-5..10 (IP ke-5 dilempar ulang ke AbuseIPDB)
        self.assertTrue(all(out["results"][ip]["source"] == "virustotal" for ip in IPS[:4]))
        self.assertTrue(all(out["results"][ip]["source"] == "abuseipdb" for ip in IPS[4:]))
        self.assertTrue(all(r["status"] == "CHECKED" for r in out["results"].values()))
        st = out["stats"]
        self.assertIn("exhausted", st["providers"]["virustotal"]["state"])
        self.assertEqual(st["switches"], [{"from": "virustotal", "to": "abuseipdb", "after_api_calls": 5}])
        self.assertTrue(any("beralih ke abuseipdb" in l for l in out["log"]))

    def test_no_second_provider_call_when_first_succeeds(self):
        eng, sess, _ = engine(ok_responder, strategy="failover")
        eng.lookup(IPS)
        self.assertEqual(len(sess.calls), 10)
        self.assertTrue(all("virustotal" in c[0] for c in sess.calls))

    def test_exhausted_state_persists_across_runs(self):
        cache = R.ReputationCache(tempfile.mktemp(suffix=".sqlite"))
        eng, sess, _ = engine(lambda u, p: quota_resp() if "virustotal" in u else ab_ok(), cache=cache, strategy="failover")
        eng.lookup(IPS[:3])
        eng2, sess2, _ = engine(lambda u, p: quota_resp() if "virustotal" in u else ab_ok(), cache=cache, strategy="failover")
        out = eng2.lookup(["1.1.1.1", "1.0.0.1"])
        self.assertEqual([c for c in sess2.calls if "virustotal" in c[0]], [])  # tidak membuang request ke VT lagi
        self.assertIn("dilewati sampai", out["stats"]["providers"]["virustotal"]["state"])
        cache.clear_exhausted("virustotal")
        self.assertIsNone(cache.get_exhausted("virustotal"))

    def test_exhausted_expires(self):
        now = [1_000_000.0]
        cache = R.ReputationCache(tempfile.mktemp(suffix=".sqlite"), clock=lambda: now[0])
        cache.set_exhausted("virustotal", "x")
        self.assertIsNotNone(cache.get_exhausted("virustotal"))
        now[0] += 25 * 3600
        self.assertIsNone(cache.get_exhausted("virustotal"))

    def test_cache_from_any_provider_avoids_api_call(self):
        cache = R.ReputationCache(tempfile.mktemp(suffix=".sqlite"))
        cache.put("abuseipdb", "8.8.8.8", {"abuseConfidenceScore": 5, "totalReports": 0, "lastReportedAt": None})
        eng, sess, _ = engine(ok_responder, cache=cache, strategy="failover")
        out = eng.lookup(["8.8.8.8"])
        self.assertEqual(sess.calls, [])
        self.assertEqual(out["results"]["8.8.8.8"]["source"], "abuseipdb")

    def test_all_providers_exhausted_does_not_crash(self):
        eng, sess, _ = engine(lambda u, p: quota_resp(), strategy="failover")
        out = eng.lookup(IPS)
        self.assertEqual(len([c for c in sess.calls if "virustotal" in c[0]]), 1)
        self.assertEqual(len([c for c in sess.calls if "abuseipdb" in c[0]]), 1)
        self.assertTrue(all(r["status"] == "UNAVAILABLE" for r in out["results"].values()))
        self.assertTrue(any("Semua provider" in l for l in out["log"]))

    def test_remaining_header_zero_switches_before_error(self):
        def responder(url, params):
            if "abuseipdb" in url:
                return Resp(200, {"data": {"abuseConfidenceScore": 1, "totalReports": 0}}, headers={"X-RateLimit-Remaining": "0"})
            return vt_ok()
        eng, sess, _ = engine(responder, strategy="failover")
        eng.cfg["provider_order"] = ["abuseipdb", "virustotal"]
        eng.order = ["abuseipdb", "virustotal"]
        out = eng.lookup(["8.8.8.8", "8.8.4.4"])
        self.assertEqual(out["results"]["8.8.8.8"]["source"], "abuseipdb")
        self.assertEqual(out["results"]["8.8.4.4"]["source"], "virustotal")

    def test_auth_error_falls_over_to_next(self):
        eng, sess, _ = engine(lambda u, p: Resp(401) if "virustotal" in u else ab_ok(), strategy="failover")
        out = eng.lookup(IPS[:3])
        self.assertEqual(len([c for c in sess.calls if "virustotal" in c[0]]), 1)
        self.assertTrue(all(r["source"] == "abuseipdb" for r in out["results"].values()))

    def test_short_429_is_retried_not_treated_as_quota(self):
        seq = [Resp(429, {"message": "slow down"}, headers={"Retry-After": "2"}), vt_ok(1)]
        sess, sleeps = FakeSession(lambda u, p: seq.pop(0)), []
        prov = VirusTotalProvider(api_key="k", session=sess, sleep=sleeps.append, max_retries=2, backoff=0.1)
        self.assertEqual(prov.query_ip("8.8.8.8")["malicious"], 1)

    def test_long_retry_after_is_quota(self):
        from cybersec_report.threat_intel.base import ProviderQuotaExceeded
        prov = VirusTotalProvider(api_key="k", session=FakeSession(lambda u, p: Resp(429, {}, headers={"Retry-After": "3600"})),
                                  sleep=lambda s: None, max_retries=3)
        with self.assertRaises(ProviderQuotaExceeded):
            prov.query_ip("8.8.8.8")

    def test_default_strategy_is_failover_and_order(self):
        cfg = load_settings()["reputation"]
        self.assertEqual(cfg["strategy"], "failover")
        self.assertEqual(cfg["provider_order"], ["virustotal", "abuseipdb"])


class TestApiKeyStorage(unittest.TestCase):
    def setUp(self):
        from cybersec_report.core import config_loader as C
        self.C, self._old = C, os.environ.get("CYBERSEC_DATA_DIR")
        self.tmp = tempfile.mkdtemp()
        os.environ["CYBERSEC_DATA_DIR"] = self.tmp
        for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY"):
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ["CYBERSEC_DATA_DIR"] = self._old

    def test_save_and_read_key_in_database_env(self):
        path = self.C.save_env_keys({"VT_API_KEY": "vt-secret-1234", "ABUSEIPDB_API_KEY": ""})
        self.assertEqual(path.parent.resolve(), __import__("pathlib").Path(self.tmp).resolve())
        key, src = self.C.find_api_key("VT_API_KEY")
        self.assertEqual(key, "vt-secret-1234")
        self.assertTrue(src.endswith(".env"))
        self.assertIsNone(self.C.get_api_key("ABUSEIPDB_API_KEY"))   # kosong tidak ditulis
        self.C.save_env_keys({"ABUSEIPDB_API_KEY": "ab-9999", "VT_API_KEY": "vt-new"})
        self.assertEqual(self.C.get_api_key("ABUSEIPDB_API_KEY"), "ab-9999")
        self.assertEqual(self.C.get_api_key("VT_API_KEY"), "vt-new")   # diperbarui, bukan duplikat
        self.assertEqual(Path(path).read_text().count("VT_API_KEY="), 1)

    def test_ui_override_wins_and_mask(self):
        self.C.save_env_keys({"VT_API_KEY": "from-file"})
        self.assertEqual(self.C.get_api_key("VT_API_KEY", {"VT_API_KEY": "from-ui"}), "from-ui")
        self.assertEqual(self.C.mask_key("abcdefghijkl"), "********ijkl")

    def test_empty_value_in_one_file_does_not_hide_key_in_another(self):
        (__import__("pathlib").Path(self.tmp) / ".env").write_text("VT_API_KEY=\n")
        self.assertIsNone(self.C.get_api_key("VT_API_KEY"))
        self.C.save_env_keys({"VT_API_KEY": "real"})
        self.assertEqual(self.C.get_api_key("VT_API_KEY"), "real")


if __name__ == "__main__":
    unittest.main()
