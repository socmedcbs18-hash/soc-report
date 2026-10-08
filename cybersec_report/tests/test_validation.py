import io
import unittest

from cybersec_report.core import normalization as N
from cybersec_report.core import period as P
from cybersec_report.core.config_loader import load_source_mapping
from cybersec_report.core.validation import classify_ip
from cybersec_report.pipeline import IPSPipeline


def run(csv_text):
    pl = IPSPipeline()
    pl.ingest(io.BytesIO(csv_text.encode()), filename="IPS_Sep_2026.csv")
    pl.prepare()
    return pl


class TestValidation(unittest.TestCase):
    def test_private_ip_detection(self):
        for ip in ["10.1.1.1", "172.16.0.5", "172.31.255.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fd00::1", "::1", "fe80::1"]:
            self.assertEqual(classify_ip(ip), "PRIVATE_IP", ip)
        for ip in ["8.8.8.8", "187.108.1.142", "2001:4860:4860::8888"]:
            self.assertEqual(classify_ip(ip), "PUBLIC", ip)

    def test_invalid_ip(self):
        for bad in ["256.256.256.256", "abc", "1.2.3", ""]:
            self.assertEqual(classify_ip(bad), "INVALID", bad)
        pl = run("attack;srcip;dstip;severity;count\nX;999.1.1.1;10.0.0.1;high;2\nY;8.8.8.8;10.0.0.1;high;3\n")
        chk = {c["check"]: c for c in pl.validation["checks"]}
        self.assertEqual(chk["Invalid source IP"]["value"], 1)
        self.assertEqual(chk["Invalid source IP"]["status"], "WARNING")

    def test_missing_severity_is_critical_and_blocks(self):
        pl = run("attack;srcip;count\nX;8.8.8.8;2\n")
        self.assertTrue(pl.validation["blocking"])
        self.assertEqual(pl.validation["overall"], "FAIL")
        pl.cross = {"blocking": False}
        with self.assertRaises(RuntimeError):
            pl.generate()

    def test_negative_count_is_critical(self):
        pl = run("attack;srcip;severity;count\nX;8.8.8.8;high;-5\n")
        self.assertTrue(pl.validation["blocking"])

    def test_unknown_severity_not_dropped(self):
        pl = run("attack;srcip;severity;count\nX;8.8.8.8;weird;4\nY;8.8.4.4;high;1\n")
        self.assertEqual(float(pl.norm["count"].sum()), 5.0)
        self.assertIn("Unknown", set(pl.norm["severity"]))

    def test_no_guessing_similar_column_names(self):
        sch = N.detect_schema(["attackk", "src_ipp", "severity"], "IPS", load_source_mapping())
        self.assertNotIn("attack_name", sch["mapping"])
        self.assertIn("attack_name", sch["missing_required"])
        self.assertIn("attack_name", sch["suggestions"])  # hanya saran, tidak dipakai otomatis

    def test_manual_mapping_unblocks_validation(self):
        pl = IPSPipeline()
        pl.ingest(io.BytesIO(b"weird_attack;ipsrc;sev;count\nX;8.8.8.8;high;2\n"), filename="IPS_Sep_2026.csv")
        pl.prepare()
        self.assertTrue(pl.validation["blocking"])  # kolom tidak dikenali -> diblokir, TIDAK ditebak
        pl.prepare(manual_mapping={"attack_name": "weird_attack", "src_ip": "ipsrc", "severity": "sev", "count": "count"})
        self.assertEqual(pl.schema["missing_required"], [])
        self.assertFalse(pl.validation["blocking"])
        self.assertEqual(float(pl.norm["count"].sum()), 2.0)

    def test_period_from_filename_and_override(self):
        self.assertEqual(P.period_from_filename("IPS_Sep_2026.csv"), (9, 2026))
        self.assertEqual(P.period_from_filename("ips-2026-03.xlsx"), (3, 2026))
        self.assertEqual(P.period_from_filename("IPS_Agustus_2025.csv"), (8, 2025))
        self.assertIsNone(P.period_from_filename("ips.csv"))
        p = P.make_period(2, 2028)
        self.assertEqual(p["end_date"].day, 29)  # tahun kabisat

    def test_count_missing_each_row_is_one_event(self):
        pl = run("attack;srcip;severity\nX;8.8.8.8;high\nY;8.8.4.4;low\n")
        self.assertEqual(float(pl.norm["count"].sum()), 2.0)


if __name__ == "__main__":
    unittest.main()
