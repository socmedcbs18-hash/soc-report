import re
import unittest

from cybersec_report import ui_components as U


class TestComponents(unittest.TestCase):
    def test_hbar_escapes_and_labels_values(self):
        h = U.hbar_list([("<script>x</script>", 10, 50.0), ("Others", 10, 50.0)])
        self.assertNotIn("<script>", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertIn("50,0%", h)
        self.assertIn(U.OTHERS, h)           # Others = abu-abu

    def test_hbar_empty(self):
        self.assertIn("Tidak ada serangan Medium", U.hbar_list([], empty="Tidak ada serangan Medium"))

    def test_donut_percent_stops_end_at_100(self):
        h = U.donut([("A", 30, 30.0, "#111", "d"), ("B", 70, 70.0, "#222", "")], "100", "total")
        self.assertIn("#222 30.000% 100.000%", h)
        self.assertIn(">100<", h)

    def test_kpi_long_value_uses_smaller_font(self):
        h = U.kpi_cards([("Top", "United States", "x", None), ("N", "939", None, None)])
        self.assertEqual(re.findall(r"font-size:(1\.\d+rem);font-weight:700", h), ["1.2rem", "1.75rem"])


if __name__ == "__main__":
    unittest.main()
