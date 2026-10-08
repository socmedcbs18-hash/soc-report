"""Smoke test UI dengan stub Streamlit (BUKAN pengganti uji di browser). Menangkap NameError/KeyError/salah-import pada alur render."""
import importlib
import io
import os
import sys
import tempfile
import unittest

from cybersec_report.tests.test_ui_smoke import StubStreamlit   # hanya stub test; kode modul tidak saling impor
from soc_incident.tests._helpers import make_raw, to_xlsx_bytes


class Stub(StubStreamlit):
    def time_input(self, label, value=None, **k):
        return value


class FakeUpload(io.BytesIO):
    def __init__(self, data, name="Insiden-Ivanti-September-2026.xlsx"):
        super().__init__(data)
        self.name, self.size = name, len(data)


def _is_mod(k):
    return k == "streamlit" or k.startswith("soc_incident.dashboard")


class TestUI(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get("SOC_INCIDENT_DATA_DIR")
        os.environ["SOC_INCIDENT_DATA_DIR"] = tempfile.mkdtemp(prefix="soc_incident_ui_")
        self._saved = {k: v for k, v in sys.modules.items() if _is_mod(k)}
        self.sep = FakeUpload(to_xlsx_bytes(make_raw()))
        self.oct = FakeUpload(to_xlsx_bytes(make_raw(month=10, new_only=True, n_new=100, seed=5)), "Insiden-Ivanti-Oktober-2026.xlsx")

    def tearDown(self):
        if self._old is None:
            os.environ.pop("SOC_INCIDENT_DATA_DIR", None)
        else:
            os.environ["SOC_INCIDENT_DATA_DIR"] = self._old
        for k in [k for k in sys.modules if _is_mod(k)]:
            del sys.modules[k]
        sys.modules.update(self._saved)

    def _run(self, stub):
        sys.modules["streamlit"] = stub
        for k in [k for k in sys.modules if k.startswith("soc_incident.dashboard")]:
            del sys.modules[k]
        mod = importlib.import_module("soc_incident.dashboard")
        mod.render_soc_incident_dashboard()
        return mod

    def test_no_upload_does_not_crash(self):
        stub = Stub()
        self._run(stub)
        self.assertIn("info", stub.calls)

    def test_full_flow_renders_executive_view(self):
        stub = Stub(upload=self.sep)
        self._run(stub)
        html = "".join(stub.html)
        for needle in ("Ringkasan untuk manajemen", "Tiket per hari", "Perbandingan per era", "Insight otomatis", "Perlu diperhatikan",
                       "Metrik state machine", "Tidak ada timestamp", "Ringkasan mingguan"):
            self.assertIn(needle, html)
        self.assertNotIn("error", stub.calls)
        self.assertNotIn("exception", stub.calls)

    def test_save_snapshot_then_compare_two_months(self):
        from soc_incident import snapshot
        self._run(Stub(upload=self.sep, clicks={"si_save_snap"}))
        # bulan kedua: seluruh bulan = state machine baru
        self._run(Stub(upload=self.oct, clicks={"si_save_snap"}, choices={"si_cut_mode": "none", "si_cut_single": "new"}))
        self.assertEqual([x["label"] for x in snapshot.list_snapshots()], ["SOC-Incident-Oktober-2026", "SOC-Incident-September-2026"])
        stub = Stub()
        self._run(stub)
        html = "".join(stub.html)
        self.assertIn("SOC-Incident-September-2026", html)
        self.assertIn("Tiket per hari", html)
        self.assertNotIn("error", stub.calls)

    def test_manual_cutover_renders(self):
        stub = Stub(upload=self.sep, choices={"si_cut_mode": "manual"})
        self._run(stub)
        self.assertNotIn("error", stub.calls)
        self.assertIn("Perbandingan per era", "".join(stub.html))

    def test_clear_upload_keeps_snapshots(self):
        from soc_incident import snapshot
        s1 = Stub(upload=self.sep, clicks={"si_save_snap"})
        self._run(s1)
        n = len(snapshot.list_snapshots())
        s2 = Stub(upload=self.sep, clicks={"si_clear"}, session=s1.session_state)
        mod = self._run(s2)
        mod._clear_cb()
        self.assertNotIn("si_df", s2.session_state)
        self.assertEqual(len(snapshot.list_snapshots()), n)

    def test_delete_snapshot_and_excel_export(self):
        from soc_incident import snapshot
        s1 = Stub(upload=self.sep, clicks={"si_save_snap", "si_make_xlsx"})
        self._run(s1)
        self.assertEqual(len(snapshot.list_snapshots()), 1)
        self.assertTrue(s1.session_state.get("si_xlsx"))
        s2 = Stub(upload=self.sep, session=s1.session_state, clicks={"si_del_snap"}, choices={"si_del_confirm": True})
        self._run(s2)
        self.assertEqual(snapshot.list_snapshots(), [])
        self.assertTrue(s2.downloads)


if __name__ == "__main__":
    unittest.main()
