"""Smoke test UI TANPA Streamlit sungguhan (stub). Menjalankan seluruh alur render: upload -> tab -> dashboard ->
generate -> tombol unduh. Menangkap NameError/KeyError/salah-import yang tidak terlihat oleh test logika.
Catatan: ini BUKAN pengganti uji di browser (perilaku rerun/download Streamlit asli tidak dapat ditiru stub)."""
import contextlib
import importlib
import io
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

from cybersec_report.tests._helpers import FIXTURE


def _is_ui(k):
    return k.startswith(("cybersec_report.dashboard", "cybersec_report.sources_view", "cybersec_report.compare_view", "cybersec_report.akamai_view"))


class Ctx:
    """Objek serbaguna: context manager + semua method mengembalikan Ctx."""
    def __init__(self, st): self._st = st
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        real = getattr(type(self._st), name, None)
        return getattr(self._st, name) if callable(real) else (lambda *a, **k: self._st._call(name, *a, **k))
    def __iter__(self): return iter([])


class StubStreamlit(types.ModuleType):
    __version__ = "1.50.0"

    def __init__(self, upload=None, clicks=(), choices=None, session=None, uploads=None):
        super().__init__("streamlit")
        self.session_state, self.upload, self.clicks, self.calls = dict(session or {}), upload, set(clicks), []
        self.choices, self.images, self.uploads = dict(choices or {}), [], dict(uploads or {})
        self.sidebar = Ctx(self)
        self.downloads, self.html, self.plots = [], [], []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **k: self._call(name, *a, **k)

    def _call(self, name, *a, **k):
        self.calls.append(name)
        return Ctx(self)

    def columns(self, spec, **k):
        n = spec if isinstance(spec, int) else len(spec)
        return [Ctx(self) for _ in range(n)]

    def tabs(self, names): return [Ctx(self) for _ in names]
    def expander(self, *a, **k): return Ctx(self)
    def spinner(self, *a, **k): return Ctx(self)
    def file_uploader(self, *a, key=None, **k):
        for prefix, f in self.uploads.items():       # uploader bernama (mis. Akamai) dipisah dari uploader IPS
            if (key or "").startswith(prefix):
                return f
        return None if (key or "").startswith("cs_ak_upload") else self.upload
    def button(self, label, key=None, on_click=None, args=(), **k):
        hit = key in self.clicks and not k.get("disabled")   # tombol non-aktif tidak bisa diklik (seperti Streamlit asli)
        if hit and on_click:
            on_click(*args)
        return hit
    def checkbox(self, label, value=False, key=None, **k): return self.choices.get(key, value)
    def selectbox(self, label, options, index=0, key=None, **k):
        return self.choices.get(key, list(options)[index] if len(list(options)) else None)
    def radio(self, label, options, index=0, key=None, **k): return self.choices.get(key, list(options)[index])
    def multiselect(self, label, options, default=None, **k): return list(default if default is not None else [])
    def image(self, path, **k): self.images.append(path)
    def number_input(self, label, min_value=None, max_value=None, value=0, **k): return value if not isinstance(min_value, int) or value is not None else min_value
    def text_input(self, label, value="", **k): return value
    def date_input(self, label, value=None, **k): return value
    def progress(self, *a, **k): return Ctx(self)
    def rerun(self): pass
    def markdown(self, body, unsafe_allow_html=False, **k):
        if unsafe_allow_html:
            self.html.append(body)
    def plotly_chart(self, fig, **k): self.plots.append(fig)
    def download_button(self, label, data, **k): self.downloads.append((label, len(data), k))
    def metric(self, *a, **k): pass


class FakeUpload(io.BytesIO):
    name, size = "IPS_Sep_2026.csv", 1


class UIHarness:
    """Mixin: pasang stub Streamlit, impor dashboard, jalankan render."""
    def setUp(self):
        import os, tempfile
        self._old_dir = os.environ.get("CYBERSEC_DATA_DIR")
        os.environ["CYBERSEC_DATA_DIR"] = tempfile.mkdtemp(prefix="cybersec_ui_")   # data terisolasi per test
        self._saved = {k: v for k, v in sys.modules.items() if k == "streamlit" or _is_ui(k)}

    def tearDown(self):
        import os
        os.environ["CYBERSEC_DATA_DIR"] = self._old_dir
        for k in [k for k in sys.modules if k == "streamlit" or _is_ui(k)]:
            del sys.modules[k]
        sys.modules.update(self._saved)

    def _run(self, stub):
        sys.modules["streamlit"] = stub
        for k in [k for k in sys.modules if _is_ui(k)]:
            del sys.modules[k]
        mod = importlib.import_module("cybersec_report.dashboard")
        mod.render_cybersec_report_dashboard()
        return mod


class TestUISmoke(UIHarness, unittest.TestCase):
    def test_no_upload_no_snapshot_does_not_crash(self):
        stub = StubStreamlit()
        self._run(stub)
        self.assertIn("info", stub.calls)

    def test_full_flow_dashboard_generate_and_downloads(self):
        up = FakeUpload(Path(FIXTURE).read_bytes())
        stub = StubStreamlit(upload=up, clicks={"cs_generate"})
        mod = self._run(stub)
        html = "".join(stub.html)
        for needle in ("Attack Name", "Critical", "Source Country", "Dest", "Description", "Total", "By%"):
            self.assertIn(needle, html)
        self.assertNotIn("error", stub.calls)
        self.assertNotIn("exception", stub.calls)
        self.assertEqual(len(stub.downloads), 5)
        self.assertTrue(all(d[2].get("on_click") == "ignore" for d in stub.downloads))
        self.assertTrue(all(d[1] > 0 for d in stub.downloads))
        # periode tersimpan -> bisa dibuka lagi tanpa upload
        from cybersec_report.core import snapshot
        self.assertEqual([s["label"] for s in snapshot.list_snapshots()],
                         ["P2FWX0109-IPS-September-2026", "P1FWX0209-IPS-September-2026"])
        stub2 = StubStreamlit()
        self._run(stub2)
        html2 = "".join(stub2.html)
        self.assertIn("Attack Name", html2)
        self.assertNotIn("error", stub2.calls)

    def test_old_streamlit_download_has_no_on_click_ignore(self):
        up = FakeUpload(Path(FIXTURE).read_bytes())
        stub = StubStreamlit(upload=up, clicks={"cs_generate"})
        stub.__version__ = "1.40.2"
        self._run(stub)
        self.assertTrue(stub.downloads and all("on_click" not in d[2] for d in stub.downloads))

    def test_clear_upload_resets_session_but_keeps_cache_and_snapshots(self):
        from cybersec_report.core import snapshot
        from cybersec_report.core.config_loader import cache_dir
        up = FakeUpload(Path(FIXTURE).read_bytes())
        stub = StubStreamlit(upload=up, clicks={"cs_generate"})
        self._run(stub)
        self.assertTrue(stub.session_state.get("cs_pl"))
        cache_file = cache_dir() / "reputation.sqlite"
        cache_file.write_bytes(b"x")
        n_snaps = len(snapshot.list_snapshots())
        stub_b = StubStreamlit(upload=up, clicks={"cs_clear_upload"}, session=stub.session_state)
        mod = self._run(stub_b)
        self.assertEqual(stub_b.session_state.get("cs_up_n"), 1)   # tombol memanggil callback hapus
        mod._clear_upload_cb()
        self.assertNotIn("cs_pl", stub_b.session_state)
        self.assertEqual(stub_b.session_state["cs_up_n"], 2)
        stub = stub_b
        # uploader baru kosong -> UI tidak crash dan tidak ada pipeline
        stub3 = StubStreamlit(session=stub.session_state)
        self._run(stub3)
        self.assertNotIn("error", stub3.calls)
        self.assertTrue(cache_file.exists())
        self.assertEqual(len(snapshot.list_snapshots()), n_snaps)

    def test_compare_tab_renders_two_hostnames(self):
        up = FakeUpload(Path(FIXTURE).read_bytes())
        self._run(StubStreamlit(upload=up, clicks={"cs_generate"}))
        stub = StubStreamlit()
        self._run(stub)
        html = "".join(stub.html)
        self.assertNotIn("error", stub.calls)
        self.assertIn("Total events", html)

    def test_other_sources_are_enabled_placeholders_with_sample_images(self):
        from cybersec_report.core.config_loader import load_report_structure
        ids = [x["id"] for x in load_report_structure()["sections"] if x.get("menu", True)]
        self.assertTrue({"akamai", "dlp", "edr", "cspm", "vuln", "siem", "proxy", "email", "exec"} <= set(ids))
        for sid in ids:
            if sid in ("ips", "akamai"):
                continue
            stub = StubStreamlit(choices={"cs_source": sid})
            self._run(stub)
            self.assertNotIn("error", stub.calls, sid)
            self.assertTrue(stub.images, sid)
            self.assertNotIn("Attack Name", "".join(stub.html), sid)

    def test_delete_snapshot_from_dashboard(self):
        from cybersec_report.core import snapshot
        up = FakeUpload(Path(FIXTURE).read_bytes())
        self._run(StubStreamlit(upload=up, clicks={"cs_generate"}))
        before = snapshot.list_snapshots()
        self.assertEqual(len(before), 2)
        target = before[0]["path"]
        stub = StubStreamlit(clicks={"cs_del_snap"}, choices={"cs_dash_source": target, "cs_del_confirm": True})
        self._run(stub)
        after = [x["path"] for x in snapshot.list_snapshots()]
        self.assertEqual(len(after), 1)
        self.assertNotIn(target, after)
        self.assertEqual(stub.session_state["cs_del_msg"][0], "ok")

    def test_delete_snapshot_refuses_outside_folder(self):
        from cybersec_report.core import snapshot
        import tempfile
        f = Path(tempfile.mkdtemp()) / "x.json"
        f.write_text("{}")
        with self.assertRaises(ValueError):
            snapshot.delete_snapshot(f)
        self.assertTrue(f.exists())


if __name__ == "__main__":
    unittest.main()
