"""Helper test: pipeline siap-pakai dari fixture IPS dan HTTP session palsu."""
from pathlib import Path

from cybersec_report.pipeline import IPSPipeline

FIXTURE = Path(__file__).parent / "fixtures" / "IPS_Sep_2026.csv"


def make_pipeline(path=FIXTURE, split_by="none"):
    """split_by='none' = semua hostname digabung (angka baseline 939 pada satu section); 'device' = per hostname."""
    pl = IPSPipeline()
    pl.settings["ips"]["split_by"] = split_by
    pl.ingest(path)
    pl.prepare()
    pl.analyze()
    return pl


class Resp:
    def __init__(self, code, js=None, headers=None):
        self.status_code, self._js, self.headers, self.text = code, js or {}, headers or {}, str(js)

    def json(self):
        return self._js


class FakeSession:
    """Session HTTP palsu. responses: list/callable -> Resp. Mencatat setiap request."""
    def __init__(self, responder):
        self.responder, self.calls = responder, []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, params))
        return self.responder(url, params)
