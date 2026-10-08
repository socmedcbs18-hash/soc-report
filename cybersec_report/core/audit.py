"""Audit trail: setiap angka di PPT harus bisa ditelusuri ke source file, filter, dan
rumus perhitungannya (report_audit.json)."""
import json
from datetime import datetime


def _py(v):
    """Konversi numpy/pandas scalar ke tipe Python agar JSON-serializable."""
    try:
        import numpy as np
        if isinstance(v, np.integer):
            return int(v)
        if isinstance(v, np.floating):
            return None if np.isnan(v) else float(v)
    except ImportError:
        pass
    return v


class AuditLog:
    def __init__(self, source_file=""):
        self.source_file = source_file
        self.entries = []

    def record(self, slide, metric, value, filter="", calculation="", source_file=None):
        self.entries.append({
            "slide": slide, "metric": metric, "value": _py(value),
            "source_file": source_file or self.source_file,
            "filter": filter, "calculation": calculation,
        })

    def record_table(self, slide, table, df, label_col, value_col, filter="", calculation=""):
        """Catat setiap baris tabel (label -> nilai) beserta baris Total."""
        for _, r in df.iterrows():
            self.record(slide, f"{table}[{r[label_col]}]", r[value_col], filter, calculation)

    def find(self, slide, metric):
        return [e for e in self.entries if e["slide"] == slide and e["metric"] == metric]

    def to_list(self):
        return list(self.entries)

    def to_json(self, meta=None):
        payload = {"generated_at": datetime.now().isoformat(timespec="seconds"),
                   "source_file": self.source_file, "meta": meta or {}, "entries": self.entries}
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    def save(self, path, meta=None):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json(meta))
