"""Snapshot periode: hasil analytics + reputasi + findings disimpan di database/cybersec_report/snapshots/
sehingga dashboard periode (mis. 'IPS September 2026') bisa dibuka lagi TANPA upload ulang.
Format JSON (bukan pickle): aman dibuka/diaudit, tidak menjalankan kode saat dimuat."""
import json
import os
import re
from pathlib import Path
from datetime import date, datetime

import numpy as np
import pandas as pd

from cybersec_report.core.config_loader import snapshot_dir

SCHEMA_VERSION = 1


def _enc(o):
    if isinstance(o, pd.DataFrame):
        d = o.astype(object).where(o.notna(), None)
        return {"__df__": True, "columns": [str(c) for c in o.columns], "dtypes": [str(t) for t in o.dtypes],
                "data": [[_enc(v) for v in row] for row in d.values.tolist()]}
    if isinstance(o, dict):
        return {str(k): _enc(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_enc(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating, float)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, (date, datetime)):
        return {"__date__": o.isoformat()}
    return o


def _dec(o):
    if isinstance(o, dict):
        if o.get("__df__"):
            df = pd.DataFrame(o["data"], columns=o["columns"])
            for col, dt in zip(o["columns"], o["dtypes"]):
                if dt.startswith(("float", "int")):
                    df[col] = pd.to_numeric(df[col], errors="coerce")
            return df
        if "__date__" in o and len(o) == 1:
            return date.fromisoformat(o["__date__"][:10])
        return {k: _dec(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_dec(v) for v in o]
    return o


def _slug(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(text)).strip("_") or "ALL"


def snapshot_name(year, month, source="IPS", hostname=None):
    """IPS_<hostname>_<YYYY-MM>.json (satu snapshot per hostname per bulan). Tanpa hostname = format lama."""
    host = f"_{_slug(hostname)}" if hostname else ""
    return f"{source}{host}_{int(year)}-{int(month):02d}.json"


def snapshot_title(source, hostname, month_name, year):
    """Judul seperti nama laporan insiden: P1FWX0209-IPS-September-2026."""
    return f"{hostname}-{source}-{month_name}-{year}" if hostname else f"{source}-{month_name}-{year}"


def save_snapshot(vm, source="IPS", directory=None, hostname=None):
    """vm = view-model dari IPSPipeline.view_model(section). Tulis atomik (tmp lalu replace).
    Hostname yang sama + bulan yang sama = menimpa (upload ulang memperbarui, bukan menggandakan)."""
    p = vm["period"]
    d = directory or snapshot_dir()
    hostname = hostname or vm.get("hostname")
    path = d / snapshot_name(p["report_year"], p["report_month"], source, hostname)
    payload = {"schema_version": SCHEMA_VERSION, "source": source, "saved_at": datetime.now().isoformat(timespec="seconds"),
               **_enc({**vm, "hostname": hostname})}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return path


def list_snapshots(directory=None):
    """Daftar periode tersimpan, terbaru dulu. File rusak dilewati (tidak menjatuhkan UI)."""
    out = []
    for f in (directory or snapshot_dir()).glob("*.json"):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
            p = raw["period"]
            src, host = raw.get("source", "IPS"), raw.get("hostname")
            out.append({"path": str(f), "source": src, "hostname": host, "year": p["report_year"], "month": p["report_month"],
                        "label": snapshot_title(src, host, p["month_name"], p["report_year"]) if host
                        else f"{src}-{p['month_name']}-{p['report_year']} (format lama, semua hostname)",
                        "saved_at": raw.get("saved_at", ""), "source_file": raw.get("source_file", ""),
                        "total_events": raw.get("total_events")})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(out, key=lambda r: (r["year"], r["month"], str(r["hostname"])), reverse=True)


def load_snapshot(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    vm = _dec({k: v for k, v in raw.items() if k not in ("schema_version", "saved_at", "source")})
    vm["saved_at"], vm["source"], vm["schema_version"] = raw.get("saved_at"), raw.get("source", "IPS"), raw.get("schema_version")
    return vm


def delete_snapshot(path, directory=None):
    """Hapus SATU file snapshot. Hanya file .json di dalam folder snapshots yang boleh dihapus (path lain ditolak).
    Cache reputasi dan file lain tidak disentuh. Return True bila terhapus."""
    base = Path(directory or snapshot_dir()).resolve()
    f = Path(path).resolve()
    if f.suffix != ".json" or f.parent != base:
        raise ValueError("Hanya file snapshot di folder snapshots yang boleh dihapus.")
    if not f.exists():
        return False
    f.unlink()
    return True
