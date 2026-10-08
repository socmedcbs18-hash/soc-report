"""Snapshot bulanan laporan insiden SOC (JSON, bukan pickle). Isi = angka agregat, TANPA data tiket mentah/nama customer.
Lokasi: database/soc_incident/snapshots/ (env SOC_INCIDENT_DATA_DIR untuk test). Folder database/ tidak boleh dihapus."""
import json
import math
import os
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from soc_incident import fmt
from soc_incident.processor import ERA_LABEL, ERA_METRICS

PROJECT_DIR = Path(__file__).resolve().parents[1]
VERSION = 1


def data_dir():
    o = os.environ.get("SOC_INCIDENT_DATA_DIR", "").strip()
    d = Path(o) if o else PROJECT_DIR / "database" / "soc_incident"
    d.mkdir(parents=True, exist_ok=True)
    return d


def snapshot_dir():
    d = data_dir() / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _js(x):
    if isinstance(x, dict):
        return {str(k): _js(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_js(v) for v in x]
    if isinstance(x, pd.DataFrame):
        return {"__df__": json.loads(x.reset_index().to_json(orient="split", date_format="iso"))}
    if isinstance(x, (pd.Timestamp, datetime)):
        return x.isoformat()
    if isinstance(x, (np.integer,)):
        return int(x)
    if isinstance(x, (float, np.floating)):
        return None if math.isnan(x) else float(x)
    if isinstance(x, (np.bool_,)):
        return bool(x)
    return x


def _unjs(x):
    if isinstance(x, dict):
        if "__df__" in x:
            d = x["__df__"]
            return pd.DataFrame(d["data"], columns=d["columns"])
        return {k: _unjs(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_unjs(v) for v in x]
    return x


def snapshot_name(year, month):
    return f"SOC-Incident_{int(year)}-{int(month):02d}.json"


def title(year, month):
    return f"SOC-Incident-{fmt.month_name(month)}-{year}"


def save_snapshot(res, source_file, headlines, directory=None):
    from soc_incident.processor import executive_headlines  # noqa: F401  (headline dibuat pemanggil)
    p = res["period"]
    body = {"schema_version": VERSION, "saved_at": datetime.now().isoformat(timespec="seconds"), "source_file": source_file,
            "year": p["year"], "month": p["month"], "cutover": res["cutover"], "eras": res["eras"], "single_era": res.get("single_era"),
            "stats": res["stats"], "total": res["total"], "priority": res["priority"], "weekly": res["weekly"],
            "insights": res["insights"], "headlines": headlines, "threshold": res["threshold"]}
    path = Path(directory or snapshot_dir()) / snapshot_name(p["year"], p["month"])
    path.write_text(json.dumps(_js(body), ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def list_snapshots(directory=None):
    out = []
    for f in Path(directory or snapshot_dir()).glob("SOC-Incident_*.json"):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
            out.append({"path": str(f), "year": raw["year"], "month": raw["month"], "label": title(raw["year"], raw["month"]),
                        "saved_at": raw.get("saved_at", ""), "tickets": raw["total"]["tickets"], "eras": raw.get("eras", [])})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(out, key=lambda r: (r["year"], r["month"]), reverse=True)


def load_snapshot(path):
    return _unjs(json.loads(Path(path).read_text(encoding="utf-8")))


def delete_snapshot(path, directory=None):
    base = Path(directory or snapshot_dir()).resolve()
    f = Path(path).resolve()
    if f.suffix != ".json" or f.parent != base:
        raise ValueError("Hanya file snapshot di folder snapshots yang boleh dihapus.")
    if not f.exists():
        return False
    f.unlink()
    return True


# ------------------------------------------------------------------ compare
def basis_stats(snap, basis):
    """basis 'latest' = era terakhir (state machine baru bila ada), 'total' = seluruh bulan. Return (stats, label)."""
    if basis == "total":
        return snap["total"], "Total bulan"
    e = "new" if "new" in snap["stats"] else snap["eras"][-1]
    return snap["stats"][e], f"Era {ERA_LABEL.get(e, e).lower()}"


COMPARE_KEYS = [k for k in ("tickets", "per_day", "p1_share", "p3_share", "auto_share", "resp_median", "resp_p90", "breach_n", "breach_rate", "resolved_cov", "closed_no_resolve")]


def compare_months(a, b, basis="latest"):
    """a = bulan pembanding (lama), b = bulan dilihat. Return {table, notes, label_a, label_b}."""
    sa, la = basis_stats(a, basis)
    sb, lb = basis_stats(b, basis)
    kinds = {k: (lab, kind) for k, lab, kind in ERA_METRICS}
    kinds["tickets"] = ("Jumlah tiket", "int")
    rows = []
    for k in COMPARE_KEYS:
        va, vb = sa.get(k), sb.get(k)
        lab, kind = kinds[k]
        d = None if va is None or vb is None or (isinstance(va, float) and math.isnan(va)) or (isinstance(vb, float) and math.isnan(vb)) else vb - va
        rows.append({"key": k, "Metrik": lab, "kind": kind, "A": va, "B": vb, "Δ": d})
    notes = []
    if basis == "total":
        for s, nm in ((a, "A"), (b, "B")):
            if len(s["eras"]) == 2:
                notes.append(f"Bulan {nm} memuat dua state machine; angka 'Total bulan' (prioritas, resolusi, jumlah tiket) tidak sebanding dengan bulan lain. Gunakan basis era terbaru.")
    else:
        if "new" not in a["stats"] and a.get("single_era") != "new":
            notes.append("Bulan A tidak ditandai sebagai state machine baru; perbandingan era-terbaru mungkin tidak apel-ke-apel (atur 'Seluruh bulan memakai state machine' saat analisis).")
        if "new" not in b["stats"] and b.get("single_era") != "new":
            notes.append("Bulan B tidak ditandai sebagai state machine baru; perbandingan era-terbaru mungkin tidak apel-ke-apel.")
        for s, nm in ((a, "A"), (b, "B")):
            if "new" in s["stats"] and s["stats"]["new"]["days"] < 14:
                notes.append(f"Era baru di bulan {nm} baru berjalan {fmt.num(s['stats']['new']['days'], 1)} hari; bandingkan tingkat per hari, bukan jumlah tiket mentah.")
    return {"table": rows, "notes": notes, "label_a": la, "label_b": lb}
