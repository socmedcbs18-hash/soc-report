"""Snapshot bulanan Akamai (JSON, bukan pickle) + perbandingan antar bulan.
Disimpan di database/cybersec_report/snapshots/akamai/ (subfolder terpisah agar tidak tercampur dengan snapshot IPS).
Satu file per bulan: AKAMAI_<YYYY>-<MM>.json; simpan ulang bulan yang sama = memperbarui."""
import json
import os
from datetime import datetime

from cybersec_report.core.config_loader import snapshot_dir
from cybersec_report.core.period import month_name
from cybersec_report.sources import akamai as ak

SCHEMA_VERSION = 1


def store_dir():
    d = snapshot_dir() / "akamai"
    d.mkdir(parents=True, exist_ok=True)
    return d


def snapshot_label(month, year):
    return f"AKAMAI-{month_name(month)}-{year}"


def save_snapshot(parsed, month, year, directory=None):
    d = directory or store_dir()
    path = d / f"AKAMAI_{int(year)}-{int(month):02d}.json"
    payload = {"schema_version": SCHEMA_VERSION, "source": "AKAMAI", "saved_at": datetime.now().isoformat(timespec="seconds"),
               "period": {"month": int(month), "year": int(year)}, "source_file": parsed.get("filename", ""),
               "sections": parsed["sections"], "checks": parsed.get("checks", []), "missing_sheets": parsed.get("missing_sheets", [])}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return path


def list_snapshots(directory=None):
    out = []
    for f in (directory or store_dir()).glob("AKAMAI_*.json"):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
            p = raw["period"]
            out.append({"path": str(f), "year": p["year"], "month": p["month"], "label": snapshot_label(p["month"], p["year"]),
                        "saved_at": raw.get("saved_at", ""), "source_file": raw.get("source_file", "")})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(out, key=lambda r: (r["year"], r["month"]), reverse=True)


def load_snapshot(path):
    raw = json.loads(__import__("pathlib").Path(path).read_text(encoding="utf-8"))
    return {"filename": raw.get("source_file", ""), "sections": raw["sections"], "checks": raw.get("checks", []),
            "missing_sheets": raw.get("missing_sheets", []), "period": raw["period"], "saved_at": raw.get("saved_at")}


def delete_snapshot(path, directory=None):
    """Hapus SATU snapshot Akamai; hanya .json di folder akamai. Cache reputasi/snapshot IPS tidak tersentuh."""
    from pathlib import Path
    base = Path(directory or store_dir()).resolve()
    f = Path(path).resolve()
    if f.suffix != ".json" or f.parent != base:
        raise ValueError("Hanya file snapshot Akamai di folder snapshots/akamai yang boleh dihapus.")
    if not f.exists():
        return False
    f.unlink()
    return True


def compare(a, b):
    """a = periode pembanding (lama), b = periode dianalisis (baru). Hanya section yang ada di kedua file.
    Label di luar top 5 pada salah satu bulan TIDAK dianggap 0 -> dipisah sebagai only_a / only_b."""
    sa, sb = ak.summarize(a), ak.summarize(b)
    common = [k for k in ak.SECTION_ORDER if k in sa["totals"] and k in sb["totals"]]
    totals = [(ak.SECTION_TITLE[k], sa["totals"][k], sb["totals"][k]) for k in common]
    sections = {}
    for k in common:
        sec = {}
        for dim in ak.DIM_ORDER:
            ra = {l: h for l, h, _ in ak.table_rows(a["sections"][k], dim) if l != ak.OTHERS}
            rb = {l: h for l, h, _ in ak.table_rows(b["sections"][k], dim) if l != ak.OTHERS}
            both = sorted(set(ra) & set(rb), key=lambda l: -rb[l])
            sec[dim] = {"both": [(l, ra[l], rb[l]) for l in both], "only_a": sorted(set(ra) - set(rb)), "only_b": sorted(set(rb) - set(ra))}
        sections[k] = sec
    notes = []
    if sa["grand_total"] and sb["grand_total"]:
        d = (sb["grand_total"] - sa["grand_total"]) / sa["grand_total"] * 100
        notes.append(f"Total hit {'naik' if d > 0 else 'turun'} {abs(d):.1f}% dibanding pembanding (selisih ini dari file saja; belum tentu mencerminkan perubahan jumlah serangan nyata).")
    missing = set(sa["totals"]) ^ set(sb["totals"])
    if missing:
        notes.append("Section tidak ada di salah satu periode, tidak dibandingkan: " + ", ".join(ak.SECTION_TITLE[k] for k in missing))
    return {"totals": totals, "grand": (sa["grand_total"], sb["grand_total"]), "sections": sections, "notes": notes}
