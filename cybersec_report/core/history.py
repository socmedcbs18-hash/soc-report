"""Histori KPI bulanan untuk Month-over-Month. Perbandingan HANYA dibuat bila bulan
sebelumnya benar-benar tersimpan (tidak ada comparison karangan)."""
import json

from cybersec_report.core.config_loader import cache_dir


def history_path():
    return cache_dir() / "history.json"


def _load(path=None):
    p = path or history_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _key(year, month):
    return f"{int(year)}-{int(month):02d}"


def save_snapshot(year, month, section, a, path=None):
    p = path or history_path()
    data = _load(p)
    sev = {r["Severity"]: float(r["Count"]) for _, r in a["severity"].iterrows()}
    data.setdefault(_key(year, month), {})[section] = {
        "total_events": float(a["total_events"]), "severity": sev, "unique_source_ip": a["unique"]["source_ip"]}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def previous_snapshot(year, month, section, path=None):
    y, m = (int(year) - 1, 12) if int(month) == 1 else (int(year), int(month) - 1)
    return _load(path).get(_key(y, m), {}).get(section)


def compare(a, prev, stable_threshold_pct=5.0):
    """Return list baris perbandingan, atau None bila periode sebelumnya tidak tersedia."""
    if not prev:
        return None
    cur = {"Total events": float(a["total_events"])}
    old = {"Total events": float(prev["total_events"])}
    for _, r in a["severity"].iterrows():
        if r["Severity"] in ("Critical", "High", "Medium", "Low"):
            cur[r["Severity"]] = float(r["Count"])
            old[r["Severity"]] = float(prev["severity"].get(r["Severity"], 0.0))
    rows = []
    for k in cur:
        diff = cur[k] - old[k]
        pct = (diff / old[k] * 100.0) if old[k] else None
        if pct is None:
            arrow = "↑ Increase" if diff > 0 else "→ Stable"
        else:
            arrow = "→ Stable" if abs(pct) < stable_threshold_pct else ("↑ Increase" if diff > 0 else "↓ Decrease")
        rows.append({"Metric": k, "Previous": old[k], "Current": cur[k], "Change": diff, "Change %": pct, "Trend": arrow})
    return rows
