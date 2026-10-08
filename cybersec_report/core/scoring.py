"""Internal Normalized Threat Score (0-100). BUKAN skor resmi vendor manapun.
Dihitung hanya dari komponen yang tersedia; bobot dinormalisasi ulang atas komponen tsb."""
from datetime import datetime, timezone


def risk_level(score, bands):
    if score is None:
        return "Not assessed"
    for lo, hi, name in bands:
        if lo <= score <= hi:
            return name
    return bands[-1][2] if score > bands[-1][1] else bands[0][2]


def _recency_factor(last_reported, rules, now=None):
    if not last_reported:
        return 0.0
    try:
        ts = datetime.fromisoformat(str(last_reported).replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    days = ((now or datetime.now(timezone.utc)) - ts).total_seconds() / 86400
    for max_days, factor in rules:
        if days <= max_days:
            return float(factor)
    return 0.0


def compute_threat_score(provider_data, cfg, now=None):
    """provider_data: {'virustotal': {...}|None, 'abuseipdb': {...}|None}.
    Return {'score': float|None, 'level': str, 'components': {...}}."""
    w, comps = cfg["weights"], {}
    vt, ab = provider_data.get("virustotal"), provider_data.get("abuseipdb")
    if vt:
        sat = cfg["vt"]["malicious_saturation_engines"]
        eff = vt["malicious"] + cfg["vt"]["suspicious_weight"] * vt["suspicious"]
        comps["vt_malicious"] = min(1.0, eff / sat) if sat else 0.0
    if ab:
        comps["abuse_confidence"] = min(1.0, ab["abuseConfidenceScore"] / 100.0)
        comps["abuse_reports"] = min(1.0, ab["totalReports"] / cfg["abuse"]["reports_saturation"])
        comps["recency"] = _recency_factor(ab.get("lastReportedAt"), cfg["recency_days"], now)
    if not comps:
        return {"score": None, "level": "Not assessed", "components": {}}
    wsum = sum(w[k] for k in comps)
    score = round(100.0 * sum(w[k] * v for k, v in comps.items()) / wsum, 1)
    return {"score": score, "level": risk_level(score, cfg["bands"]), "components": comps}
