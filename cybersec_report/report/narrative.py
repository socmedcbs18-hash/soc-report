"""Narasi management: finding -> 3 kolom slide (Kesimpulan | Implikasi | Insight & Rekomendasi).
Rule-based. Hook AI hanya membangun payload TERAGREGASI (tanpa IP/username/URL/aset internal)."""


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def ips_narrative(findings):
    by = lambda lvl: [f for f in findings if f["severity"] in lvl]
    def expand(f):
        return [f["finding"]] + ["– " + d for d in f.get("details", [])]
    kes = [x for f in findings[:3] if f["severity"] in ("INFO", "HIGH", "MEDIUM") for x in expand(f)]
    kes += [f["finding"] for f in findings if f["finding"].startswith("Negara sumber")]
    impl = _dedupe([f["impact"] for f in findings if f["impact"]])
    ins = [f["finding"] for f in findings[3:] if not f["finding"].startswith("Negara sumber") and f["severity"] != "INFO"]
    ins += [f["finding"] for f in findings if f["finding"].startswith(("Total event", "Dari ", "Reputasi"))]
    recs = _dedupe([f["recommendation"] for f in findings])
    acts = _dedupe([f["action"] for f in findings])
    prev = _dedupe([f["prevention"] for f in findings])
    return {"kesimpulan": _dedupe(kes), "implikasi": impl, "insight": _dedupe(ins),
            "rekomendasi": recs, "tindakan": acts, "pencegahan": prev}


def ai_payload(a, rep_summary=None):
    """Payload aman untuk AI eksternal: hanya statistik teragregasi. TIDAK menyertakan source IP,
    destination IP, username, URL penuh, atau nama aset internal."""
    return {"domain": "IPS", "total_events": a["total_events"],
            "severity": {r["Severity"]: float(r["Count"]) for _, r in a["severity"].iterrows()},
            "top_attack": a["top_attacks"][["Attack Name", "Count"]].to_dict("records"),
            "top_country": a["top_country"][["Source Country", "Count"]].to_dict("records"),
            "category": a["categories"][["Category", "Count"]].to_dict("records"),
            "unique": a["unique"], "reputation": rep_summary or {}}
