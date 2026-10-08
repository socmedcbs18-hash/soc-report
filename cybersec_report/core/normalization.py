"""Schema detection + normalisasi ke canonical schema.
Semua analytics bekerja pada canonical schema, BUKAN pada nama kolom raw."""
import difflib
import re

import numpy as np
import pandas as pd

CANONICAL_FIELDS = [
    "timestamp", "source_type", "device", "environment", "action", "severity", "src_ip", "dst_ip",
    "src_country", "dst_country", "hostname", "username", "domain", "url", "attack_name", "rule_name",
    "category", "subcategory", "count", "status", "description",
]
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]


def norm_header(h):
    return re.sub(r"[\s\-]+", "_", str(h).strip().lower())


def detect_schema(raw_columns, source_type, mapping_cfg):
    """Pencocokan EXACT terhadap alias. Kemiripan hanya jadi SARAN (butuh konfirmasi user).
    Jika dua kolom raw cocok ke satu canonical field -> konflik, TIDAK dipilih otomatis."""
    cfg = mapping_cfg[source_type]
    aliases = {c: {norm_header(a) for a in al} for c, al in cfg["aliases"].items()}
    raw_norm = {c: norm_header(c) for c in raw_columns}
    mapping, conflicts, confidence = {}, {}, {}
    for canon, alias_set in aliases.items():
        hits = [raw for raw, n in raw_norm.items() if n in alias_set]
        if len(hits) == 1:
            mapping[canon], confidence[canon] = hits[0], 1.0
        elif len(hits) > 1:
            conflicts[canon] = hits
    used = set(mapping.values())
    unmapped = [c for c in raw_columns if c not in used and c not in sum(conflicts.values(), [])]
    suggestions = {}
    for canon in cfg["aliases"]:
        if canon in mapping:
            continue
        pool = list(aliases[canon]) + [canon]
        cand = []
        for raw in unmapped:
            best = max((difflib.SequenceMatcher(None, raw_norm[raw], p).ratio() for p in pool), default=0)
            if best >= 0.7:
                cand.append((raw, round(best, 2)))
        if cand:
            suggestions[canon] = sorted(cand, key=lambda x: -x[1])
    required = cfg.get("required", [])
    recommended = cfg.get("recommended", [])
    return {
        "source_type": source_type, "mapping": mapping, "confidence": confidence, "conflicts": conflicts,
        "unmapped_columns": unmapped, "suggestions": suggestions,
        "required": required, "recommended": recommended,
        "missing_required": [r for r in required if r not in mapping],
        "missing_recommended": [r for r in recommended if r not in mapping],
    }


def apply_manual_mapping(schema, manual):
    """Gabungkan pilihan user (canonical -> kolom raw) ke hasil detect_schema."""
    schema = {**schema, "mapping": dict(schema["mapping"]), "confidence": dict(schema["confidence"])}
    for canon, raw in manual.items():
        if raw:
            schema["mapping"][canon] = raw
            schema["confidence"][canon] = 1.0
            schema["conflicts"] = {k: v for k, v in schema["conflicts"].items() if k != canon}
    used = set(schema["mapping"].values())
    schema["unmapped_columns"] = [c for c in schema["unmapped_columns"] if c not in used]
    # Hitung ulang kolom yang masih hilang - tanpa ini mapping manual dari UI tidak pernah membuka blokir validasi.
    schema["missing_required"] = [r for r in schema.get("required", []) if r not in schema["mapping"]]
    schema["missing_recommended"] = [r for r in schema.get("recommended", []) if r not in schema["mapping"]]
    return schema


def normalize_severity(value):
    if pd.isna(value):
        return "Unknown"
    v = str(value).strip().lower()
    if v in ("critical", "high", "medium", "low"):
        return v.title()
    if v in ("info", "informational", "information"):
        return "Info"
    return "Unknown"


def normalize(df_raw, schema, source_type, device_env=None):
    """df_raw + mapping -> DataFrame canonical. Field yang tidak ada diisi NaN (BUKAN
    dikarang). Kolom bantu: severity_raw, count_valid, _row (nomor baris di file asli)."""
    mapping = schema["mapping"]
    out = pd.DataFrame(index=df_raw.index)
    for f in CANONICAL_FIELDS:
        out[f] = df_raw[mapping[f]] if f in mapping else np.nan
    for c in out.columns:
        if out[c].dtype == object:
            out[c] = out[c].apply(lambda x: x.strip() if isinstance(x, str) else x)
            out[c] = out[c].replace("", np.nan)
    out["source_type"] = source_type
    if "vd" in schema["mapping"]:
        out["vd"] = df_raw[schema["mapping"]["vd"]]
    out["severity_raw"] = out["severity"]
    out["severity"] = out["severity"].apply(normalize_severity)
    out["action"] = out["action"].astype("string").str.lower().astype(object)
    out["action"] = out["action"].where(out["action"].notna(), np.nan)
    # count: numerik. Tanpa kolom count -> tiap baris = 1 event (ditandai count_defaulted).
    if "count" in mapping:
        cnt = pd.to_numeric(out["count"], errors="coerce")
        out["count_valid"] = cnt.notna() & (cnt >= 0)
        out["count"] = cnt.where(out["count_valid"], 0).astype(float)
        out["count_invalid_value"] = pd.to_numeric(df_raw[mapping["count"]], errors="coerce")
    else:
        out["count"] = 1.0
        out["count_valid"] = True
        out["count_invalid_value"] = np.nan
    device_env = device_env or {}
    if "device" in mapping:
        out["environment"] = out["device"].map(lambda d: device_env.get(str(d), "Unmapped") if pd.notna(d) else "Unmapped")
    else:
        out["environment"] = "Unmapped"
    out["_row"] = df_raw.index + 2  # +2: header di baris 1, data mulai baris 2
    return out
