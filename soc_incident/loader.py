"""Loader + normalisasi tiket insiden Ivanti (SOC). Modul ini SELF-CONTAINED (tidak mengimpor modul lain).
Pencocokan kolom = EXACT terhadap alias (tidak menebak). Kolom wajib hilang -> LoaderError dengan daftar kolom yang ada."""
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

ALIASES = {
    "ticket": ["Ticket Number", "Incident", "Incident ID"],
    "created": ["Created On"],
    "resolved": ["Resolved Date Time", "Resolved On"],
    "closed": ["Closed On"],
    "active": ["Active DateTime", "Responded On"],
    "customer": ["Customer"],
    "incident_type": ["Incident Type"],
    "issue": ["Issue"],
    "sub_issue": ["Sub_Issue", "Sub Issue"],
    "product_type": ["Product Type"],
    "priority": ["Priority"],
    "status": ["Status"],
    "source": ["Source"],
    "owner": ["Owner"],
    "cause_code": ["Cause Code"],
    "dur_active": ["Duration Active (Minutes)"],
    "dur_resolved": ["Duration Resolved (Minutes)"],
    "breach_resp": ["FlagBreachResponse"],
    "breach_reso": ["FlagBreachReso", "FlagBreachResolution"],
    "maintenance": ["Ticket For Maintenance"],
}
REQUIRED = ["ticket", "created", "priority", "status"]
TEXT = ["customer", "incident_type", "issue", "sub_issue", "product_type", "status", "source", "owner", "cause_code"]
DATES = ["created", "resolved", "closed", "active"]


class LoaderError(Exception):
    pass


def load_config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _norm(h):
    return re.sub(r"[\s\-]+", "_", str(h).strip().lower())


def read_table(file, filename):
    name = (filename or getattr(file, "name", "")).lower()
    try:
        if name.endswith(".csv"):
            raw = pd.read_csv(file, sep=None, engine="python", encoding="utf-8-sig")
        elif name.endswith((".xlsx", ".xls")):
            xl = pd.ExcelFile(file)
            sheet = next((s for s in xl.sheet_names if "soc" in s.lower()), xl.sheet_names[0])
            raw = xl.parse(sheet)
        else:
            raise LoaderError("Format file tidak didukung (gunakan CSV, XLSX, atau XLS).")
    except LoaderError:
        raise
    except Exception as e:  # file rusak / bukan tabel
        raise LoaderError(f"File tidak dapat dibaca: {e}")
    raw = raw.dropna(how="all")
    return raw, {"filename": filename or name, "rows": len(raw), "columns": list(raw.columns)}


def detect_mapping(columns):
    norm = {_norm(c): c for c in columns}
    mapping = {}
    for canon, aliases in ALIASES.items():
        for a in aliases:
            if _norm(a) in norm:
                mapping[canon] = norm[_norm(a)]
                break
    return mapping


def normalize(raw, mapping, cfg=None):
    """Return (DataFrame canonical, notes). Field yang tidak ada = NaN (tidak dikarang). Kolom bantu: is_auto."""
    cfg = cfg or load_config()
    missing = [r for r in REQUIRED if r not in mapping]
    if missing:
        raise LoaderError("Kolom wajib tidak ditemukan: " + ", ".join(missing) + ". Kolom di file: " + ", ".join(map(str, raw.columns)))
    out = pd.DataFrame(index=raw.index)
    for canon in ALIASES:
        out[canon] = raw[mapping[canon]] if canon in mapping else np.nan
    for c in DATES:
        out[c] = pd.to_datetime(out[c], errors="coerce")
    for c in TEXT:
        out[c] = out[c].apply(lambda x: x.strip() if isinstance(x, str) else x).replace("", np.nan)
    out["priority"] = pd.to_numeric(out["priority"], errors="coerce")
    for c in ("dur_active", "dur_resolved"):
        out[c] = pd.to_numeric(out[c], errors="coerce")
    for c in ("breach_resp", "breach_reso", "maintenance"):
        out[c] = pd.to_numeric(out[c], errors="coerce")
    notes = []
    dups = int(out["ticket"].duplicated().sum())
    if dups:
        out = out.drop_duplicates("ticket", keep="last")
        notes.append(f"{dups} baris duplikat Ticket Number dibuang (diambil baris terakhir).")
    bad_ts = int(out["created"].isna().sum())
    if bad_ts:
        notes.append(f"{bad_ts} tiket tanpa Created On valid dikeluarkan dari analisis.")
        out = out[out["created"].notna()]
    if out.empty:
        raise LoaderError("Tidak ada tiket dengan Created On yang valid.")
    pats = [p.lower() for p in cfg["system_customer_patterns"]]
    out["is_auto"] = out["customer"].astype("string").str.lower().fillna("").apply(lambda s: any(p in s for p in pats))
    out = out.sort_values(["created", "ticket"]).reset_index(drop=True)
    return out, notes


def detect_period(df):
    """Bulan laporan = bulan dengan tiket terbanyak. Bila ada bulan lain, dilaporkan sebagai peringatan (tidak dibuang diam-diam)."""
    ym = df["created"].dt.to_period("M")
    top = ym.value_counts().idxmax()
    start = top.start_time
    end = (top + 1).start_time
    others = {str(k): int(v) for k, v in ym.value_counts().items() if k != top}
    return {"year": int(top.year), "month": int(top.month), "start": start, "end": end, "other_months": others,
            "first_ticket_at": df["created"].min(), "last_ticket_at": df["created"].max()}
