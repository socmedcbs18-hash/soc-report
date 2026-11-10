"""
Lookup mapping rule -> Cyber Kill Chain + MITRE ATT&CK (v2.2, dasar ATT&CK v20.0).

Kenapa ada modul ini: label Kill Chain/MITRE di tiket Ivanti adalah SALINAN anotasi
rule Splunk lama, dan sebagian besar salah (lihat Mapping_Alert_FINAL). Selama anotasi
di Splunk belum diperbaiki, laporan tetap harus benar - jadi label diganti saat
report dibuat, berdasarkan NAMA RULE. Label asli tiket TIDAK dibuang: disimpan di
kolom '<kolom> (Ivanti)' dan bisa dipilih lewat toggle di dashboard.

Aturan penerapan (per rule):
- status 'Siap...'            -> label rekomendasi dipakai (kategori Serangan) atau
                                 dikosongkan (Perubahan/Operasional/Informasional/Agregasi).
- status 'Usulan...'/'Perlu review SPL' -> belum disetujui: label tiket dipakai apa adanya
                                 dan ditandai, supaya kelihatan berapa tiket yang belum dipetakan.
- rule tidak ada di lookup    -> dicoba pola alert non-Splunk (FortiRecon, Defender, dst);
                                 kalau tetap tidak ada, label tiket dipakai apa adanya.
Tidak ada label yang dikarang: semua nilai berasal dari config/data/*.
"""

import difflib
import json
import re
from functools import lru_cache
from pathlib import Path

import pandas as pd

from utils.helpers import clean_rule_name

try:
    from config.settings import TERAPKAN_LABEL_USULAN as _APPLY_PROPOSED
except Exception:  # pragma: no cover
    _APPLY_PROPOSED = False

DATA_DIR = Path(__file__).resolve().parent.parent / "config" / "data"
RULE_CSV = DATA_DIR / "rule_killchain_mitre.csv"
PATTERN_JSON = DATA_DIR / "alert_nonsplunk_patterns.json"

KATEGORI_LABEL = {
    "S": "Serangan",
    "P": "Perubahan/kebijakan",
    "O": "Operasional",
    "I": "Informasional",
    "R": "Agregasi risiko",
    "U": "PENDING (belum dipetakan)",
    "T": "Tiket uji",
}
# Kategori yang TIDAK masuk grafik Kill Chain
NON_ATTACK = {"P", "O", "I", "R"}

SRC_MAPPING = "mapping v2.2 (rule dikenal)"
SRC_NONSPLUNK = "mapping v2.2 (alert non-Splunk, usulan)"
SRC_PROPOSED = "mapping v2.2 (usulan, belum dikonfirmasi SPL)"
SRC_TICKET_PENDING = "label tiket (rule menunggu review)"
SRC_TICKET_UNKNOWN = "label tiket (rule tidak ada di mapping)"
SRC_TEST = "tiket uji (dikeluarkan)"

_FUZZY_CUTOFF = 0.88


@lru_cache(maxsize=1)
def load_rule_mapping():
    """DataFrame mapping, di-index oleh nama rule ternormalisasi (clean_rule_name)."""
    df = pd.read_csv(RULE_CSV, dtype=str, keep_default_na=False)
    df["_key"] = df["rule_name"].map(clean_rule_name)
    return df.drop_duplicates(subset="_key").set_index("_key")


@lru_cache(maxsize=1)
def _patterns():
    with open(PATTERN_JSON, encoding="utf-8") as f:
        pats = json.load(f)
    for p in pats:
        p["_re"] = re.compile(p["pattern"], re.IGNORECASE)
    return pats


@lru_cache(maxsize=4096)
def lookup_rule(name):
    """Cari 1 nama rule/alert. Return dict atau None.
    Urutan: nama persis (ternormalisasi) -> nama mirip (>=0.88) -> pola non-Splunk."""
    raw = "" if name is None or (isinstance(name, float) and pd.isna(name)) else str(name)
    key = clean_rule_name(raw)
    rules = load_rule_mapping()
    if key and key in rules.index:
        return _from_rule(rules.loc[key], exact=True)
    if key:
        close = difflib.get_close_matches(key, list(rules.index), n=1, cutoff=_FUZZY_CUTOFF)
        if close:
            return _from_rule(rules.loc[close[0]], exact=False)
    for p in _patterns():
        if p["_re"].search(raw):
            return {
                "kode": p["kategori_kode"], "kc": p["cyber_kill_chain"], "mitre": p["mitre_attack"],
                "keyakinan": p["keyakinan"], "status": "Usulan - alert non-Splunk",
                "severity_rek": "", "rule": p["family"], "source": "nonsplunk", "exact": True,
            }
    return None


def _from_rule(r, exact):
    return {
        "kode": r["kategori_kode"], "kc": r["cyber_kill_chain"], "mitre": r["mitre_attack"],
        "keyakinan": r["keyakinan"], "status": r["status"], "severity_rek": r["severity_rekomendasi"],
        "rule": r["rule_name"], "source": "rule", "exact": exact,
    }


def _fmt(csv_text):
    ids = [t.strip() for t in str(csv_text).split(",") if t.strip()]
    return "[" + ", ".join(ids) + "]" if ids else "[]"


def rule_stages(name):
    """Stage Kill Chain hasil mapping untuk 1 nama rule (list, bisa kosong).
    Kosong untuk rule non-serangan, PENDING, atau tidak dikenal."""
    r = lookup_rule(name)
    if not r or r["kode"] != "S" or not (r["status"].startswith("Siap") or r["source"] == "nonsplunk"):
        return []
    return [r["kc"]] if r["kc"] else []


def apply_rule_mapping(df, name_col="Summary", mitre_col="Incident MITRE", kc_col="Incident KillChain", replace=True):
    """Tambah kolom metadata mapping ke DataFrame tiket dan (bila replace=True)
    ganti isi kolom MITRE/KillChain dengan label mapping untuk rule yang disetujui.

    Kolom baru: _Label_Source, _Rule_Category (kode), _Rule_Category_Label,
    _Rule_Confidence, _Rule_Status, _Severity_Rek, _Mapping_Rule, _Test_Ticket.
    Kolom asli disimpan sebagai '<mitre_col> (Ivanti)' dan '<kc_col> (Ivanti)'."""
    df = df.copy()
    names = df[name_col] if name_col in df.columns else pd.Series([""] * len(df), index=df.index)
    for col in (mitre_col, kc_col):
        if col not in df.columns:
            df[col] = ""
        df[col + " (Ivanti)"] = df[col]

    cache = {}
    out = {k: [] for k in ["mitre", "kc", "src", "kode", "kat", "conf", "status", "sev", "rule", "test"]}
    for orig_m, orig_k, nm in zip(df[mitre_col + " (Ivanti)"], df[kc_col + " (Ivanti)"], names):
        r = cache.get(nm, "?")
        if r == "?":
            r = cache[nm] = lookup_rule(nm)
        m, k = orig_m, orig_k
        if r is None:
            src, kode, conf, status, sev, rule, test = SRC_TICKET_UNKNOWN, "", "", "", "", "", False
        else:
            kode, conf, status, sev, rule = r["kode"], r["keyakinan"], r["status"], r["severity_rek"], r["rule"]
            test = kode == "T"
            proposed = _APPLY_PROPOSED and kode == "S" and status.startswith("Usulan")
            approved = status.startswith("Siap") or r["source"] == "nonsplunk" or proposed
            if test:
                src, m, k = SRC_TEST, "[]", "[]"
            elif kode == "U" or not approved:
                src = SRC_TICKET_PENDING
            else:
                src = SRC_PROPOSED if proposed else (SRC_MAPPING if r["source"] == "rule" else SRC_NONSPLUNK)
                if kode == "S":
                    m, k = _fmt(r["mitre"]), _fmt(r["kc"])
                else:
                    m, k = "[]", "[]"
        out["mitre"].append(m); out["kc"].append(k); out["src"].append(src); out["kode"].append(kode)
        out["kat"].append(KATEGORI_LABEL.get(kode, "Belum dipetakan")); out["conf"].append(conf)
        out["status"].append(status); out["sev"].append(sev); out["rule"].append(rule); out["test"].append(test)

    if replace:
        df[mitre_col] = out["mitre"]
        df[kc_col] = out["kc"]
    df["_Label_Source"] = out["src"]
    df["_Rule_Category"] = out["kode"]
    df["_Rule_Category_Label"] = out["kat"]
    df["_Rule_Confidence"] = out["conf"]
    df["_Rule_Status"] = out["status"]
    df["_Severity_Rek"] = out["sev"]
    df["_Mapping_Rule"] = out["rule"]
    df["_Test_Ticket"] = out["test"]
    if replace:
        from core.ticket_context import apply_ticket_context
        apply_ticket_context(df, mitre_col, kc_col)
    return df
