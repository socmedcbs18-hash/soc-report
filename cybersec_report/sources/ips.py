"""Definisi sumber IPS / Firewall: klasifikasi signature, filter scope, urutan severity."""
import re

import numpy as np
import pandas as pd

SOURCE_TYPE = "IPS"
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low"]


def classify_attack(name, rules):
    """Cocokkan nama attack ke kamus (regex). Tidak cocok -> ('Uncategorized', None):
    sistem TIDAK memberi interpretasi untuk signature yang tidak dikenal."""
    if pd.isna(name):
        return "Uncategorized", None
    for r in rules:
        if re.search(r["pattern"], str(name), flags=re.IGNORECASE):
            return r["category"], r["note"]
    return "Uncategorized", None


def enrich(df_norm, rules):
    df = df_norm.copy()
    cls = df["attack_name"].map(lambda n: classify_attack(n, rules))
    df["category"] = cls.map(lambda t: t[0])
    return df


def scope_filter(df_norm, allowed_actions):
    """Filter default: action dropped/blocked/denied (configurable).
    Return (df_in_scope, df_excluded, filter_description)."""
    allowed = {a.lower() for a in allowed_actions}
    if df_norm["action"].notna().any():
        mask = df_norm["action"].isin(allowed)
        desc = "action in [" + ", ".join(sorted(allowed)) + "]"
    else:
        mask = pd.Series(True, index=df_norm.index)
        desc = "tanpa filter action (kolom action tidak tersedia)"
    return df_norm[mask].copy(), df_norm[~mask].copy(), desc
