"""
Analisis turunan Kill Chain (sesuai MOM manajemen, Nov 2026):

1. Breakdown ALERT (Splunk) vs TIKET (Ivanti) per tahap Kill Chain -> gap alert-tiket.
2. Severity berdasarkan Kill Chain: tiket yang sudah masuk Exploitation (atau tahap
   sesudahnya) seharusnya Critical. Dihitung dari label mapping yang sudah divalidasi,
   BUKAN dari label tiket mentah (yang mayoritas salah mapping).
3. Valid Accounts (T1078) - seberapa dominan, dari rule mana, dan rule mana yang
   perlu di-tuning (False Positive tinggi).
4. Ringkasan sumber label (berapa tiket sudah dipetakan, berapa masih label tiket).

Semua fungsi murni (input DataFrame -> output DataFrame), tidak membaca file sendiri
selain lookup di core.rule_mapping. Tidak ada angka yang dikarang: kalau data tidak
cukup, hasilnya kosong, bukan perkiraan.
"""

import pandas as pd

from core.mitre_killchain import KILLCHAIN_STAGE_ORDER
from core.rule_mapping import KATEGORI_LABEL, lookup_rule, rule_stages

# Tahap yang dianggap "sudah masuk Exploitation atau lebih jauh" -> Critical.
CRITICAL_STAGES = {"Exploitation", "Installation", "Privilege Escalation",
                   "Command & Control", "Actions On Objectives"}
_STAGE_KEY = {s.lower(): s for s in KILLCHAIN_STAGE_ORDER}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Tidak diketahui"]
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Tidak diketahui": -1}

VALID_ACCOUNTS_MIN_TICKETS = 10     # minimal tiket untuk dinilai
VALID_ACCOUNTS_FP_THRESHOLD = 0.70  # False Positive >= 70% dari yang ditriase -> perlu tuning


def normalize_severity(value):
    """Severity tiket Ivanti bervariasi (critical/High/'-'/'notice'/teks nyasar).
    Nilai di luar 5 kategori baku -> 'Tidak diketahui' (tidak ditebak)."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "Tidak diketahui"
    v = str(value).strip().lower()
    if v in ("critical", "high", "medium", "low"):
        return v.title()
    if v in ("informational", "info", "notice"):
        return "Informational"
    return "Tidak diketahui"


def add_effective_severity(df):
    """Tambah _Severity_Norm, _Stage_Critical, _Severity_Efektif, _Severity_Naik.
    _Severity_Efektif = Critical bila tiket punya tahap >= Exploitation DAN terkonfirmasi (Triage True Positive
    atau Cause Code Breach - Reported). Tiket yang belum terkonfirmasi tetap memakai severity aslinya: Critical
    memicu CSIRT, jadi tidak boleh naik hanya dari label rule. Bila data tidak punya kolom Triage sama sekali
    (export lama), perilaku lama dipakai. _Severity_Naik = True kalau efektif > asli."""
    df = df.copy()
    sev_col = "Severity" if "Severity" in df.columns else None
    df["_Severity_Norm"] = df[sev_col].map(normalize_severity) if sev_col else "Tidak diketahui"
    stages_col = df["_KillChain_Stages"] if "_KillChain_Stages" in df.columns else pd.Series([[]] * len(df), index=df.index)
    crit = stages_col.map(lambda L: any(_STAGE_KEY.get(str(x).lower(), x) in CRITICAL_STAGES for x in L))
    if "_Triage" in df.columns:
        _tri = df["_Triage"].astype(str).str.lower().str.startswith("true")
        _cc = df["Cause Code"].astype(str).str.lower().str.startswith("breach") if "Cause Code" in df.columns else pd.Series(False, index=df.index)
        crit = crit & (_tri | _cc)
    df["_Stage_Critical"] = crit
    eff = []
    for sev, c in zip(df["_Severity_Norm"], crit):
        eff.append("Critical" if c else sev)
    df["_Severity_Efektif"] = eff
    df["_Severity_Naik"] = [(_SEV_RANK[e] > _SEV_RANK[a]) for a, e in zip(df["_Severity_Norm"], eff)]
    return df


def build_killchain_severity(df):
    """Per tahap Kill Chain: jumlah tiket, sebaran severity asli, dan berapa yang
    seharusnya Critical tetapi belum. df = hasil add_effective_severity."""
    cols = ["Stage", "Tiket", "Critical", "High", "Medium", "Low", "Lainnya", "Perlu_Naik_ke_Critical", "Persen_Perlu_Naik"]
    if len(df) == 0 or "_Severity_Norm" not in df.columns:
        return pd.DataFrame(columns=cols)
    rows = []
    for stage in KILLCHAIN_STAGE_ORDER:
        sub = df[df["_KillChain_Stages"].map(lambda L: any(str(x).lower() == stage.lower() for x in L))]
        if len(sub) == 0:
            continue
        vc = sub["_Severity_Norm"].value_counts()
        naik = int(sub["_Severity_Naik"].sum()) if stage in CRITICAL_STAGES else 0
        rows.append({
            "Stage": stage, "Tiket": len(sub),
            "Critical": int(vc.get("Critical", 0)), "High": int(vc.get("High", 0)),
            "Medium": int(vc.get("Medium", 0)), "Low": int(vc.get("Low", 0)),
            "Lainnya": int(len(sub) - sum(vc.get(k, 0) for k in ("Critical", "High", "Medium", "Low"))),
            "Perlu_Naik_ke_Critical": naik,
            "Persen_Perlu_Naik": round(100 * naik / len(sub), 1) if stage in CRITICAL_STAGES else 0.0,
        })
    return pd.DataFrame(rows, columns=cols)


def build_severity_raise_by_rule(df, top=20):
    """Rule yang menghasilkan tiket berseverity di bawah Critical padahal sudah di
    Exploitation ke atas - bahan perubahan severity di Splunk."""
    cols = ["Rule", "Tiket_Perlu_Naik", "Total_Tiket", "Severity_Asli_Terbanyak", "Stage"]
    if len(df) == 0 or "_Severity_Naik" not in df.columns:
        return pd.DataFrame(columns=cols)
    name_col = "_Mapping_Rule" if "_Mapping_Rule" in df.columns else ("Summary" if "Summary" in df.columns else None)
    if name_col is None:
        return pd.DataFrame(columns=cols)
    d = df.copy()
    d["_Rule"] = d[name_col].replace("", pd.NA).fillna(d["Summary"] if "Summary" in d.columns else "(tidak diketahui)")
    g = d.groupby("_Rule")
    out = pd.DataFrame({
        "Tiket_Perlu_Naik": g["_Severity_Naik"].sum().astype(int),
        "Total_Tiket": g.size(),
        "Severity_Asli_Terbanyak": g["_Severity_Norm"].agg(lambda s: s.mode().iloc[0] if not s.mode().empty else "-"),
        "Stage": g["_KillChain_Stages"].agg(lambda s: ", ".join(sorted({x for L in s for x in L}))),
    }).reset_index().rename(columns={"_Rule": "Rule"})
    out = out[out["Tiket_Perlu_Naik"] > 0].sort_values("Tiket_Perlu_Naik", ascending=False).head(top)
    return out[cols].reset_index(drop=True)


def _row_group(name):
    """(kelompok, jenis) untuk 1 nama rule/alert."""
    stages = rule_stages(name)
    if stages:
        s = _STAGE_KEY.get(stages[0].lower(), stages[0])
        return s, "Stage Kill Chain"
    r = lookup_rule(name)
    if r is None:
        return "Belum dipetakan (rule tidak ada di mapping)", "Di luar Kill Chain"
    if r["kode"] in ("P", "O", "I", "R"):
        return KATEGORI_LABEL[r["kode"]], "Di luar Kill Chain"
    return "Belum dipetakan (PENDING / menunggu review)", "Di luar Kill Chain"


def build_killchain_alert_breakdown(alert_df, incident_df, alert_name_col="Alert Name", incident_name_col="Summary"):
    """Breakdown ALERT Splunk vs TIKET Ivanti per tahap Kill Chain.

    - Alert = jumlah baris notifikasi alert; Tiket = jumlah tiket unik; keduanya
      dikelompokkan lewat mapping nama rule (core.rule_mapping).
    - Gap = Alert - Tiket (positif: alert yang tidak berujung tiket; negatif: tiket
      melebihi alert, mis. tiket dari alert non-Splunk atau satu tiket menampung banyak alert).
    Return (per_stage, per_rule)."""
    cols_stage = ["Kelompok", "Jenis", "Rule_Aktif", "Alert", "Tiket", "Konversi_Persen", "Gap_Alert_minus_Tiket"]
    cols_rule = ["Kelompok", "Rule", "Alert", "Tiket", "Gap_Alert_minus_Tiket", "Severity_Rekomendasi"]
    a = pd.DataFrame(columns=["Rule", "Kelompok", "Jenis"])
    t = pd.DataFrame(columns=["Rule", "Kelompok", "Jenis"])
    if alert_df is not None and len(alert_df) > 0 and alert_name_col in alert_df.columns:
        names = alert_df[alert_name_col].fillna("").astype(str)
        grp = {n: _row_group(n) for n in names.unique()}
        a = pd.DataFrame({"Rule": names.values, "Kelompok": [grp[n][0] for n in names], "Jenis": [grp[n][1] for n in names]})
    if incident_df is not None and len(incident_df) > 0 and incident_name_col in incident_df.columns:
        inc = incident_df.drop_duplicates(subset=["Incident"]) if "Incident" in incident_df.columns else incident_df
        names = inc[incident_name_col].fillna("").astype(str)
        grp = {n: _row_group(n) for n in names.unique()}
        t = pd.DataFrame({"Rule": names.values, "Kelompok": [grp[n][0] for n in names], "Jenis": [grp[n][1] for n in names]})
    if len(a) == 0 and len(t) == 0:
        return pd.DataFrame(columns=cols_stage), pd.DataFrame(columns=cols_rule)

    def _key(s):  # nama rule dinormalkan agar alert & tiket (beda tulisan) bertemu
        from utils.helpers import clean_rule_name
        return s.map(clean_rule_name)

    a["_k"], t["_k"] = _key(a["Rule"]), _key(t["Rule"])
    ac = a.groupby(["Kelompok", "Jenis", "_k"]).size().rename("Alert")
    tc = t.groupby(["Kelompok", "Jenis", "_k"]).size().rename("Tiket")
    per_rule = pd.concat([ac, tc], axis=1).fillna(0).astype(int).reset_index()
    per_rule["Gap_Alert_minus_Tiket"] = per_rule["Alert"] - per_rule["Tiket"]
    # nama tampil: pakai nama asli pertama yang ditemui
    disp = {}
    for df_ in (a, t):
        for k, n in zip(df_["_k"], df_["Rule"]):
            disp.setdefault(k, n)
    per_rule["Rule"] = per_rule["_k"].map(disp)
    per_rule["Severity_Rekomendasi"] = per_rule["Rule"].map(lambda n: (lookup_rule(n) or {}).get("severity_rek", "") or "")
    per_rule = per_rule.sort_values(["Gap_Alert_minus_Tiket"], ascending=False)[cols_rule].reset_index(drop=True)

    jenis = pd.concat([a[["Kelompok", "Jenis"]], t[["Kelompok", "Jenis"]]]).drop_duplicates("Kelompok").set_index("Kelompok")["Jenis"]
    g = per_rule.groupby("Kelompok").agg(Rule_Aktif=("Rule", "count"), Alert=("Alert", "sum"), Tiket=("Tiket", "sum")).reset_index()
    g["Jenis"] = g["Kelompok"].map(jenis)
    g["Konversi_Persen"] = [round(100 * ti / al, 1) if al else None for al, ti in zip(g["Alert"], g["Tiket"])]
    g["Gap_Alert_minus_Tiket"] = g["Alert"] - g["Tiket"]
    order = {s: i for i, s in enumerate(KILLCHAIN_STAGE_ORDER)}
    g["_o"] = g["Kelompok"].map(lambda k: (0, order[k]) if k in order else (1, 99))
    g = g.sort_values("_o").drop(columns="_o")[cols_stage].reset_index(drop=True)
    return g, per_rule


def build_valid_accounts_insight(df):
    """Valid Accounts (T1078*): seberapa dominan, dibandingkan label Ivanti asli, dan
    rule mana yang perlu di-tuning. df = enriched (butuh _MITRE_Techniques; bila ada
    _MITRE_Techniques_Tiket dipakai sebagai pembanding label asli)."""
    cols = ["Rule", "Tiket", "True_Positive", "False_Positive", "Persen_False_Positive", "Perlu_Tuning"]
    summary = {"tiket_label_ivanti": None, "tiket_label_mapping": 0, "total_tiket": len(df), "teks": []}
    if len(df) == 0 or "_MITRE_Techniques" not in df.columns:
        return summary, pd.DataFrame(columns=cols)

    def has78(L):
        return any(str(x).upper().startswith("T1078") for x in L)

    m = df["_MITRE_Techniques"].map(has78)
    summary["tiket_label_mapping"] = int(m.sum())
    if "_MITRE_Techniques_Tiket" in df.columns:
        summary["tiket_label_ivanti"] = int(df["_MITRE_Techniques_Tiket"].map(has78).sum())
    sub = df[m]
    name_col = "_Mapping_Rule" if "_Mapping_Rule" in sub.columns else "Summary"
    if len(sub) == 0 or name_col not in sub.columns:
        return summary, pd.DataFrame(columns=cols)
    tri = sub["_Triage"] if "_Triage" in sub.columns else pd.Series(["Unknown"] * len(sub), index=sub.index)
    d = pd.DataFrame({"Rule": sub[name_col].replace("", pd.NA).fillna(sub["Summary"] if "Summary" in sub.columns else "(tidak diketahui)"), "T": tri})
    g = d.groupby("Rule")["T"].agg(
        Tiket="size",
        True_Positive=lambda s: int((s == "True Positive").sum()),
        False_Positive=lambda s: int((s == "False Positive").sum()),
    ).reset_index()
    tri_n = g["True_Positive"] + g["False_Positive"]
    g["Persen_False_Positive"] = [round(100 * f / n, 1) if n else None for f, n in zip(g["False_Positive"], tri_n)]
    g["Perlu_Tuning"] = [
        "Ya" if (n >= VALID_ACCOUNTS_MIN_TICKETS and f / n >= VALID_ACCOUNTS_FP_THRESHOLD) else ""
        for f, n in zip(g["False_Positive"], tri_n)
    ]
    g = g.sort_values("Tiket", ascending=False).reset_index(drop=True)[cols]

    tuning = g[g["Perlu_Tuning"] == "Ya"]
    teks = []
    if summary["tiket_label_ivanti"] is not None and summary["tiket_label_ivanti"] > 0:
        teks.append(f"Valid Accounts (T1078) muncul di {summary['tiket_label_ivanti']} tiket menurut label Ivanti asli, "
                    f"dan {summary['tiket_label_mapping']} tiket setelah dipetakan ulang per rule - selisihnya berasal "
                    "dari rule yang salah diberi label T1078.")
    if len(tuning) > 0:
        top = tuning.sort_values("Tiket", ascending=False).iloc[0]
        teks.append(f"{len(tuning)} rule berlabel Valid Accounts punya False Positive >= "
                    f"{int(VALID_ACCOUNTS_FP_THRESHOLD*100)}% (terbesar: '{str(top['Rule'])[:70]}', {int(top['Tiket'])} tiket) "
                    "- ini kandidat tuning deteksi, bukan sekadar perbaikan label.")
    summary["teks"] = teks
    return summary, g


def build_label_source_summary(df):
    """Berapa tiket yang labelnya sudah dari mapping vs masih label tiket. Dasar
    kepercayaan angka Kill Chain di report."""
    cols = ["Sumber_Label", "Tiket", "Persen"]
    if len(df) == 0 or "_Label_Source" not in df.columns:
        return pd.DataFrame(columns=cols)
    vc = df["_Label_Source"].value_counts()
    out = vc.rename_axis("Sumber_Label").reset_index(name="Tiket")
    out["Persen"] = (100 * out["Tiket"] / out["Tiket"].sum()).round(1)
    return out[cols]


def build_rule_category_summary(df):
    """Tiket per kategori rule (Serangan / Perubahan-kebijakan / ...) - panel terpisah
    untuk yang bukan serangan, supaya tidak tercampur di grafik Kill Chain."""
    cols = ["Kategori", "Tiket", "Persen"]
    if len(df) == 0 or "_Rule_Category_Label" not in df.columns:
        return pd.DataFrame(columns=cols)
    vc = df["_Rule_Category_Label"].value_counts()
    out = vc.rename_axis("Kategori").reset_index(name="Tiket")
    out["Persen"] = (100 * out["Tiket"] / out["Tiket"].sum()).round(1)
    return out[cols]


_TICKET_LABEL_COLS = ["_KillChain_Stages", "_KillChain_Invalid", "_MITRE_Tactics", "_MITRE_Techniques", "_MITRE_Invalid"]


def use_ticket_labels(df):
    """Ganti kolom label aktif dengan label ASLI tiket (kolom *_Tiket) - dipakai toggle
    'Label tiket apa adanya' di dashboard. Bila kolom *_Tiket tidak ada, df dikembalikan apa adanya."""
    if not all(c + "_Tiket" in df.columns for c in _TICKET_LABEL_COLS):
        return df
    d = df.copy()
    for c in _TICKET_LABEL_COLS:
        d[c] = d[c + "_Tiket"]
    return d
