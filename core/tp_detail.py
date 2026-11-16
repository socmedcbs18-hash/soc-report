"""Detail tiket True Positive: insiden teratas, sistem yang terdampak, orang terkait, sumber serangan (permintaan CTO).
Data diambil dari isi Description tiket Ivanti (pasangan 'kunci: nilai' dari alert Splunk)."""
import re
from collections import Counter

import pandas as pd

_KEY_RE = re.compile(r"(?:(?<=\s)|^)([A-Za-z_][A-Za-z0-9_]*):\s")
_SUFFIX_RE = re.compile(r"\s*-\s*Severity\s*\d+\s*$")

SISTEM_KEYS = ["host", "hostname", "computer", "devname", "dstip", "dest", "destination_ip", "target_internal"]
APP_KEYS = ["apps", "app"]
METRIC_KEYS = ["deny_count", "unique_ports", "total_events", "monitor_hits", "total_hits", "event_count", "count"]
ORANG_KEYS = ["user_email", "userid", "user", "principal", "recipients", "recipient"]
SUMBER_KEYS = ["client_ip", "srcip", "src_ip", "src", "ip_sender"]
DETAIL_KEYS = ["attack", "rule_message", "sensitive_file", "signature", "description", "threat", "policy"]
_SKIP_ORANG = {"threatintel", "system", "-", "", "nan", "none"}


def rule_name(s):
    return _SUFFIX_RE.sub("", str(s)).strip()


def parse_description(text):
    """Pasangan kunci:nilai (kunci huruf kecil) dari Description. Dipotong di 'View result in Splunk'."""
    t = re.sub(r"\s+", " ", str(text or ""))
    t = t.split("View result in Splunk")[0]
    ms = list(_KEY_RE.finditer(t))
    out = {}
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(t)
        k = m.group(1).lower()
        v = t[m.end():end].strip()
        if k not in out and v:
            out[k] = v
    return out


def _flat(v, limit=3):
    """Nilai bisa berupa list JSON; ratakan, unik, batasi."""
    items = re.findall(r'"([^"]+)"', v) if v.startswith("[") else [v]
    seen, out = set(), []
    for x in items:
        x = x.strip().strip(",")
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out[:limit]


def _site(path):
    m = re.search(r"/(?:sites|personal)/([^/\s]+)", path or "")
    return m.group(1) if m else ""


def extract_entities(text):
    """Return dict Sistem, Orang, Sumber, Detail (masing-masing list string)."""
    kv = parse_description(text)
    sistem = []
    for k in SISTEM_KEYS:
        if k in kv:
            for x in _flat(kv[k]):
                sistem.append(("FW " + x) if k == "devname" else x)
    for k in APP_KEYS:
        if k in kv:
            app = _flat(kv[k])[:1]
            site = _site(kv.get("file_path", ""))
            sistem.extend([f"{app[0]} ({site})" if site else app[0]] if app else [])
            break
    if "recipients" in kv:
        sistem.append("Email O365 (Exchange Online)")
    orang = []
    for k in ORANG_KEYS:
        if k in kv:
            orang = [x.lower() for x in _flat(kv[k]) if x.lower() not in _SKIP_ORANG]
            if orang:
                break
    sumber = []
    for k in SUMBER_KEYS:
        if k in kv:
            sumber = _flat(kv[k])
            break
    detail = []
    for k in DETAIL_KEYS:
        if k in kv:
            v = _flat(kv[k], 1)
            if v:
                detail.append(v[0][:90])
        if len(detail) >= 2:
            break
    metrik = [f"{k}={_flat(kv[k], 1)[0]}" for k in METRIC_KEYS if k in kv and _flat(kv[k], 1)][:2]
    return {"Sistem": sistem, "Orang": orang, "Sumber": sumber, "Detail": detail, "Metrik": metrik}


TENTANG = [
    ("Malicious Source IP", "IP berbahaya memindai banyak port ke firewall (ditolak)"),
    ("WebMoni", "Traffic dari/ke IP publik terdeteksi di firewall (indikasi scanning)"),
    ("Sensitive File Access", "Percobaan mengakses file sensitif (mis. .env) lewat aplikasi web"),
    ("Known Malicious IP", "IP dengan reputasi buruk mengakses aplikasi web"),
    ("Detected Phish", "Email phishing terdeteksi dan dikarantina"),
    ("Cross-Site Scripting", "Percobaan serangan XSS ke aplikasi web"),
    ("Command Injection", "Percobaan command injection ke aplikasi web"),
    ("SQL Injection", "Percobaan SQL injection ke aplikasi web"),
    ("Exfiltration via File", "Unduhan file massal dari SharePoint/OneDrive"),
    ("Failed Login", "Percobaan login gagal berulang ke aplikasi"),
    ("IDPS", "Scanning/serangan jaringan yang diblokir IDPS Fortinet"),
    ("Check Point ESG", "Anomali login (mis. dari negara tidak lazim, gagal di MFA)"),
    ("Cynet", "Aktivitas mencurigakan di endpoint terdeteksi Cynet"),
    ("PTA", "Aktivitas akun istimewa mencurigakan di CyberArk"),
    ("Malware on Email", "Email berisi malware terdeteksi"),
]


def tentang(rule):
    for k, v in TENTANG:
        if k.lower() in rule.lower():
            return v
    return "-"


def _top(counter, n=3):
    return ", ".join(f"{k} ({v})" if v > 1 else k for k, v in counter.most_common(n)) if counter else "-"


def _stage(v):
    return [t.strip() for t in str(v).strip("[]").split(",") if t.strip()]


def build_tp_tables(df, top_n=10, name_col="Summary", id_col="Incident"):
    """df: tiket terenrich (mitre_enriched_raw). Return (top_insiden, detail_tiket) khusus Triage True Positive."""
    cols_top = ["No", "Insiden", "Tentang", "Jumlah_TP", "Tahap_Kill_Chain", "MITRE", "Detail_Kejadian", "Sistem_Terdampak",
                "Orang_Terkait", "Sumber_Serangan", "Analyst_Utama"]
    cols_tk = ["Tiket", "Insiden", "Tahap_Kill_Chain", "Detail_Kejadian", "Sistem_Terdampak", "Orang_Terkait",
               "Sumber_Serangan", "Analyst", "Created On"]
    if df is None or len(df) == 0 or "Triage" not in df.columns:
        return pd.DataFrame(columns=cols_top), pd.DataFrame(columns=cols_tk)
    d = df[df["Triage"].astype(str).str.lower().str.startswith("true")].copy()
    if "_Test_Ticket" in d.columns:
        d = d[~d["_Test_Ticket"].fillna(False).astype(bool)]
    if d.empty:
        return pd.DataFrame(columns=cols_top), pd.DataFrame(columns=cols_tk)
    d["_rule"] = d[name_col].map(rule_name)
    ent = d["Description"].map(extract_entities) if "Description" in d.columns else pd.Series([{}] * len(d), index=d.index)
    kc_col = "Incident KillChain" if "Incident KillChain" in d.columns else None
    mi_col = "Incident MITRE" if "Incident MITRE" in d.columns else None
    tk = pd.DataFrame({
        "Tiket": d[id_col].astype(str),
        "Insiden": d["_rule"],
        "Tahap_Kill_Chain": d[kc_col].map(lambda v: ", ".join(_stage(v)) or "-") if kc_col else "-",
        "Detail_Kejadian": ent.map(lambda e: "; ".join(e.get("Detail", []) or e.get("Metrik", [])) or "-"),
        "Sistem_Terdampak": ent.map(lambda e: ", ".join(e.get("Sistem", [])) or "-"),
        "Orang_Terkait": ent.map(lambda e: ", ".join(e.get("Orang", [])) or "-"),
        "Sumber_Serangan": ent.map(lambda e: ", ".join(e.get("Sumber", [])) or "-"),
        "Analyst": d["Owner"].astype(str) if "Owner" in d.columns else "-",
        "Created On": d["Created On"] if "Created On" in d.columns else pd.NaT,
    })
    rows = []
    for rule, g in d.groupby("_rule"):
        e = ent.loc[g.index]
        c_sis, c_org, c_src, c_det, c_kc, c_mi = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
        for x in e:
            c_sis.update(x.get("Sistem", [])); c_org.update(x.get("Orang", [])); c_src.update(x.get("Sumber", []))
            c_det.update(x.get("Detail", []))
        if kc_col:
            for v in g[kc_col]:
                c_kc.update(_stage(v))
        if mi_col:
            for v in g[mi_col]:
                c_mi.update(t for t in _stage(v) if t.startswith("T"))
        rows.append({"Insiden": rule, "Tentang": tentang(rule), "Jumlah_TP": len(g), "Tahap_Kill_Chain": _top(c_kc, 2),
                     "MITRE": _top(c_mi, 2), "Detail_Kejadian": _top(c_det, 2), "Sistem_Terdampak": _top(c_sis, 3) if c_sis else "- (tidak tercatat di alert)",
                     "Orang_Terkait": _top(c_org, 3) if c_org else "- (aset/jaringan, tidak ada user)",
                     "Sumber_Serangan": _top(c_src, 3),
                     "Analyst_Utama": _top(Counter(g["Owner"].astype(str)), 1) if "Owner" in g.columns else "-"})
    top = pd.DataFrame(rows).sort_values("Jumlah_TP", ascending=False).head(top_n).reset_index(drop=True)
    top.insert(0, "No", top.index + 1)
    return top[cols_top], tk.sort_values("Created On").reset_index(drop=True)[cols_tk]
