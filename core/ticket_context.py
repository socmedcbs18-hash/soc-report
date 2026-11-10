"""Penyesuaian label Kill Chain/MITRE per TIKET berdasarkan isi Description.

Label per rule (config/data/rule_killchain_mitre.csv) menjawab "apa yang dideteksi rule ini". Beberapa rule
terlalu umum sehingga satu label rule salah untuk banyak tiketnya. Modul ini memakai bukti yang ADA di tiket
(identitas akun, jenis aktivitas, nama sub-rule Cynet) dan tidak menebak di luar itu.

Aturan:
- O365 Exfiltration via File (Download / Sync Download):
    * akun di luar @alto.id (guest, gmail, tenantanon/anonymous link) -> label rule tetap (Actions on Objectives).
    * akun @alto.id + FileSyncDownloadedFull (sinkronisasi klien OneDrive) -> bukan tahap serangan (label kosong).
    * akun @alto.id + FileDownloaded -> teknik Collection tetap dicatat, tetapi BUKAN tahap Kill Chain
      (unduh massal oleh akun internal belum bukti eksfiltrasi; perlu verifikasi).
- Anomaly File Operation (operasi file massal SharePoint/OneDrive internal): teknik tetap, bukan tahap Kill Chain.
- Cynet 'Unauthorized File Operation Attempt': dipetakan dari nama sub-rule di Description
    (Credentials Theft -> Credential Access T1555 / Exploitation; Ransomware Extension -> Impact T1486 / Actions on
    Objectives; sub-rule lain -> kosong + perlu review; nama tidak terbaca -> label rule dipertahankan).
"""
import re

SRC_CONTEXT = "mapping v2.2 + konteks tiket"
INTERNAL_DOMAIN = "@alto.id"


def _kv(text, key):
    m = re.search(rf"(?:^|\s){key}:\s*(\S+)", text)
    return m.group(1).strip().strip('"[],') if m else ""


def refine_ticket(rule, description, mitre, kc):
    """Return (mitre, kc, konteks, changed). rule = nama rule hasil mapping, description = teks tiket."""
    rule = str(rule or "")
    text = str(description or "")
    if "O365 Exfiltration via File" in rule:
        user = _kv(text, "user")
        sig = _kv(text, "signature")
        cnt = _kv(text, "count")
        if not user:
            return mitre, kc, "Identitas akun tidak ada di isi tiket (format email lama) - label rule dipertahankan, belum bisa diverifikasi", False
        if not user.lower().endswith(INTERNAL_DOMAIN):
            kind = "tautan anonim (tenantanon)" if "tenantanon" in user.lower() else f"akun di luar {INTERNAL_DOMAIN}"
            return mitre, kc, f"Identitas {kind}, {cnt or '?'} aktivitas: potensi eksfiltrasi ke pihak luar - label rule dipertahankan, perlu eskalasi", False
        who = "akun vendor/magang" if re.match(r"(vendor|intern)", user.lower()) else "akun internal"
        if sig.startswith("FileSyncDownloaded"):
            return "[]", "[]", f"Sinkronisasi klien OneDrive/SharePoint oleh {who} ({cnt or '?'} file) - aktivitas operasional, bukan tahap serangan", True
        return mitre, "[]", f"Unduh massal oleh {who} ({cnt or '?'} file): potensi Collection, perlu verifikasi - belum bukti eksfiltrasi, tidak dihitung sebagai tahap Kill Chain", True
    if "Anomaly File Operation" in rule:
        return mitre, "[]", "Operasi file massal pada SharePoint/OneDrive internal: perlu verifikasi - tidak dihitung sebagai tahap Kill Chain", True
    if "Unauthorized File Operation" in rule:
        m = re.search(r"Rule Name\s+(.+?)(?:\s{2,}|\s+Process Command Line|\s+Process Path|$)", text)
        if not m:
            return mitre, kc, "Nama sub-rule Cynet tidak terbaca - label rule dipertahankan", False
        sub = m.group(1).strip()
        low = sub.lower()
        if "credentials theft" in low or "credential theft" in low:
            tech = "T1555.003" if "browser" in low else "T1555"
            return f"[TA0006, {tech}]", "[Exploitation]", f"Cynet: {sub}", True
        if "ransomware" in low:
            return "[TA0040, T1486]", "[Actions on Objectives]", f"Cynet: {sub}", True
        return "[]", "[]", f"Cynet sub-rule '{sub}' belum dipetakan - perlu review", True
    return mitre, kc, "", False


def apply_ticket_context(df, mitre_col, kc_col, rule_col="_Mapping_Rule", desc_col="Description", src_col="_Label_Source"):
    """Terapkan refine_ticket ke seluruh baris; tambah kolom _Konteks_Tiket. Mengubah df secara in-place."""
    if desc_col not in df.columns or rule_col not in df.columns:
        df["_Konteks_Tiket"] = ""
        return df
    ctx, ms, ks, srcs = [], [], [], []
    for rule, desc, m, k, src in zip(df[rule_col], df[desc_col], df[mitre_col], df[kc_col], df[src_col]):
        if "mapping" not in str(src):  # tiket uji / label tiket asli tidak disentuh
            ms.append(m); ks.append(k); ctx.append(""); srcs.append(src); continue
        nm, nk, c, changed = refine_ticket(rule, desc, m, k)
        ms.append(nm); ks.append(nk); ctx.append(c); srcs.append(SRC_CONTEXT if changed else src)
    df[mitre_col], df[kc_col], df["_Konteks_Tiket"], df[src_col] = ms, ks, ctx, srcs
    return df
