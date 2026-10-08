"""Sumber Akamai (Cloud WAF / Anti-DDoS / Anti-BOT): parser export bulanan dari tim Akamai, validasi, ringkasan, insight.

Format yang dikenali (diperiksa dari file asli, bukan ditebak): workbook .xlsx dengan sheet 'WAF Attack', 'BOT Attack',
'Bad Reputation', 'DOS'. Tiap sheet berisi beberapa tabel 'top 5 + Others' dengan kolom <label> | Total Hits | By %.
Tabel dikenali dari header 'Total Hits' (bukan dari posisi sel tetap), jadi tata letak berdampingan (WAF/BOT) maupun
bertumpuk (Bad Reputation/DOS) sama-sama terbaca. Kolom 'By %' dari file TIDAK dipakai (dihitung ulang dari hit).

Batasan yang jujur: file hanya berisi agregat (top 5 + Others) tanpa timestamp, action, IP, URL, atau rule ID."""
import re
from collections import OrderedDict

SECTION_ORDER = ["badrep", "waf", "bot", "dos"]
SECTION_TITLE = {"badrep": "Bad Reputation IP/Client", "waf": "WAF (App Protection)", "bot": "BOT Traffic", "dos": "DoS Traffic"}
SECTION_DESC = {
    "badrep": "Traffic dari IP/sumber yang masuk daftar hitam (reputasi buruk) karena sering dipakai penyerang atau web scraper.",
    "waf": "Traffic HTTP(S) yang berusaha mengeksploitasi celah aplikasi web, misalnya SQLi, XSS, Path Traversal.",
    "bot": "Traffic otomatis (robot) untuk crawling/scraping, mis. mesin pencari, SEO, atau media sosial.",
    "dos": "Traffic yang sengaja dibuat untuk membanjiri server/aplikasi sampai melambat atau tidak bisa diakses.",
}
SECTION_COLOR = {"badrep": "#8b5cf6", "waf": "#e34948", "bot": "#e0a100", "dos": "#3987e5"}
SHEET_NAMES = {"waf": "waf attack", "bot": "bot attack", "badrep": "bad reputation", "dos": "dos"}
DIM_LABEL = {"category": "Kategori / tipe", "destination": "Host tujuan (Dest)", "country": "Negara sumber"}
DIM_ORDER = ["category", "destination", "country"]
OTHERS = "Others"

CFG = {"dominant_share_pct": 50.0, "concentration_pct": 50.0, "country_pct": 40.0, "others_pct": 30.0,
       "multi_section_min": 3, "top_type_pct": 30.0}

# Catatan netral per label (definisi umum dari nama; bukan klaim tentang kejadian di ALTO). Label tak dikenal = tanpa catatan.
LABEL_NOTES = [
    (r"local file inclusion", "upaya membaca file lokal server lewat parameter aplikasi (path traversal/LFI)"),
    (r"cross.?site scripting|xss", "upaya menyisipkan skrip ke halaman web (XSS)"),
    (r"sql", "upaya menyisipkan perintah SQL (SQL injection)"),
    (r"browser impersonator", "klien otomatis yang meniru browser; dapat berkaitan dengan scraping atau otomasi"),
    (r"http librar", "klien berbasis library HTTP (skrip/aplikasi), bukan browser"),
    (r"ai (fetchers|search)", "bot terkait layanan AI (fetcher/crawler)"),
    (r"web attackers", "sumber yang diklasifikasi Akamai sebagai pelaku serangan web"),
    (r"network control", "kategori kontrol DoS bernama Network Control (makna rule persisnya perlu dikonfirmasi ke tim Akamai)"),
    (r"rate control", "kategori kontrol DoS bernama Rate Control (pembatasan laju; konfirmasi detail rule ke tim Akamai)"),
]


class AkamaiError(ValueError):
    pass


def _clean(v):
    if v is None:
        return ""
    return re.sub(r"[​‌‍﻿ ]", "", str(v)).strip()


def _num(v):
    """Angka murni saja. Teks seperti '1.234' sengaja ditolak (ambigu desimal/ribuan) dan dicatat sebagai error baris."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v) if v == v and v >= 0 else None
    s = _clean(v)
    return float(s) if re.fullmatch(r"\d+(\.0+)?", s) else None


def _dim_of(header):
    h = header.lower()
    if "dest" in h or "host" in h:
        return "destination"
    if "country" in h or "negara" in h:
        return "country"
    return "category"


def _find_tables(rows, sheet_key):
    """Cari tabel dari header 'Total Hits'. Return (tables, issues)."""
    tables, issues = OrderedDict(), []
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            if _clean(cell).lower() != "total hits" or c == 0:
                continue
            header = _clean(row[c - 1])
            if not header:
                continue
            dim = _dim_of(header)
            if dim in tables:
                issues.append(("warn", f"Sheet {SHEET_NAMES[sheet_key]}: tabel '{header}' muncul lebih dari sekali; yang pertama dipakai."))
                continue
            items, total, pct_file = [], None, {}
            for rr in range(r + 1, len(rows)):
                rrow = rows[rr]
                label = _clean(rrow[c - 1]) if c - 1 < len(rrow) else ""
                raw = rrow[c] if c < len(rrow) else None
                if not label and raw is None:
                    break
                if label.lower().startswith("total"):
                    total = _num(raw)
                    break
                hits = _num(raw)
                if not label or hits is None:
                    issues.append(("error", f"Sheet {SHEET_NAMES[sheet_key]}, tabel '{header}', baris {rr + 1}: nilai hit bukan angka ({raw!r}); baris dilewati."))
                    continue
                items.append({"label": label, "hits": int(hits)})
                p = rrow[c + 1] if c + 1 < len(rrow) else None
                if isinstance(p, (int, float)) and not isinstance(p, bool):
                    pct_file[label] = float(p)
            tables[dim] = {"header": header, "items": items, "total": None if total is None else int(total), "_pct_file": pct_file}
    return tables, issues


def parse_workbook(source, filename=""):
    """source = path / file-like (.xlsx). Return dict parsed + checks. Tidak melempar error untuk sheet/tabel yang hilang
    (dilaporkan di checks); AkamaiError hanya bila file tak terbaca atau tidak ada satu pun sheet Akamai yang dikenali."""
    try:
        import openpyxl
        wb = openpyxl.load_workbook(source, read_only=True, data_only=True)
    except Exception as e:  # file rusak / bukan xlsx
        raise AkamaiError(f"File tidak dapat dibuka sebagai .xlsx: {e}") from e
    by_name = {re.sub(r"\s+", " ", _clean(ws.title)).lower(): ws for ws in wb.worksheets}
    parsed, checks, missing = OrderedDict(), [], []
    for key in SECTION_ORDER:
        ws = by_name.get(SHEET_NAMES[key])
        if ws is None:
            missing.append(SHEET_NAMES[key])
            continue
        rows = [list(r) for r in ws.iter_rows(values_only=True)]
        tables, issues = _find_tables(rows, key)
        for lvl, msg in issues:
            checks.append({"level": lvl, "msg": msg})
        if "category" not in tables:
            checks.append({"level": "error", "msg": f"Sheet '{SHEET_NAMES[key]}': tabel kategori (kolom pertama + 'Total Hits') tidak ditemukan."})
            continue
        parsed[key] = {"title": SECTION_TITLE[key], "tables": tables}
    if not parsed:
        raise AkamaiError("Tidak ada sheet Akamai yang dikenali. Sheet yang ditemukan: "
                          f"{[ws.title for ws in wb.worksheets]}; yang diharapkan: WAF Attack, BOT Attack, Bad Reputation, DOS.")
    for name in missing:
        checks.append({"level": "warn", "msg": f"Sheet '{name}' tidak ada di file; bagian itu tidak ditampilkan dan tidak dihitung ke total."})
    checks += validate(parsed)
    for sec in parsed.values():
        for t in sec["tables"].values():
            t.pop("_pct_file", None)
    return {"filename": filename, "sections": parsed, "checks": checks, "missing_sheets": missing}


def validate(parsed):
    out = []
    for key, sec in parsed.items():
        name = SECTION_TITLE[key]
        totals = {}
        for dim, t in sec["tables"].items():
            s = sum(i["hits"] for i in t["items"])
            t["items_sum"] = s
            labels = [i["label"].lower() for i in t["items"]]
            if len(labels) != len(set(labels)):
                out.append({"level": "warn", "msg": f"{name} / {DIM_LABEL[dim]}: ada label ganda dalam satu tabel."})
            if t["total"] is None:
                out.append({"level": "warn", "msg": f"{name} / {DIM_LABEL[dim]}: baris Total tidak ditemukan; jumlah item ({s:,}) dipakai sebagai total."})
                t["total"] = s
            elif t["total"] != s:
                out.append({"level": "error", "msg": f"{name} / {DIM_LABEL[dim]}: jumlah item {s:,} ≠ baris Total {t['total']:,} (selisih {t['total'] - s:+,})."})
            else:
                out.append({"level": "ok", "msg": f"{name} / {DIM_LABEL[dim]}: jumlah item = Total ({s:,})."})
            totals[dim] = t["total"]
            for lab, p in (t.get("_pct_file") or {}).items():
                hits = next((i["hits"] for i in t["items"] if i["label"] == lab), None)
                if hits is not None and t["total"] and abs(p - hits / t["total"]) > 0.005:
                    out.append({"level": "warn", "msg": f"{name} / {DIM_LABEL[dim]} / {lab}: kolom By % di file ({p * 100:.1f}%) ≠ hit/total ({hits / t['total'] * 100:.1f}%). Dashboard memakai hitungan ulang."})
        if len(set(totals.values())) > 1:
            out.append({"level": "warn", "msg": f"{name}: total tiap tabel berbeda {totals}; total tabel kategori yang dipakai sebagai total section."})
    return out


# ---------------------------------------------------------------- analytics
def _share(x, total):
    return (x / total * 100.0) if total else 0.0


def section_total(sec):
    return int(sec["tables"]["category"]["total"])


def table_rows(sec, dim):
    """[(label, hits, pct_of_section_total)] dengan Others di akhir; pct dihitung ulang."""
    t = sec["tables"].get(dim)
    if not t:
        return []
    total = t["total"] or sum(i["hits"] for i in t["items"])
    rows = [(i["label"], i["hits"], _share(i["hits"], total)) for i in t["items"]]
    return [r for r in rows if r[0] != OTHERS] + [r for r in rows if r[0] == OTHERS]


def note_for(label):
    for pat, note in LABEL_NOTES:
        if re.search(pat, label, flags=re.IGNORECASE):
            return note
    return None


def _base_host(h):
    parts = h.lower().split(".")
    while len(parts) > 1 and parts[-1] in {"id", "com", "co", "net", "org", "io"}:
        parts.pop()
    return ".".join(parts)


def summarize(parsed):
    secs = parsed["sections"]
    order = [k for k in SECTION_ORDER if k in secs]
    totals = {k: section_total(secs[k]) for k in order}
    grand = sum(totals.values())
    hosts = OrderedDict()
    for k in order:
        for lab, hits, _ in table_rows(secs[k], "destination"):
            if lab != OTHERS:
                hosts.setdefault(lab, {})[k] = hits
    host_rows = sorted(({"host": h, "by": by, "total": sum(by.values()), "n_sections": len(by)} for h, by in hosts.items()),
                       key=lambda x: (-x["n_sections"], -x["total"]))
    return {"order": order, "totals": totals, "grand_total": grand,
            "shares": {k: _share(v, grand) for k, v in totals.items()}, "hosts": host_rows}


def build_insights(parsed, summary=None):
    """Insight hedged: 'tercatat', 'mengindikasikan', 'perlu divalidasi'. Tidak pernah menyatakan kompromi/insiden tanpa bukti."""
    from cybersec_report.core.fmt import fmt_int, fmt_pct
    summary = summary or summarize(parsed)
    secs, out = parsed["sections"], []
    gt = summary["grand_total"]

    def add(level, title, text, section=None):
        out.append({"level": level, "title": title, "text": text, "section": section})

    if gt and summary["order"]:
        top = max(summary["order"], key=lambda k: summary["totals"][k])
        sh = summary["shares"][top]
        if sh >= CFG["dominant_share_pct"]:
            add("watch", f"{SECTION_TITLE[top]} mendominasi volume",
                f"{SECTION_TITLE[top]} tercatat {fmt_int(summary['totals'][top])} hit ({fmt_pct(sh, 1)}) dari total {fmt_int(gt)} hit pada kategori yang ada di file. "
                "File tidak memuat kolom action, sehingga tidak dapat dipastikan semuanya diblokir; angka ini adalah jumlah kejadian terdeteksi, bukan jumlah serangan yang berhasil.", top)
    for k in summary["order"]:
        sec, total = secs[k], section_total(secs[k])
        cat = table_rows(sec, "category")
        real = [r for r in cat if r[0] != OTHERS]
        if real and real[0][2] >= CFG["top_type_pct"]:
            n = note_for(real[0][0])
            add("info", f"{SECTION_TITLE[k]}: '{real[0][0]}' terbesar",
                f"'{real[0][0]}' tercatat {fmt_int(real[0][1])} hit ({fmt_pct(real[0][2], 1)} dari {SECTION_TITLE[k]})."
                + (f" Secara umum berarti {n}." if n else "") + " Perlu divalidasi apakah pola ini konsisten dengan bulan sebelumnya (tab Compare).", k)
        dest = [r for r in table_rows(sec, "destination") if r[0] != OTHERS]
        if dest and dest[0][2] >= CFG["concentration_pct"]:
            add("watch", f"{SECTION_TITLE[k]} terkonsentrasi pada satu host",
                f"{dest[0][0]} menerima {fmt_int(dest[0][1])} hit ({fmt_pct(dest[0][2], 1)} dari {SECTION_TITLE[k]}). "
                "Hal ini mengindikasikan trafik terfokus pada satu target; perlu divalidasi apakah berasal dari lonjakan penggunaan sah atau upaya serangan terarah.", k)
        ctry = [r for r in table_rows(sec, "country") if r[0] != OTHERS]
        if ctry and ctry[0][2] >= CFG["country_pct"]:
            add("info", f"{SECTION_TITLE[k]}: satu negara dominan",
                f"{ctry[0][0]} tercatat {fmt_int(ctry[0][1])} hit ({fmt_pct(ctry[0][2], 1)}). Negara adalah hasil geolokasi IP sumber, bukan atribusi pelaku; "
                "VPN, proxy, atau infrastruktur hosting dapat mengaburkan asal sebenarnya.", k)
        for dim in ("category", "destination", "country"):
            rows = table_rows(sec, dim)
            oth = next((r for r in rows if r[0] == OTHERS), None)
            if oth and oth[2] >= CFG["others_pct"]:
                add("info", f"{SECTION_TITLE[k]} / {DIM_LABEL[dim]}: 'Others' besar",
                    f"'Others' = {fmt_pct(oth[2], 1)} ({fmt_int(oth[1])} hit). File hanya memuat top 5, sehingga pola di luar top 5 tidak dapat dinilai dari data ini.", k)
    multi = [h for h in summary["hosts"] if h["n_sections"] >= CFG["multi_section_min"]]
    if multi:
        names = ", ".join(f"{h['host']} ({h['n_sections']} kategori, {fmt_int(h['total'])} hit)" for h in multi[:4])
        add("watch", "Host yang muncul di banyak kategori",
            f"Berdasarkan top 5 host tujuan tiap kategori: {names}. Mengindikasikan host ini menjadi target di beberapa jenis traffic sekaligus; "
            "layak diprioritaskan untuk review konfigurasi WAF/bot/rate control. Host di luar top 5 tidak terlihat di file.")
    groups = {}
    for h in summary["hosts"]:
        groups.setdefault(_base_host(h["host"]), set()).add(h["host"])
    for base, names in groups.items():
        if len(names) > 1:
            add("info", "Nama host serupa dengan domain berbeda",
                f"{', '.join(sorted(names))} memiliki nama dasar sama tetapi domain berbeda. Data TIDAK digabung; mohon konfirmasi ke tim Akamai apakah ini domain berbeda yang sah atau salah penulisan.")
    br = secs.get("badrep")
    if br:
        cat = [r for r in table_rows(br, "category") if r[0] != OTHERS]
        if cat and cat[0][2] >= CFG["dominant_share_pct"]:
            add("info", "Bad Reputation didominasi satu kategori",
                f"'{cat[0][0]}' = {fmt_pct(cat[0][2], 1)} dari {fmt_int(section_total(br))} hit. Klasifikasi berasal dari intelijen reputasi Akamai; IP tertentu belum diverifikasi independen.", "badrep")
    add("info", "Batasan data",
        "Total semua kategori adalah penjumlahan hit; satu permintaan dapat tercatat di lebih dari satu kategori (tidak dapat diverifikasi dari file). "
        "Periode ditentukan dari nama file/pilihan user karena file tidak memuat rentang tanggal.")
    return out


def to_excel(parsed, path):
    """Excel ringkas (semua tabel dengan % hitung ulang) untuk arsip/lampiran. Tanpa data lain."""
    import pandas as pd
    summary = summarize(parsed)
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        pd.DataFrame([{"Kategori": SECTION_TITLE[k], "Total Hits": summary["totals"][k], "By %": round(summary["shares"][k], 2)}
                      for k in summary["order"]] + [{"Kategori": "Total", "Total Hits": summary["grand_total"], "By %": 100.0}]
                     ).to_excel(w, sheet_name="Ringkasan", index=False)
        for k in summary["order"]:
            recs = [{"Tabel": DIM_LABEL[d], "Label": lab, "Total Hits": h, "By % (hitung ulang)": round(p, 2)}
                    for d in DIM_ORDER for lab, h, p in table_rows(parsed["sections"][k], d)]
            pd.DataFrame(recs).to_excel(w, sheet_name=SECTION_TITLE[k][:31].replace("/", "-"), index=False)
        pd.DataFrame([{"Level": i["level"], "Judul": i["title"], "Insight": i["text"]} for i in build_insights(parsed, summary)]
                     ).to_excel(w, sheet_name="Insight", index=False)
        pd.DataFrame(parsed["checks"]).to_excel(w, sheet_name="Validasi", index=False)
    return path
