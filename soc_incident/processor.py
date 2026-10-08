"""Analytics laporan insiden SOC bulanan. Murni pandas; tidak ada angka dikarang.
Inti: perpindahan state machine di tengah bulan -> data dipisah menjadi era 'old' dan 'new' agar tidak dibandingkan apel-ke-jeruk.
Cutover dideteksi dari data (field yang berhenti terisi) dan boleh di-override user."""
import numpy as np
import pandas as pd

from soc_incident import fmt
from soc_incident.loader import detect_period, load_config

ERA_LABEL = {"old": "State machine lama", "new": "State machine baru", "all": "Seluruh periode"}
SCHEMA_FIELDS = [("sub_issue", "Sub_Issue"), ("product_type", "Product Type"), ("cause_code", "Cause Code"),
                 ("resolved", "Resolved Date Time"), ("dur_resolved", "Duration Resolved")]
# (key, label, kind) -> kind menentukan format di UI/Excel
ERA_METRICS = [
    ("tickets", "Jumlah tiket", "int"), ("days", "Lama era (hari)", "f1"), ("per_day", "Tiket per hari", "f1"),
    ("p1_share", "Porsi P1 (High)", "pct"), ("p2_share", "Porsi P2 (Medium)", "pct"), ("p3_share", "Porsi P3 (Low)", "pct"),
    ("auto_share", "Tiket otomatis dari sistem", "pct"), ("email_share", "Sumber Email", "pct"),
    ("resp_median", "Waktu ke Active – median (MTTR)", "min"), ("resp_p90", "Waktu ke Active – P90", "min"),
    ("breach_n", "Tiket melewati batas respons", "int"), ("breach_rate", "Persentase melewati batas respons", "pct"),
    ("resolved_cov", "Tiket yang punya waktu Resolved", "pct"), ("resolved_median", "Created→Resolved – median", "min"),
    ("closed_no_resolve", "Closed tanpa waktu Resolved", "int"), ("closed_median", "Created→Closed – median", "min"),
]


def fmt_metric(v, kind):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "–"
    return {"int": lambda: fmt.num(v), "f1": lambda: fmt.num(v, 1), "pct": lambda: fmt.pct(v), "min": lambda: fmt.minutes(v)}[kind]()


def _cfg(cfg):
    return {**load_config(), **(cfg or {})}


# ---------------------------------------------------------------- cutover
def detect_cutover(df, cfg=None):
    """Cutover = awal 'ekor' tiket terakhir yang SEMUA field penanda skema lama (Product Type & Sub_Issue) kosong,
    sementara tiket sebelumnya masih punya. Butuh ekor minimal N tiket dan porsi minimal; jika tidak, 'tidak terdeteksi'."""
    c = _cfg(cfg)["cutover_detection"]
    fields = [f for f in c["marker_fields"] if f in df.columns]
    base = {"cutover": None, "first_ticket": None, "last_old_ticket": None, "tail": 0, "reason": ""}
    if not fields:
        return {**base, "reason": "Kolom penanda skema tidak ada di file."}
    d = df.sort_values(["created", "ticket"]).reset_index(drop=True)
    new_style = d[fields].isna().all(axis=1).to_numpy()
    if new_style.all() or not new_style.any():
        return {**base, "reason": "Seluruh tiket berpola sama (tidak ada perubahan skema)."}
    k = len(d)
    while k > 0 and new_style[k - 1]:
        k -= 1
    tail = len(d) - k
    if tail == 0 or k == 0:
        return {**base, "reason": "Tidak ada ekor tiket berskema baru yang konsisten."}
    if tail < c["min_tail_tickets"] or tail / len(d) < c["min_tail_share"] or k < c["min_tail_tickets"]:
        return {**base, "tail": tail, "reason": f"Ekor skema baru terlalu kecil ({tail} tiket) untuk disimpulkan sebagai cutover."}
    return {"cutover": d.loc[k, "created"], "first_ticket": int(d.loc[k, "ticket"]), "last_old_ticket": int(d.loc[k - 1, "ticket"]),
            "tail": tail, "reason": "Terdeteksi dari field yang berhenti terisi."}


def assign_era(df, cutover, single_era="all"):
    d = df.copy()
    d["era"] = single_era if cutover is None else np.where(d["created"] >= cutover, "new", "old")
    return d


def schema_changes(df):
    """Per field: % terisi di era lama vs baru dan tiket terakhir yang masih terisi (bukti perubahan skema)."""
    rows = []
    for key, label in SCHEMA_FIELDS:
        if key not in df.columns:
            continue
        has = df[key].notna()
        old, new = df[df["era"].isin(["old", "all"])], df[df["era"] == "new"]
        last = df.loc[has, "created"].max() if has.any() else pd.NaT
        rows.append({"Field": label, "Terisi era lama": round(old[key].notna().mean() * 100, 1) if len(old) else np.nan,
                     "Terisi era baru": round(new[key].notna().mean() * 100, 1) if len(new) else np.nan,
                     "Terakhir terisi (Created On)": last})
    o_, n_ = df[df["era"].isin(["old", "all"])], df[df["era"] == "new"]
    auto_old = o_["is_auto"].mean() * 100 if len(o_) else np.nan
    auto_new = n_["is_auto"].mean() * 100 if len(n_) else np.nan
    last_h = df.loc[~df["is_auto"], "created"].max() if (~df["is_auto"]).any() else pd.NaT
    rows.append({"Field": "Customer = akun sistem (bukan nama orang)", "Terisi era lama": round(auto_old, 1) if pd.notna(auto_old) else np.nan,
                 "Terisi era baru": round(auto_new, 1) if pd.notna(auto_new) else np.nan, "Terakhir terisi (Created On)": last_h})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- statistik
def _q(s, q):
    s = s.dropna()
    return float(s.quantile(q)) if len(s) else np.nan


def era_stats(d, days):
    n = len(d)
    out = {"tickets": n, "days": days, "per_day": n / days if days else np.nan}
    for p in (1, 2, 3):
        c = int((d["priority"] == p).sum())
        out[f"p{p}"] = c
        out[f"p{p}_share"] = c / n * 100 if n else np.nan
    out["auto_n"] = int(d["is_auto"].sum())
    out["auto_share"] = out["auto_n"] / n * 100 if n else np.nan
    out["email_share"] = float((d["source"].astype("string").str.lower() == "email").sum()) / n * 100 if n else np.nan
    resp = d["dur_active"].dropna()
    out.update({"resp_n": len(resp), "resp_median": _q(d["dur_active"], .5), "resp_p90": _q(d["dur_active"], .9),
                "resp_mean": float(resp.mean()) if len(resp) else np.nan, "resp_max": float(resp.max()) if len(resp) else np.nan})
    flag = d["breach_resp"].dropna()
    out["breach_n"] = int((flag > 0).sum()) if len(flag) else None
    out["breach_rate"] = out["breach_n"] / len(flag) * 100 if len(flag) else np.nan
    out["reso_breach_n"] = int((d["breach_reso"].dropna() > 0).sum()) if d["breach_reso"].notna().any() else None
    has_res = d["resolved"].notna()
    out["resolved_n"] = int(has_res.sum())
    out["resolved_cov"] = has_res.mean() * 100 if n else np.nan
    out["resolved_median"] = _q(d["dur_resolved"], .5)
    out["resolved_mean"] = float(d["dur_resolved"].mean()) if d["dur_resolved"].notna().any() else np.nan
    out["closed_no_resolve"] = int((d["closed"].notna() & ~has_res).sum())
    out["closed_median"] = _q((d["closed"] - d["created"]).dt.total_seconds() / 60, .5)
    return out


def _implied_threshold(df):
    """Batas respons yang TERSIRAT dari data (max durasi MET vs min durasi BREACHED). Bukan aturan; hanya pengamatan."""
    ok = df[(df["breach_resp"] == 0) & df["dur_active"].notna()]["dur_active"]
    bad = df[(df["breach_resp"] > 0) & df["dur_active"].notna()]["dur_active"]
    if len(ok) and len(bad) and ok.max() < bad.min():
        return {"max_met": float(ok.max()), "min_breached": float(bad.min()), "consistent": True}
    return {"max_met": float(ok.max()) if len(ok) else np.nan, "min_breached": float(bad.min()) if len(bad) else np.nan, "consistent": False}


def _week_start(s):
    return (s.dt.normalize() - pd.to_timedelta((s.dt.dayofweek + 1) % 7, unit="D"))  # minggu = awal pekan


def _counts(d, col, eras):
    t = d.groupby([col, "era"]).size().unstack("era", fill_value=0)
    for e in eras:
        if e not in t.columns:
            t[e] = 0
    t = t[eras]
    t["Total"] = t.sum(axis=1)
    return t.sort_values("Total", ascending=False)


def analyze(df, cutover="auto", cfg=None, single_era="all"):
    """df = hasil loader.normalize. cutover: 'auto' | Timestamp | None (paksa satu era). Return dict hasil lengkap."""
    cfgm = _cfg(cfg)
    period = detect_period(df)
    notes = []
    inm = (df["created"] >= period["start"]) & (df["created"] < period["end"])
    if (~inm).any():
        notes.append(f"{int((~inm).sum())} tiket berada di luar bulan {fmt.month_name(period['month'])} {period['year']} dan tidak dihitung.")
    df = df[inm].copy()
    det = detect_cutover(df, cfgm)
    cut = det["cutover"] if isinstance(cutover, str) and cutover == "auto" else cutover
    manual = not (isinstance(cutover, str) and cutover == "auto")
    if manual and cut is not None:
        cut = pd.Timestamp(cut)
        if not (df["created"].min() < cut <= df["created"].max()):
            notes.append("Cutover manual di luar rentang tiket; diabaikan (dipakai satu era).")
            cut = None
    df = assign_era(df, cut, single_era)
    eras = ["old", "new"] if cut is not None else [single_era]
    start = max(period["start"], df["created"].min().normalize())
    end = min(period["end"], df["created"].max().normalize() + pd.Timedelta(days=1))
    bounds = {single_era: (start, end)} if cut is None else {"old": (start, cut), "new": (cut, end)}
    stats = {e: era_stats(df[df["era"] == e], max((b - a).total_seconds() / 86400, 1e-9)) for e, (a, b) in bounds.items()}
    total = era_stats(df, max((end - start).total_seconds() / 86400, 1e-9))
    era_table = pd.DataFrame([{"Metrik": lab, **{ERA_LABEL[e]: stats[e].get(k) for e in eras}} for k, lab, _ in ERA_METRICS])

    prio = df.groupby(["priority", "era"]).size().unstack("era", fill_value=0)
    for e in eras:
        if e not in prio.columns:
            prio[e] = 0
    prio = prio[eras]
    prio.index = [cfgm["priority_labels"].get(str(int(i)), f"P{int(i)}") if pd.notna(i) else "Tanpa prioritas" for i in prio.index]
    prio_by_era = prio.copy()
    sla_prio = (df.groupby(["era", "priority"]).agg(Tiket=("ticket", "size"), Median_mnt=("dur_active", "median"), P90_mnt=("dur_active", lambda s: _q(s, .9)),
                                                    Breach=("breach_resp", lambda s: int((s.dropna() > 0).sum()))).reset_index())
    sla_prio["Era"] = sla_prio["era"].map(ERA_LABEL)
    sla_prio["Prioritas"] = sla_prio["priority"].map(lambda p: cfgm["priority_labels"].get(str(int(p)), f"P{int(p)}") if pd.notna(p) else "–")
    sla_prio["% Breach"] = (sla_prio["Breach"] / sla_prio["Tiket"] * 100).round(1)
    sla_prio = sla_prio[["Era", "Prioritas", "Tiket", "Median_mnt", "P90_mnt", "Breach", "% Breach"]]

    breaches = df[df["breach_resp"] > 0].sort_values("dur_active", ascending=False)
    breaches = breaches[["ticket", "created", "priority", "owner", "source", "dur_active", "era"]].rename(columns={
        "ticket": "Ticket", "created": "Created On", "priority": "Priority", "owner": "Owner", "source": "Source", "dur_active": "Menit ke Active", "era": "Era"})
    breaches["Era"] = breaches["Era"].map(ERA_LABEL)

    d2 = df.assign(day=df["created"].dt.normalize())
    daily = d2.groupby(["day", "era"]).size().unstack("era", fill_value=0)
    for e in eras:
        if e not in daily.columns:
            daily[e] = 0
    daily = daily[eras].reindex(pd.date_range(start, end - pd.Timedelta(days=1), freq="D"), fill_value=0)
    daily["Total"] = daily.sum(axis=1)
    for p in (1, 2, 3):
        daily[f"P{p}"] = d2[d2["priority"] == p].groupby("day").size().reindex(daily.index, fill_value=0)
    daily["Breach"] = d2[d2["breach_resp"] > 0].groupby("day").size().reindex(daily.index, fill_value=0)
    daily.index.name = "Tanggal"

    ws = _week_start(df["created"])
    wk = df.assign(week=ws).groupby("week").agg(Tiket=("ticket", "size"), P1=("priority", lambda s: int((s == 1).sum())), P2=("priority", lambda s: int((s == 2).sum())),
                                               P3=("priority", lambda s: int((s == 3).sum())), Breach=("breach_resp", lambda s: int((s.dropna() > 0).sum())),
                                               Otomatis=("is_auto", "sum")).reset_index()
    wk["Pekan (Min–Sab)"] = wk["week"].map(lambda w: f"{w:%d %b} – {w + pd.Timedelta(days=6):%d %b}")
    wk["Ada cutover"] = wk["week"].map(lambda w: cut is not None and w <= cut < w + pd.Timedelta(days=7))
    wk["Otomatis"] = wk["Otomatis"].astype(int)
    weekly = wk[["Pekan (Min–Sab)", "Tiket", "P1", "P2", "P3", "Breach", "Otomatis", "Ada cutover"]]

    hourly = df.groupby([df["created"].dt.hour, "era"]).size().unstack("era", fill_value=0)
    hourly = hourly.reindex(range(24), fill_value=0)
    for e in eras:
        if e not in hourly.columns:
            hourly[e] = 0
    hourly = hourly[eras]
    hourly["Total"] = hourly.sum(axis=1)
    hourly.index.name = "Jam"

    owners = _counts(df.assign(owner=df["owner"].fillna("Unassigned")), "owner", eras)
    sources = _counts(df.assign(source=df["source"].fillna("(kosong)")), "source", eras)
    itype = _counts(df.assign(incident_type=df["incident_type"].fillna("(kosong)")), "incident_type", eras)
    status = _counts(df.assign(status=df["status"].fillna("(kosong)")), "status", eras)
    legacy = df[df["era"].isin(["old", "all"])]  # kategori hanya valid untuk skema lama
    sub_issue = legacy["sub_issue"].fillna("(kosong)").value_counts().rename_axis("Sub_Issue").reset_index(name="Tiket")
    cause = legacy["cause_code"].fillna("(kosong)").value_counts().rename_axis("Cause Code").reset_index(name="Tiket")

    res = {"period": period, "cutover": cut, "cutover_manual": manual, "detection": det, "eras": eras, "stats": stats, "total": total,
           "era_table": era_table, "priority": prio_by_era, "sla_priority": sla_prio, "breaches": breaches, "daily": daily, "weekly": weekly,
           "hourly": hourly, "owners": owners, "sources": sources, "incident_type": itype, "status": status, "sub_issue": sub_issue,
           "cause_code": cause, "schema": schema_changes(df), "single_era": single_era, "threshold": _implied_threshold(df), "notes": notes, "tickets": df,
           "has_contained": False, "maintenance": int((df["maintenance"] > 0).sum())}
    res["insights"] = build_insights(res, cfgm)
    return res


# ---------------------------------------------------------------- insight
def _label(res):
    return f"{fmt.month_name(res['period']['month'])} {res['period']['year']}"


def build_insights(res, cfg):
    """Daftar {level, topic, text}. level: info | watch | limit. Kalimat hedged; tidak menyimpulkan kompromi tanpa bukti."""
    t = cfg["insight_thresholds"]
    S, tot = res["stats"], res["total"]
    ins = []
    two = res["eras"] == ["old", "new"]
    ins.append({"level": "info", "topic": "Volume", "text":
                f"Tercatat {fmt.num(tot['tickets'])} tiket insiden SOC pada {_label(res)} (rata-rata {fmt.num(tot['per_day'], 1)} tiket/hari)."})
    if two:
        o, n = S["old"], S["new"]
        chg = (n["per_day"] - o["per_day"]) / o["per_day"] * 100 if o["per_day"] else np.nan
        ins.append({"level": "info", "topic": "Volume", "text":
                    f"Laju harian {fmt.num(o['per_day'], 1)} tiket/hari (state machine lama) menjadi {fmt.num(n['per_day'], 1)} tiket/hari (baru), "
                    f"{'naik' if chg > 0 else 'turun'} {fmt.pct(abs(chg))}. Perubahan ini belum tentu mencerminkan perubahan ancaman karena cara tiket dibuat ikut berubah."})
        shifts = [f"P{p} {fmt.pct(o[f'p{p}_share'])} → {fmt.pct(n[f'p{p}_share'])}" for p in (1, 2, 3)
                  if abs(n[f"p{p}_share"] - o[f"p{p}_share"]) >= t["share_shift_pp"]]
        if shifts:
            ins.append({"level": "watch", "topic": "Prioritas", "text":
                        f"Komposisi prioritas bergeser tajam ({'; '.join(shifts)}). Pergeseran sebesar ini lebih mungkin terkait perubahan klasifikasi/aturan prioritas pada state machine baru "
                        f"daripada perubahan tingkat risiko; berdasarkan data yang tersedia belum bisa dipastikan, perlu konfirmasi tim Ivanti/SOC."})
        da = n["auto_share"] - o["auto_share"]
        if da >= t["share_shift_pp"]:
            ins.append({"level": "watch", "topic": "Sumber tiket", "text":
                        f"Tiket dengan Customer akun sistem naik dari {fmt.pct(o['auto_share'])} menjadi {fmt.pct(n['auto_share'])}, mengindikasikan pembuatan tiket otomatis dari alert "
                        f"semakin dominan (asumsi: Customer berisi pola {', '.join(cfg['system_customer_patterns'])} = akun sistem)."})
        if o["breach_rate"] == o["breach_rate"] and n["breach_rate"] == n["breach_rate"]:
            ratio_ok = n["breach_rate"] >= max(o["breach_rate"], 0.01) * t["breach_ratio"]
            if ratio_ok and n["breach_rate"] - o["breach_rate"] >= t["breach_min_diff_pp"]:
                ins.append({"level": "watch", "topic": "SLA respons", "text":
                            f"Tiket yang melewati batas respons naik dari {fmt.pct(o['breach_rate'])} ({fmt.num(o['breach_n'])} tiket) menjadi {fmt.pct(n['breach_rate'])} ({fmt.num(n['breach_n'])} tiket)."})
        br = res["breaches"]
        nb = br[br["Era"] == ERA_LABEL["new"]]
        if len(nb):
            w = nb[nb["Created On"] < res["cutover"] + pd.Timedelta(hours=t["cutover_window_hours"])]
            if len(w) / len(nb) >= .3:
                ins.append({"level": "watch", "topic": "SLA respons", "text":
                            f"{fmt.num(len(w))} dari {fmt.num(len(nb))} breach era baru terjadi dalam {t['cutover_window_hours']} jam pertama setelah cutover, pola yang konsisten dengan masa penyesuaian; "
                            f"perlu dipantau apakah menurun pada bulan berikutnya."})
            if nb["Priority"].nunique() == 1:
                ins.append({"level": "info", "topic": "SLA respons", "text":
                            f"Seluruh breach era baru berprioritas P{int(nb['Priority'].iloc[0])}; median keterlambatan {fmt.minutes(nb['Menit ke Active'].median())} (tiket prioritas lebih tinggi tidak terdampak)."})
        dc = o["resolved_cov"] - n["resolved_cov"]
        if dc >= t["coverage_drop_pp"]:
            ins.append({"level": "limit", "topic": "Resolusi", "text":
                        f"Hanya {fmt.pct(n['resolved_cov'])} tiket era baru memiliki waktu Resolved (era lama {fmt.pct(o['resolved_cov'])}); {fmt.num(n['closed_no_resolve'])} tiket langsung Closed tanpa Resolved. "
                        f"Durasi penyelesaian era baru karena itu hanya mewakili sebagian tiket dan tidak sebanding dengan era lama."})
        gone = [r["Field"] for _, r in res["schema"].iterrows() if r["Terisi era lama"] >= 30 and r["Terisi era baru"] <= 5 and "Customer" not in r["Field"]]
        if gone:
            ins.append({"level": "limit", "topic": "Skema data", "text":
                        f"Field {', '.join(gone)} tidak lagi terisi sejak cutover, sehingga analisis kategori insiden (Sub_Issue/Cause Code) hanya valid untuk era lama."})
    else:
        ins.append({"level": "info", "topic": "SLA respons", "text":
                    f"{fmt.num(tot['breach_n'])} tiket ({fmt.pct(tot['breach_rate'])}) melewati batas respons; median waktu ke Active {fmt.minutes(tot['resp_median'])}."})
    ins.append({"level": "limit", "topic": "State machine", "text":
                "MTTC (Active→Contained) tidak dapat dihitung karena data Ivanti belum memiliki timestamp Contained; Created→Resolved yang ada bukan MTRV (Contained→Resolved)."})
    ow = res["owners"]["Total"]
    if len(ow) >= 3 and ow.median() > 0 and ow.max() / ow.median() >= t["owner_ratio"]:
        ins.append({"level": "info", "topic": "Beban kerja", "text":
                    f"Distribusi tiket antar analis tidak merata (tertinggi {ow.index[0]}: {fmt.num(ow.iloc[0])} tiket, median analis {fmt.num(ow.median())}); "
                    f"angka ini mencerminkan jumlah tiket, bukan kualitas kerja."})
    return ins


def executive_headlines(res):
    """3–4 kalimat untuk pembaca level direksi, dari angka yang sama dengan tabel."""
    S, tot = res["stats"], res["total"]
    out = [f"{fmt.num(tot['tickets'])} tiket insiden SOC pada {_label(res)}."]
    if res["eras"] == ["old", "new"]:
        out[0] += f" Tiket P1: {fmt.num(S['old']['p1'])} (era lama) dan {fmt.num(S['new']['p1'])} (era baru) — tidak dijumlahkan karena aturan prioritas berbeda."
    else:
        out[0] += f" Tiket P1: {fmt.num(tot['p1'])} ({fmt.pct(tot['p1_share'])})."
    if res["eras"] == ["old", "new"]:
        c = res["cutover"]
        out.append(f"Perpindahan ke state machine baru terdeteksi pada {c:%d %b %Y %H:%M}; data dilaporkan terpisah per era karena field dan cara pembuatan tiket berbeda.")
    out.append(f"{fmt.num(tot['breach_n'])} tiket ({fmt.pct(tot['breach_rate'])}) melewati batas respons; median waktu ke Active {fmt.minutes(tot['resp_median'])}.")
    out.append("Perbandingan antar era bersifat indikatif: prioritas, kelengkapan resolusi, dan kategori tiket tidak diukur dengan cara yang sama." if len(res["eras"]) == 2
               else f"Seluruh tiket bulan ini dianggap satu era ({ERA_LABEL[res['eras'][0]]}).")
    return out


# ---------------------------------------------------------------- export
def to_excel(res, path):
    """Excel opsional: ringkasan, per era, pekan, harian, SLA, owner, skema, insight, dan tiket ternormalisasi (tanpa email)."""
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        pd.DataFrame([{"Level": i["level"], "Topik": i["topic"], "Insight": i["text"]} for i in res["insights"]]).to_excel(w, sheet_name="Insight", index=False)
        res["era_table"].to_excel(w, sheet_name="Per Era", index=False)
        res["weekly"].to_excel(w, sheet_name="Mingguan", index=False)
        res["daily"].reset_index().to_excel(w, sheet_name="Harian", index=False)
        res["sla_priority"].to_excel(w, sheet_name="SLA per Prioritas", index=False)
        res["breaches"].to_excel(w, sheet_name="Breach Respons", index=False)
        res["owners"].reset_index().to_excel(w, sheet_name="Owner", index=False)
        res["schema"].to_excel(w, sheet_name="Skema", index=False)
        cols = [c for c in res["tickets"].columns if c not in ("is_auto",)]
        res["tickets"][cols].drop(columns=["customer"], errors="ignore").to_excel(w, sheet_name="Tiket", index=False)
    return path
