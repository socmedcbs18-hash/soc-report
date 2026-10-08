"""
=========================================================
SOC Report Generator - PPTX Writer
=========================================================
PRINSIP UTAMA: modul ini TIDAK menghitung ulang apapun. Semua angka & chart
di sini diambil langsung dari `report` dict yang sama persis yang dipakai
ExcelWriter dan app.py (hasil SOCProcessor.run()). Ini menjamin angka di
PPT, Excel, dan Streamlit SELALU konsisten.

Struktur mengikuti 8 bab yang sama dengan Streamlit:
1. Master Rules Database
2. Splunk vs Ivanti (+ deep-dive Top 10 Rule)
3. Non-Splunk vs Ivanti
4. Task dari Tim Lain
5. Tren Alert
6. Efektivitas & Severity
7. Temuan Berulang (auto-skip kalau kosong)
8. KPI SOC per Analyst (tabel lengkap semua analyst)
=========================================================
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION
from pptx.enum.text import PP_ALIGN
from pathlib import Path

NAVY = RGBColor(0x1F, 0x4E, 0x78)
LIGHT_BLUE = RGBColor(0xDC, 0xE6, 0xF1)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
DARK_TEXT = RGBColor(0x33, 0x33, 0x33)
RED = RGBColor(0xC0, 0x00, 0x00)
GREEN = RGBColor(0x2E, 0x7D, 0x32)
HEADER_FILL = RGBColor(0x1F, 0x4E, 0x78)

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)


class PPTXWriter:

    def __init__(self, report, period_label):
        self.report = report
        self.period = period_label
        self.prs = Presentation()
        self.prs.slide_width = SLIDE_W
        self.prs.slide_height = SLIDE_H
        self.blank_layout = self.prs.slide_layouts[6]

    # =====================================================
    # Helpers
    # =====================================================

    def _new_slide(self):
        return self.prs.slides.add_slide(self.blank_layout)

    def _add_title_bar(self, slide, title, subtitle=None):
        bar = slide.shapes.add_shape(1, 0, 0, SLIDE_W, Inches(1.0))
        bar.fill.solid()
        bar.fill.fore_color.rgb = NAVY
        bar.line.fill.background()
        tb = bar.text_frame
        tb.margin_left = Inches(0.4)
        tb.margin_top = Inches(0.12)
        p = tb.paragraphs[0]
        p.text = title
        p.font.size = Pt(26)
        p.font.bold = True
        p.font.color.rgb = WHITE
        if subtitle:
            p2 = tb.add_paragraph()
            p2.text = subtitle
            p2.font.size = Pt(13)
            p2.font.color.rgb = LIGHT_BLUE

    def _section_divider(self, number, title):
        slide = self._new_slide()
        bg = slide.shapes.add_shape(1, 0, 0, SLIDE_W, SLIDE_H)
        bg.fill.solid()
        bg.fill.fore_color.rgb = NAVY
        bg.line.fill.background()
        self._add_textbox(slide, Inches(0.8), Inches(3.0), Inches(3), Inches(1.5),
                           [str(number)], size=60, bold=True, color=LIGHT_BLUE)
        self._add_textbox(slide, Inches(0.8), Inches(3.9), Inches(11.7), Inches(1.2),
                           [title], size=32, bold=True, color=WHITE)

    def _add_textbox(self, slide, left, top, width, height, lines, size=14, bold=False, color=DARK_TEXT, align=PP_ALIGN.LEFT):
        box = slide.shapes.add_textbox(left, top, width, height)
        tf = box.text_frame
        tf.word_wrap = True
        for i, line in enumerate(lines):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            p.text = line
            p.font.size = Pt(size)
            p.font.bold = bold
            p.font.color.rgb = color
            p.alignment = align
        return box

    def _style_chart(self, chart, show_legend=False):
        chart.has_legend = show_legend
        if show_legend:
            chart.legend.position = XL_LEGEND_POSITION.BOTTOM
            chart.legend.include_in_layout = False
        try:
            plot = chart.plots[0]
            plot.has_data_labels = True
            plot.data_labels.font.size = Pt(11)
        except Exception:
            pass

    def _slide_bar_chart(self, title, subtitle, categories, series_dict, chart_type=XL_CHART_TYPE.COLUMN_CLUSTERED,
                          x=Inches(0.6), y=Inches(1.3), cx=Inches(12.1), cy=Inches(5.8)):
        slide = self._new_slide()
        self._add_title_bar(slide, title, subtitle)
        chart_data = CategoryChartData()
        chart_data.categories = categories
        for name, values in series_dict.items():
            chart_data.add_series(name, values)
        gframe = slide.shapes.add_chart(chart_type, x, y, cx, cy, chart_data)
        self._style_chart(gframe.chart, show_legend=len(series_dict) > 1)
        return slide

    def _add_table(self, slide, df, left, top, width, height, max_rows=15):
        df = df.head(max_rows)
        rows, cols = len(df) + 1, len(df.columns)
        shape = slide.shapes.add_table(rows, cols, left, top, width, height)
        table = shape.table
        for j, col in enumerate(df.columns):
            cell = table.cell(0, j)
            cell.text = str(col)
            cell.fill.solid()
            cell.fill.fore_color.rgb = HEADER_FILL
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(11)
            p.font.bold = True
            p.font.color.rgb = WHITE
        for i, (_, row) in enumerate(df.iterrows(), start=1):
            for j, val in enumerate(row):
                cell = table.cell(i, j)
                cell.text = str(val)
                p = cell.text_frame.paragraphs[0]
                p.font.size = Pt(10)
                p.font.color.rgb = DARK_TEXT
        return table

    def _insight_box(self, slide, text, top=Inches(6.3)):
        box = slide.shapes.add_shape(1, Inches(0.6), top, Inches(12.1), Inches(1.0))
        box.fill.solid()
        box.fill.fore_color.rgb = LIGHT_BLUE
        box.line.fill.background()
        tf = box.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.15)
        tf.margin_top = Inches(0.08)
        p = tf.paragraphs[0]
        p.text = text
        p.font.size = Pt(11)
        p.font.color.rgb = NAVY

    def _get_insight(self, keyword):
        hyp = self.report["hypothesis_insight"]
        match = hyp[hyp["Hipotesis"].str.contains(keyword, na=False)]
        return match.iloc[0]["Temuan"] if len(match) > 0 else None

    # =====================================================
    # Cover
    # =====================================================

    def slide_cover(self):
        slide = self._new_slide()
        bg = slide.shapes.add_shape(1, 0, 0, SLIDE_W, SLIDE_H)
        bg.fill.solid()
        bg.fill.fore_color.rgb = NAVY
        bg.line.fill.background()
        self._add_textbox(slide, Inches(0.8), Inches(2.7), Inches(11.7), Inches(1.2),
                           ["CSOC Report"], size=44, bold=True, color=WHITE)
        self._add_textbox(slide, Inches(0.8), Inches(3.7), Inches(11.7), Inches(0.6),
                           [f"Periode: {self.period}"], size=20, color=LIGHT_BLUE)

    # =====================================================
    # Executive Summary
    # =====================================================

    def slide_executive_summary(self):
        exec_df = self.report["executive"]
        slide = self._new_slide()
        self._add_title_bar(slide, "Executive Summary", self.period)

        groups = [g for g in exec_df["Group"].unique() if g != "Periode"]
        col_w = Inches(12.4) / max(len(groups), 1)
        left = Inches(0.45)
        top = Inches(1.25)

        for g in groups:
            sub = exec_df[exec_df["Group"] == g]
            box = slide.shapes.add_shape(1, left, top, col_w - Inches(0.15), Inches(5.8))
            box.fill.solid()
            box.fill.fore_color.rgb = LIGHT_BLUE
            box.line.color.rgb = NAVY
            tf = box.text_frame
            tf.word_wrap = True
            tf.margin_left = Inches(0.15)
            tf.margin_top = Inches(0.15)
            p0 = tf.paragraphs[0]
            p0.text = g.split(". ", 1)[-1]
            p0.font.bold = True
            p0.font.size = Pt(14)
            p0.font.color.rgb = NAVY
            for _, row in sub.iterrows():
                p = tf.add_paragraph()
                p.text = str(row["Metric"])
                p.font.size = Pt(10)
                p.font.color.rgb = DARK_TEXT
                p.space_before = Pt(6)
                pv = tf.add_paragraph()
                pv.text = str(row["Value"])
                pv.font.size = Pt(17)
                pv.font.bold = True
                pv.font.color.rgb = NAVY
            left += col_w

    # =====================================================
    # Key Findings
    # =====================================================

    def slide_key_findings(self):
        hyp = self.report["hypothesis_insight"]
        slide = self._new_slide()
        self._add_title_bar(slide, "Key Findings", self.period)
        box = slide.shapes.add_textbox(Inches(0.6), Inches(1.25), Inches(12.1), Inches(6.0))
        tf = box.text_frame
        tf.word_wrap = True
        first = True
        for _, row in hyp.head(6).iterrows():
            p = tf.paragraphs[0] if first else tf.add_paragraph()
            first = False
            p.text = f"\u2022 {row['Hipotesis']}"
            p.font.bold = True
            p.font.size = Pt(13)
            p.font.color.rgb = NAVY if not str(row["Hipotesis"]).startswith("PERINGATAN") else RED
            p.space_before = Pt(8)
            p2 = tf.add_paragraph()
            p2.text = str(row["Temuan"])
            p2.font.size = Pt(11)
            p2.font.color.rgb = DARK_TEXT
            p2.space_after = Pt(4)

    # =====================================================
    # BAB 1: Master Rules Database
    # =====================================================

    # =====================================================
    # BAB 1: Splunk vs Ivanti (termasuk ringkasan Master Rules)
    # =====================================================

    def chapter_1_splunk_ivanti(self):
        self._section_divider(1, "Splunk vs Ivanti")

        # Slide definisi status rule
        slide_def = self._new_slide()
        self._add_title_bar(slide_def, "Definisi Status Rule", self.period)
        box = slide_def.shapes.add_textbox(Inches(0.6), Inches(1.3), Inches(12.1), Inches(5.0))
        tf = box.text_frame
        tf.word_wrap = True
        defs = [
            ("Noise", "alert banyak (>=20) tapi 0 insiden - kemungkinan besar false positive berulang."),
            ("Critical/Need Tuning, Review", "detection rate rendah - sebagian kecil alert jadi insiden nyata."),
            ("Acceptable", "detection rate 10-25% - cukup, belum optimal tapi tidak mendesak."),
            ("Healthy", "detection rate >=25% - baik."),
            ("Dormant", "terdaftar tapi 0 alert sama sekali periode ini."),
        ]
        first = True
        for label, desc in defs:
            p = tf.paragraphs[0] if first else tf.add_paragraph()
            first = False
            p.text = label
            p.font.bold = True
            p.font.size = Pt(13)
            p.font.color.rgb = NAVY
            p.space_before = Pt(8)
            p2 = tf.add_paragraph()
            p2.text = desc
            p2.font.size = Pt(11)
            p2.font.color.rgb = DARK_TEXT

        rrd = self.report.get("rule_recommendation_distribution")
        if rrd is not None and len(rrd) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Distribusi Status Rule (%)", self.period)
            chart_data = CategoryChartData()
            chart_data.categories = rrd["Recommendation"].tolist()
            chart_data.add_series("%", rrd["%"].tolist())
            gframe = slide.shapes.add_chart(XL_CHART_TYPE.PIE, Inches(2.5), Inches(1.3), Inches(8.3), Inches(5.0), chart_data)
            self._style_chart(gframe.chart, show_legend=True)

        top = self.report["top_rule"].head(10)
        if len(top) > 0:
            slide = self._slide_bar_chart(
                "Top 10 Rule - Alert vs Incident", self.period,
                [str(n)[:40] for n in top["Rule_Names"]],
                {"Alert_Count": top["Alert_Count"].tolist(), "Incident_Count": top["Incident_Count"].tolist()},
                cy=Inches(5.0)
            )
            ins = self._get_insight("H1")
            if ins:
                self._insight_box(slide, ins, top=Inches(6.5))

        dom = self.report["domain"]
        if len(dom) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Distribusi Security Domain", self.period)
            chart_data = CategoryChartData()
            chart_data.categories = dom["Security_Domain"].tolist()
            chart_data.add_series("Incident", dom["Incident"].tolist())
            gframe = slide.shapes.add_chart(XL_CHART_TYPE.PIE, Inches(2.5), Inches(1.3), Inches(8.3), Inches(5.0), chart_data)
            self._style_chart(gframe.chart, show_legend=True)

        # Deep-dive teks per rule - Top 10 KONSISTEN dengan chart di atas,
        # dipecah 2 slide (5 rule/slide) supaya tetap terbaca.
        if len(top) > 0:
            def rec_action(rec, dr):
                if rec == "Noise":
                    return "banyak alert tapi 0 insiden - evaluasi threshold/exclusion."
                elif rec in ["Critical Tuning", "Need Tuning", "Review"]:
                    return f"detection rate rendah ({dr}%) - perlu penyesuaian sensitivitas."
                elif rec == "Dormant":
                    return "tidak trigger - cek relevansi / kemungkinan blind spot."
                elif rec == "Acceptable":
                    return f"detection rate {dr}% - di atas ambang minimal, tapi belum tinggi. Pantau saja."
                elif rec == "Healthy":
                    return f"detection rate {dr}% - baik, pertahankan konfigurasi."
                return "di luar Master Rules - perlu direview."

            chunks = [top.iloc[0:5], top.iloc[5:10]]
            for idx, chunk in enumerate(chunks):
                if len(chunk) == 0:
                    continue
                slide = self._new_slide()
                self._add_title_bar(
                    slide,
                    f"Deep-dive: Dampak & Rekomendasi per Rule (Top {idx*5+1}-{idx*5+len(chunk)} dari 10)",
                    self.period
                )
                box = slide.shapes.add_textbox(Inches(0.6), Inches(1.2), Inches(12.1), Inches(6.0))
                tf = box.text_frame
                tf.word_wrap = True
                first = True
                for _, row in chunk.iterrows():
                    rec, dr = row["Recommendation"], row["Detection_Rate"]
                    p = tf.paragraphs[0] if first else tf.add_paragraph()
                    first = False
                    p.text = str(row["Rule_Names"])[:80]
                    p.font.bold = True
                    p.font.size = Pt(12)
                    p.font.color.rgb = NAVY
                    p.space_before = Pt(8)
                    p2 = tf.add_paragraph()
                    p2.text = (f"{row['Alert_Count']} alert, {row['Incident_Count']} insiden, "
                               f"Detection Rate {dr}%. Status {rec} - {rec_action(rec, dr)}")
                    p2.font.size = Pt(10)
                    p2.font.color.rgb = DARK_TEXT

        # Ringkasan Master Rules (digabung dari bab terpisah sebelumnya)
        msd = self.report.get("master_status_distribution")
        if msd is not None and len(msd) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Distribusi Status Rule Master (Enabled/Disabled/Unmapped)", self.period)
            chart_data = CategoryChartData()
            chart_data.categories = msd["Status"].tolist()
            chart_data.add_series("%", msd["%"].tolist())
            gframe = slide.shapes.add_chart(XL_CHART_TYPE.PIE, Inches(2.5), Inches(1.3), Inches(8.3), Inches(5.0), chart_data)
            self._style_chart(gframe.chart, show_legend=True)
        um = self.report.get("unmapped")
        if um is not None and len(um) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Rule Belum Ter-mapping (= tidak ditemukan di Master Rules)", self.period)
            self._add_table(slide, um, Inches(0.6), Inches(1.3), Inches(12.1), Inches(4.8))
            ins = self._get_insight("H4")
            if ins:
                self._insight_box(slide, ins)

    # =====================================================
    # BAB 2: Non-Splunk vs Ivanti
    # =====================================================

    def chapter_2_nonsplunk(self):
        cov = self.report.get("nonsplunk_coverage")
        if cov is None or len(cov) == 0:
            return
        self._section_divider(2, "Non-Splunk vs Ivanti")
        slide = self._slide_bar_chart(
            "Coverage Alert Non-Splunk per Device (%)", self.period,
            cov["Source_Device"].tolist(), {"Coverage_%": cov["Coverage_%"].tolist()}, cy=Inches(5.0)
        )
        ins = self._get_insight("H2")
        if ins:
            self._insight_box(slide, ins, top=Inches(6.5))

    # =====================================================
    # BAB 4: Task dari Tim Lain
    # =====================================================

    def chapter_3_task(self):
        task_owner = self.report.get("task_by_owner")
        if task_owner is None or len(task_owner) == 0:
            return
        self._section_divider(3, "Task dari Tim Lain")
        slide = self._slide_bar_chart(
            "Task per Analyst", self.period,
            task_owner["Owner"].tolist(), {"Total_Task": task_owner["Total_Task"].tolist()}, cy=Inches(5.0)
        )
        ins = self._get_insight("H-TaskWorkload")
        if ins:
            self._insight_box(slide, ins, top=Inches(6.5))

    # =====================================================
    # BAB 5: Tren Alert
    # =====================================================

    def chapter_4_trend(self):
        trend = self.report.get("daily_trend")
        weekly = self.report.get("weekly_trend")
        is_long = self.report.get("is_long_period", False)
        if trend is None or len(trend) == 0:
            return
        self._section_divider(4, "Tren Alert")

        use_weekly = is_long and weekly is not None and len(weekly) > 0
        chart_df = weekly if use_weekly else trend
        cat_col = "Minggu" if use_weekly else "Tanggal"
        label = "Mingguan" if use_weekly else "Harian"

        slide = self._new_slide()
        self._add_title_bar(slide, f"Tren {label}: Alert Splunk vs Insiden Ivanti", self.period)
        note = slide.shapes.add_textbox(Inches(0.6), Inches(1.05), Inches(12.1), Inches(0.4))
        p = note.text_frame.paragraphs[0]
        p.text = "Cakupan: Alert Splunk + Insiden Ivanti dari Splunk saja - TIDAK termasuk alert non-Splunk (lihat Bab 3)."
        p.font.size = Pt(10)
        p.font.italic = True
        p.font.color.rgb = DARK_TEXT

        chart_data1 = CategoryChartData()
        chart_data1.categories = [str(d) for d in chart_df[cat_col]]
        chart_data1.add_series("Jumlah_Alert", chart_df["Jumlah_Alert"].tolist())
        g1 = slide.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(0.4), Inches(1.5), Inches(6.1), Inches(4.8), chart_data1)
        self._style_chart(g1.chart, show_legend=False)

        chart_data2 = CategoryChartData()
        chart_data2.categories = [str(d) for d in chart_df[cat_col]]
        chart_data2.add_series("Jumlah_Insiden", chart_df["Jumlah_Insiden"].tolist())
        g2 = slide.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(6.7), Inches(1.5), Inches(6.1), Inches(4.8), chart_data2)
        self._style_chart(g2.chart, show_legend=False)

        ins = self._get_insight("H-DailyTrend")
        if ins:
            self._insight_box(slide, ins, top=Inches(6.5))

        th = self.report.get("time_by_hour")
        if th is not None and len(th) > 0:
            slide2 = self._slide_bar_chart(
                "Distribusi Alert per Jam (total seluruh periode, bukan rata-rata)", self.period,
                [f"{h:02d}:00" for h in th["Jam"]], {"Jumlah_Alert": th["Jumlah_Alert"].tolist()}, cy=Inches(5.0)
            )
            ins2 = self._get_insight("H-TimePattern")
            if ins2:
                self._insight_box(slide2, ins2, top=Inches(6.5))

    # =====================================================
    # BAB 6: Efektivitas & Severity
    # =====================================================

    def chapter_5_efektivitas(self):
        sev = self.report.get("severity_breakdown")
        cc = self.report.get("cause_code_breakdown")
        if (sev is None or len(sev) == 0) and (cc is None or len(cc) == 0):
            return
        self._section_divider(5, "Efektivitas & Severity")

        sev_trend = self.report.get("severity_trend")
        if sev_trend is not None and len(sev_trend) >= 2:
            slide_t = self._new_slide()
            self._add_title_bar(slide_t, "Tren Severity Lintas Periode", self.period)
            sev_cols = [c for c in ["Critical", "High", "Medium", "Low"] if c in sev_trend.columns]
            if sev_cols:
                chart_data = CategoryChartData()
                chart_data.categories = sev_trend["Period"].astype(str).tolist()
                for col in sev_cols:
                    chart_data.add_series(col, sev_trend[col].tolist())
                gframe = slide_t.shapes.add_chart(XL_CHART_TYPE.LINE_MARKERS, Inches(0.6), Inches(1.3), Inches(12.1), Inches(5.0), chart_data)
                self._style_chart(gframe.chart, show_legend=True)
            ins = self._get_insight("H-SeverityTrend")
            if ins:
                self._insight_box(slide_t, ins, top=Inches(6.5))

        # Slide definisi - supaya "Prevented"/"Breach - Reported" tidak ambigu
        slide_def = self._new_slide()
        self._add_title_bar(slide_def, "Definisi Cause Code", self.period)
        box = slide_def.shapes.add_textbox(Inches(0.6), Inches(1.3), Inches(12.1), Inches(5.0))
        tf = box.text_frame
        tf.word_wrap = True
        tf.paragraphs[0].text = (
            "Field ini diisi MANUAL oleh analyst saat menutup tiket - bukan otomatis dari sistem. "
            "Definisi berikut disimpulkan dari nama field & pola data, PERLU DIKONFIRMASI ke tim "
            "yang menentukan kriteria field ini di organisasi Anda:"
        )
        tf.paragraphs[0].font.size = Pt(13)
        tf.paragraphs[0].font.color.rgb = DARK_TEXT
        for label, desc in [
            ("Prevented", "kontrol keamanan berhasil mencegah/memblokir ancaman sebelum berdampak."),
            ("Breach - Reported", "ancaman BENAR-BENAR berhasil menembus (ada bukti akses tidak sah/"
             "kompromi), dilaporkan sebagai breach resmi."),
            ("Belum Diklasifikasi", "field Cause Code masih kosong - belum diinvestigasi tuntas."),
        ]:
            p = tf.add_paragraph()
            p.text = label
            p.font.bold = True
            p.font.size = Pt(13)
            p.font.color.rgb = NAVY
            p.space_before = Pt(10)
            p2 = tf.add_paragraph()
            p2.text = desc
            p2.font.size = Pt(11)
            p2.font.color.rgb = DARK_TEXT

        if sev is not None and len(sev) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Distribusi Tiket per Severity", self.period)
            chart_data = CategoryChartData()
            chart_data.categories = sev["Severity_Label"].astype(str).tolist()
            chart_data.add_series("Jumlah Tiket", sev["Jumlah_Tiket"].tolist())
            gframe = slide.shapes.add_chart(XL_CHART_TYPE.PIE, Inches(2.5), Inches(1.3), Inches(8.3), Inches(5.0), chart_data)
            self._style_chart(gframe.chart, show_legend=True)

        if cc is not None and len(cc) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Cause Code Breakdown (= Total Tiket)", self.period)
            chart_data = CategoryChartData()
            chart_data.categories = cc["Cause_Code"].astype(str).tolist()
            chart_data.add_series("Jumlah Tiket", cc["Jumlah_Tiket"].tolist())
            gframe = slide.shapes.add_chart(XL_CHART_TYPE.PIE, Inches(2.5), Inches(1.3), Inches(8.3), Inches(5.0), chart_data)
            self._style_chart(gframe.chart, show_legend=True)
            ins = self._get_insight("H-Outcome")
            if ins:
                self._insight_box(slide, ins, top=Inches(6.5))

        mismatch_rule = self.report.get("mismatch_under_by_rule")
        if mismatch_rule is not None and len(mismatch_rule) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Root-cause: Rule Paling Sering Under-Prioritized", self.period)
            self._add_table(slide, mismatch_rule, Inches(0.6), Inches(1.3), Inches(12.1), Inches(4.8))
            ins = self._get_insight("H-Mismatch")
            if ins:
                self._insight_box(slide, ins)

        rcs = self.report.get("resolved_closed_stats")
        if rcs is not None and len(rcs) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Resolved -> Closed: Timeline & Potensi Tanpa Review", self.period)
            self._add_table(slide, rcs, Inches(0.6), Inches(1.3), Inches(9.0), Inches(3.5))
            ins = self._get_insight("H-ResolvedClosed")
            if ins:
                self._insight_box(slide, ins, top=Inches(5.2))

        lll = self.report.get("lesson_learned_log")
        if lll is not None and len(lll) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Lesson Learned Log (dari modul Task)", self.period)
            note = slide.shapes.add_textbox(Inches(0.6), Inches(1.05), Inches(12.1), Inches(0.4))
            p = note.text_frame.paragraphs[0]
            p.text = "Dari modul Task, BUKAN Incident - export Incident Ivanti tidak punya kolom catatan/resolusi bebas."
            p.font.size = Pt(10)
            p.font.italic = True
            p.font.color.rgb = DARK_TEXT
            self._add_table(slide, lll, Inches(0.6), Inches(1.6), Inches(12.1), Inches(5.2), max_rows=10)

    # =====================================================
    # BAB 7: Temuan Berulang (auto-skip kalau kosong)
    # =====================================================

    def chapter_6_recurring(self):
        rf = self.report.get("recurring_findings")
        if rf is None or len(rf) == 0:
            return
        self._section_divider(6, "Temuan Berulang")
        slide = self._new_slide()
        self._add_title_bar(slide, "Rule Berulang Jadi Noise/Tuning", self.period)
        self._add_table(slide, rf, Inches(0.6), Inches(1.3), Inches(12.1), Inches(5.5))

    # =====================================================
    # BAB 8: KPI SOC per Analyst (paling akhir, tabel LENGKAP)
    # =====================================================

    # =====================================================
    # BAB 8: Threat Profiling & Attack Surface (BARU)
    # =====================================================

    def chapter_8_threat_profiling(self):
        tbp = self.report.get("threat_by_priority")
        if tbp is None or len(tbp) == 0:
            return
        self._section_divider(8, "Threat Profiling & Attack Surface")

        slide = self._new_slide()
        self._add_title_bar(slide, "Top Threat per Priority Tier", self.period)
        note = slide.shapes.add_textbox(Inches(0.6), Inches(1.05), Inches(12.1), Inches(0.4))
        p = note.text_frame.paragraphs[0]
        p.text = "'Asset'/'target' = proxy (Security_Domain & Customer) - bukan data inventaris aset sungguhan."
        p.font.size = Pt(10)
        p.font.italic = True
        p.font.color.rgb = DARK_TEXT
        self._add_table(slide, tbp, Inches(0.6), Inches(1.5), Inches(12.1), Inches(4.8), max_rows=15)
        ins = self._get_insight("H-Threat")
        if ins:
            self._insight_box(slide, ins, top=Inches(6.5))

        ppr = self.report.get("priority_per_rule")
        if ppr is not None and len(ppr) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Priority Insiden per Rule Splunk", self.period)
            self._add_table(slide, ppr, Inches(0.6), Inches(1.3), Inches(12.1), Inches(5.5), max_rows=15)

        ast = self.report.get("attack_surface_trend")
        if ast is not None and len(ast) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Tren Domain Lintas Periode (Attack Surface)", self.period)
            self._add_table(slide, ast, Inches(0.6), Inches(1.3), Inches(12.1), Inches(4.8))
            ins = self._get_insight("H-AttackSurface")
            if ins:
                self._insight_box(slide, ins)

        at = self.report.get("action_tracker")
        if at is not None and len(at) > 0:
            slide = self._new_slide()
            self._add_title_bar(slide, "Action Tracker - Tracking Improvement", self.period)
            note = slide.shapes.add_textbox(Inches(0.6), Inches(1.05), Inches(12.1), Inches(0.4))
            p = note.text_frame.paragraphs[0]
            p.text = "Status: Masih Terbuka = masih bermasalah periode ini. Sudah Membaik = dulu bermasalah, sekarang tidak lagi."
            p.font.size = Pt(10)
            p.font.italic = True
            p.font.color.rgb = DARK_TEXT
            self._add_table(slide, at, Inches(0.6), Inches(1.6), Inches(12.1), Inches(5.2), max_rows=15)
            ins = self._get_insight("H-ActionTracker")
            if ins:
                self._insight_box(slide, ins, top=Inches(6.8))

    def chapter_7_kpi_soc(self):
        kpi = self.report.get("soc_individual_kpi")
        if kpi is None or len(kpi) == 0:
            return
        self._section_divider(7, "KPI SOC per Analyst")

        slide = self._slide_bar_chart(
            "Total Workload per Analyst (Insiden + Task)", self.period,
            kpi["Owner"].tolist(), {"Total_Workload": kpi["Total_Workload (Insiden+Task)"].tolist()}, cy=Inches(5.0)
        )

        # Tabel LENGKAP semua nama analyst + MTTR + breach rate + jumlah tiket breach
        slide2 = self._new_slide()
        self._add_title_bar(slide2, "Seluruh Analyst SOC - MTTR, Breach Rate, Tiket Breach", self.period)
        note = slide2.shapes.add_textbox(Inches(0.6), Inches(1.05), Inches(12.1), Inches(0.4))
        p = note.text_frame.paragraphs[0]
        p.text = "MTTR = Created On -> Responded On (waktu respons PERTAMA, bukan waktu penyelesaian)."
        p.font.size = Pt(10)
        p.font.italic = True
        p.font.color.rgb = DARK_TEXT
        kpi_table = kpi[["Owner", "Total_Incident", "Avg_MTTR_sec", "Breach", "Breach_Rate_%"]].rename(
            columns={"Breach": "Jumlah_Tiket_Breach", "Avg_MTTR_sec": "MTTR (detik)"}
        )
        self._add_table(slide2, kpi_table, Inches(0.6), Inches(1.6), Inches(12.1), Inches(5.2), max_rows=20)

    # =====================================================
    # Export
    # =====================================================

    def export(self, output_dir="output"):
        self.slide_cover()
        self.slide_executive_summary()
        self.slide_key_findings()
        self.chapter_1_splunk_ivanti()
        self.chapter_2_nonsplunk()
        self.chapter_3_task()
        self.chapter_4_trend()
        self.chapter_5_efektivitas()
        self.chapter_6_recurring()
        self.chapter_8_threat_profiling()
        self.chapter_7_kpi_soc()

        out_dir = Path(output_dir)
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"SOC_Report_{self.period}.pptx"

        try:
            self.prs.save(str(out_path))
        except PermissionError:
            import time
            alt_path = out_dir / f"SOC_Report_{self.period}_{int(time.time())}.pptx"
            print(f"   [WARNING] {out_path} terkunci - menulis ke {alt_path} sebagai gantinya.")
            self.prs.save(str(alt_path))
            out_path = alt_path

        print(f"\nPPTX Report Saved : {out_path}")
        return str(out_path)
