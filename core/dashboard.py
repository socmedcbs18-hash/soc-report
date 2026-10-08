"""
Dashboard KPI Generator

CATATAN: Modul ini TIDAK dipanggil dari main.py - fungsinya sudah digantikan oleh
SOCProcessor.build_executive_summary() dan build_hypothesis_insight() di processor.py
(sheet "Executive" dan "Hypothesis Insight" di report akhir). Sebelumnya file ini juga
punya bug: mereferensi nama kolom "Alert Count"/"Incident Count"/"Detection Rate" (pakai
spasi) padahal processor.py menghasilkan "Alert_Count"/"Incident_Count"/"Detection_Rate"
(pakai underscore) - sudah diperbaiki di bawah supaya konsisten kalau suatu saat dipakai
lagi (mis. untuk dashboard ringkas di console/CLI).
"""

class DashboardGenerator:

    def __init__(self, report):

        self.report = report

    def generate(self):

        rs = self.report["rule_summary"]

        dashboard = {}

        dashboard["Total Rules"] = len(rs)

        dashboard["Total Alerts"] = rs["Alert_Count"].sum()

        dashboard["Total Incidents"] = rs["Incident_Count"].sum()

        dashboard["Noise Rules"] = len(self.report["noise"])

        dashboard["Dormant Rules"] = len(self.report["dormant"])

        dashboard["Top Detection Rate"] = round(
            rs["Detection_Rate"].max(), 2
        )

        return dashboard