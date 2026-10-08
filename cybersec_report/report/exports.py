"""Output file: Summary xlsx, IOC xlsx, Validation xlsx (audit json ditulis oleh AuditLog)."""
import pandas as pd


def _write(path, sheets):
    with pd.ExcelWriter(path, engine="xlsxwriter") as xw:
        for name, df in sheets.items():
            df.to_excel(xw, sheet_name=name[:31], index=False)
            ws = xw.sheets[name[:31]]
            for i, col in enumerate(df.columns):
                width = max([len(str(col))] + [len(str(v)) for v in df[col].head(200)]) + 2
                ws.set_column(i, i, min(width, 60))


def write_summary_xlsx(path, sections, period, recon, mom_by_section, profile_by_section):
    kpi, sev, atk, dst, cty, cat, src, mom = [], [], [], [], [], [], [], []
    for a in sections:
        n = a["name"]
        kpi.append({"Section": n, "Period": f"{period['month_name']} {period['report_year']}", "Filter": a["filter"],
                    "Raw records in file": a["reconciliation"]["raw_records_in_file"], "Records in scope": a["records_in_scope"],
                    "Aggregated events (SUM count)": a["total_events"], "Unique source IP": a["unique"]["source_ip"],
                    "Unique destination": a["unique"]["destination"], "Unique attack": a["unique"]["attack"],
                    "Top-1 source IP": a["concentration"]["top1_source_ip"], "Top-1 source IP share %": round(a["concentration"]["top1_source_ip_pct"], 2)})
        sev.append(a["severity"].assign(Section=n))
        for s, df in a["top_by_severity"].items():
            atk.append(df.rename(columns={"Attack Name": "Attack"}).assign(Section=n, Severity=s))
        dst.append(a["top_destination"].assign(Section=n))
        cty.append(a["top_country"].assign(Section=n))
        cat.append(a["categories"].assign(Section=n))
        src.append(profile_by_section[n].assign(Section=n))
        if mom_by_section.get(n):
            mom.append(pd.DataFrame(mom_by_section[n]).assign(Section=n))
    sheets = {"KPI": pd.DataFrame(kpi), "Severity": pd.concat(sev), "TopAttack_BySeverity": pd.concat(atk) if atk else pd.DataFrame(),
              "Destination": pd.concat(dst), "SourceCountry": pd.concat(cty), "Category": pd.concat(cat),
              "SourceIP_Profile": pd.concat(src), "Reconciliation": pd.DataFrame([recon])}
    if mom:
        sheets["MonthOverMonth"] = pd.concat(mom)
    _write(path, sheets)


def write_ioc_xlsx(path, ioc_df, stats, log):
    st = pd.DataFrame([{"Provider": k, **v} for k, v in (stats or {}).get("providers", {}).items()])
    sheets = {"IOC_Reputation": ioc_df if ioc_df is not None and len(ioc_df) else pd.DataFrame({"Info": ["Reputation check belum dijalankan / tidak ada hasil"]}),
              "Provider_Status": st if len(st) else pd.DataFrame({"Info": ["-"]}),
              "Log": pd.DataFrame({"Log": log or ["-"]})}
    _write(path, sheets)


def write_validation_xlsx(path, validation, cross, ppt, recon):
    def tab(res):
        return pd.DataFrame(res["checks"]).drop(columns=["value"], errors="ignore") if res else pd.DataFrame()
    summary = pd.DataFrame([{"Stage": "Data quality", "Status": validation["overall"]},
                            {"Stage": "Cross validation", "Status": cross["overall"] if cross else "-"},
                            {"Stage": "PPT vs analytics", "Status": ppt["overall"] if ppt else "-"},
                            {"Stage": "Raw == Analytics == PPT", "Status": "PASS" if recon and recon["match"] else "FAIL"}])
    _write(path, {"Summary": summary, "Data_Quality": tab(validation), "Cross_Validation": tab(cross),
                  "PPT_Verification": tab(ppt), "Reconciliation": pd.DataFrame([recon]) if recon else pd.DataFrame()})
