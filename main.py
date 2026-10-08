from core.loader import load_data
from core.normalizer import RuleNormalizer
from core.validator import Validator
from core.processor import SOCProcessor
from core.excel_writer import ExcelWriter
from core.pptx_writer import PPTXWriter


def main():

    print("=" * 70)
    print("SOC REPORT GENERATOR")
    print("=" * 70)

    # =====================================================
    # PILIH MODE
    # =====================================================

    mode = input("\nPilih mode [1] Weekly  [2] Monthly (default 1): ").strip()
    mode = "monthly" if mode == "2" else "weekly"

    year, month = None, None
    if mode == "monthly":
        year = int(input("Tahun (contoh 2026): ").strip())
        month = int(input("Bulan (1-12): ").strip())

    # =====================================================
    # LOAD DATA
    # =====================================================

    data = load_data(mode=mode, year=year, month=month)

    # =====================================================
    # NORMALIZE
    # =====================================================

    normalizer = RuleNormalizer(data)
    data = normalizer.run()

    # =====================================================
    # VALIDATION
    # =====================================================

    validator = Validator(data)
    data = validator.run()

    # =====================================================
    # PROCESS REPORT
    # =====================================================

    processor = SOCProcessor(data)
    report = processor.run()

    # =====================================================
    # TAMBAHKAN HASIL VALIDATION KE REPORT
    # =====================================================

    report["validation_summary"] = data["validation_summary"]

    report["mapping_quality"] = data["mapping_quality"]

    report["alert_incident_compare"] = data["alert_incident_compare"]

    report["unknown_rule"] = data["unknown_rule"]

    report["missing_priority"] = data["missing_priority"]

    report["missing_owner"] = data["missing_owner"]

    report["missing_severity"] = data["missing_severity"]

    report["duplicate_master"] = data["duplicate_master"]

    # =====================================================
    # EXPORT EXCEL
    # =====================================================

    writer = ExcelWriter(
        report=report,
        week=data["week"]
    )

    output_file = writer.export()

    # =====================================================
    # EXPORT PPTX (chart-heavy, konsumsi data yang sama dengan Excel)
    # =====================================================

    pptx_writer = PPTXWriter(report=report, period_label=data["week"])
    pptx_file = pptx_writer.export()

    # =====================================================
    # FINISH
    # =====================================================

    print()
    print("=" * 70)
    print("PROCESS SUCCESS")
    print("=" * 70)

    print(f"\nOutput Excel File : {output_file}")
    print(f"Output PPTX File  : {pptx_file}")

    print("\nGenerated Sheets:")

    for sheet in report.keys():
        print(f"  - {sheet}")

    print()


if __name__ == "__main__":
    main()