"""
SOC Report Constants
"""

REMOVE_PREFIX = [
    # Category label yang selalu diikuti " - " sebelum nama rule.
    # Daftar ini divalidasi langsung dari kolom "Alert Name"/"Summary" (week 27-29).
    "Splunk Alert:",
    "Threat -",
    "Access -",
    "Identity -",
    "Security -",
    "Monitoring -",
    "Audit -",
    "Endpoint -",
    "Network -",
    "Applications -",
    "Infrastructure -",
    "Risk -",
]

# ESV2 = environment lama (pensiun ~27-28 Jul 2026), ESV3 = environment baru (current).
# Keduanya distandarkan ke tag "[ESV]" tunggal supaya rule lintas-environment tetap match.
REMOVE_TAG_PATTERN = r"\[(?:ALTO-|NDP-)?ESV[23]?\]"

REMOVE_SUFFIX = [
    "- Rule - Rule",
    "- Rule",
    "- Severity 1",
    "- Severity 2",
    "- Severity 3",
    "- Severity 4",
    "- Severity 5",
]

RULE_STATUS = [

    "Enabled",
    "Disabled"

]

SHEET_NAME = {

    "dashboard": "Executive Summary",

    "rule_summary": "Rule Summary",

    "top_rule": "Top Rules",

    "noise": "Noise Rules",

    "tuning": "Tuning Candidates",

    "dormant": "Dormant Rules",

    "priority": "Priority Analysis",

    "analyst": "SOC Performance",

    "incident": "Incident Analysis",

    "domain": "Security Domain",

    "breach": "Breach Analysis",

    "insight": "Executive Insight"

}