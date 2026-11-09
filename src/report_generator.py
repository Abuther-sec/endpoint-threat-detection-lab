"""Report generator: writes JSON, CSV and Markdown reports.

Every number in a report is computed from the analysis results; nothing is
typed by hand. Only the file name of the source is stored (not its full
path), and reports made from real data belong in the git-ignored output
folder.
"""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import detection_engine as detection
import log_parser
import severity

LIMITATIONS = (
    "Findings are observations that need review, not proof of an attack.",
    "Thresholds and severity rules are starting points chosen for this lab; "
    "their detection accuracy has not been measured.",
    "Severity and confidence come from fixed rules and the evidence in the "
    "exported events only; missing context lowers confidence.",
    "Timestamps keep the offset found in the data; timestamps without an "
    "offset are assumed to be UTC and counted in the parsing summary.",
)

CSV_COLUMNS = (
    "rank", "severity", "confidence", "rule_id", "count", "first_seen",
    "last_seen", "user", "source_ip", "record_numbers", "description", "reasons",
)


def iso(value):
    return value.isoformat() if value is not None else None


def finding_row(rank, assessment):
    item = assessment.finding
    return {
        "rank": rank,
        "severity": assessment.severity,
        "confidence": assessment.confidence,
        "rule_id": item.rule_id,
        "title": item.title,
        "description": item.description,
        "count": item.count,
        "record_numbers": list(item.record_numbers),
        "first_seen": iso(item.first_seen),
        "last_seen": iso(item.last_seen),
        "user": item.user,
        "source_ip": item.source_ip,
        "reasons": list(assessment.reasons),
    }


def build_report(result, assessments, data_origin, generated_at=None):
    """Return the report as a dictionary built only from computed results."""
    generated_at = generated_at or datetime.now(timezone.utc)
    findings = [a.finding for a in assessments]
    return {
        "report_title": "Endpoint Threat Detection Report",
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "source": {
            "file_name": Path(result.source_file).name,
            "data_origin": data_origin,
        },
        "parsing": log_parser.summary(result),
        "totals": {
            "findings": len(assessments),
            "by_severity": severity.count_by_severity(assessments),
            "by_rule": detection.count_by_rule(findings),
        },
        "findings": [finding_row(i + 1, a) for i, a in enumerate(assessments)],
        "limitations": list(LIMITATIONS),
    }


def safe_cell(value):
    """Neutralize spreadsheet formulas: a cell must not start with = + - or @."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


def md_cell(value):
    """Make a value safe inside a Markdown table cell."""
    text = "" if value is None else str(value)
    text = text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(text.split())


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def write_csv(report, path):
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for row in report["findings"]:
            values = dict(row)
            values["record_numbers"] = ",".join(str(n) for n in row["record_numbers"])
            values["reasons"] = " | ".join(row["reasons"])
            writer.writerow([safe_cell(values[name]) for name in CSV_COLUMNS])


def to_markdown(report):
    totals = report["totals"]
    lines = [
        "# " + report["report_title"],
        "",
        "- Generated at: " + report["generated_at"],
        "- Source file: " + md_cell(report["source"]["file_name"]),
        "- Data origin: " + md_cell(report["source"]["data_origin"]),
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    for name in reversed(severity.SEVERITIES):
        lines.append(f"| {name} | {totals['by_severity'][name]} |")
    lines += ["", f"Total findings: {totals['findings']}", "",
              "## Data quality", "", "| Item | Value |", "|---|---|"]
    for key, value in report["parsing"].items():
        lines.append(f"| {key} | {value} |")
    lines += ["", "## Findings that need attention (Medium and High)", ""]
    attention = [x for x in report["findings"] if x["severity"] in ("High", "Medium")]
    if not attention:
        lines.append("None.")
    for item in attention:
        records = ", ".join(str(n) for n in item["record_numbers"])
        lines.append(f"### {item['rank']}. {item['severity']} "
                     f"(confidence {item['confidence']}): {md_cell(item['title'])}")
        lines += ["", "- Records: " + records,
                  "- Window: " + str(item["first_seen"]) + " to " + str(item["last_seen"]),
                  "- Description: " + md_cell(item["description"]),
                  "- Why this rating:"]
        lines += ["  - " + md_cell(reason) for reason in item["reasons"]]
        lines.append("")
    lines += ["## All findings", "",
              "| # | Severity | Confidence | Rule | Records | Description |",
              "|---|---|---|---|---|---|"]
    for item in report["findings"]:
        records = ",".join(str(n) for n in item["record_numbers"])
        lines.append(f"| {item['rank']} | {item['severity']} | {item['confidence']} | "
                     f"{item['rule_id']} | {records} | {md_cell(item['description'])} |")
    lines += ["", "## Limitations", ""]
    lines += ["- " + text for text in report["limitations"]]
    return "\n".join(lines) + "\n"


def write_reports(report, out_dir):
    """Write the JSON, CSV and Markdown reports and return their paths."""
    folder = Path(out_dir)
    folder.mkdir(parents=True, exist_ok=True)
    paths = {name: folder / ("security_report." + name) for name in ("json", "csv", "md")}
    paths["json"].write_text(to_json(report), encoding="utf-8")
    write_csv(report, paths["csv"])
    paths["md"].write_text(to_markdown(report), encoding="utf-8")
    return paths
