"""Command line entry point: parse, detect, classify and write reports.

Example:
    python src/analyze.py sample-logs/synthetic_security_events.json --origin synthetic --out sample-reports
"""
import argparse
import logging
import sys
from pathlib import Path

import detection_engine
import log_parser
import report_generator
import severity

DEFAULT_OUT = "output"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Analyze an exported security log and write reports.")
    parser.add_argument("input", help="path to a .json or .csv export")
    parser.add_argument("--origin", required=True, choices=("synthetic", "real"),
                        help="where the data comes from; real data may only go to the output folder")
    parser.add_argument("--out", default=DEFAULT_OUT, help="folder for the reports (default: output)")
    parser.add_argument("--window", type=int, default=60, help="detection window in seconds")
    parser.add_argument("--repeat-threshold", type=int, default=5,
                        help="failed logons that count as repeated")
    parser.add_argument("--multi-user-threshold", type=int, default=3,
                        help="distinct users from one source that count as suspicious")
    parser.add_argument("--success-window", type=int, default=300,
                        help="seconds to look for a successful logon after a burst")
    return parser


def run(args):
    if args.origin == "real" and Path(args.out).resolve() != Path(DEFAULT_OUT).resolve():
        raise ValueError("reports from real data may only be written to the output folder")
    result = log_parser.parse_file(args.input)
    detection_config = detection_engine.DetectionConfig(
        window_seconds=args.window,
        repeated_failures_threshold=args.repeat_threshold,
        multi_user_threshold=args.multi_user_threshold,
    )
    severity_config = severity.SeverityConfig(success_window_seconds=args.success_window)
    findings = detection_engine.detect(result, detection_config)
    assessments = severity.classify_all(findings, result, severity_config)
    report = report_generator.build_report(result, assessments, args.origin)
    return report, report_generator.write_reports(report, args.out)


def main(argv=None):
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    args = build_parser().parse_args(argv)
    try:
        report, paths = run(args)
    except (log_parser.LogParserError, ValueError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    totals = report["totals"]
    print("Findings: " + str(totals["findings"]) + "  by severity: " + str(totals["by_severity"]))
    for name in ("json", "csv", "md"):
        print("Wrote " + str(paths[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
