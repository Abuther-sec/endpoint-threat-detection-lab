"""Unit tests for report_generator. They use only synthetic data."""
import csv
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "src")

import detection_engine as d
import log_parser as p
import report_generator as g
import severity as s

SAMPLE = "sample-logs/synthetic_security_events.json"
FIXED = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def synthetic_report():
    result = p.parse_file(SAMPLE)
    assessments = s.classify_all(d.detect(result), result)
    return result, g.build_report(result, assessments, "synthetic", FIXED)


def report_for_user(name):
    event = p.Event(timestamp=FIXED, event_id=4625, computer="PC-TEST",
                    log_name="Security", user=name, source_ip="192.0.2.1",
                    record_number=1)
    result = p.ParseResult(source_file="memory.json", total_records=1)
    result.events = [event]
    assessments = s.classify_all(d.detect(result), result)
    return g.build_report(result, assessments, "synthetic", FIXED)


class ReportContentTests(unittest.TestCase):
    def setUp(self):
        self.result, self.report = synthetic_report()

    def test_totals_match_the_analysis(self):
        totals = self.report["totals"]
        self.assertEqual(totals["findings"], 21)
        self.assertEqual(totals["by_severity"],
                         {"Informational": 19, "Low": 0, "Medium": 1, "High": 1})
        self.assertEqual(totals["by_rule"], {
            "FAILED_LOGON": 15, "REPEATED_FAILED_LOGONS": 1,
            "MULTIPLE_USERS_FROM_SOURCE": 1, "IMPORTANT_EVENT": 0,
            "MALFORMED_RECORD": 3, "INCOMPLETE_RECORD": 1,
        })
        self.assertEqual(self.report["parsing"], p.summary(self.result))

    def test_source_has_file_name_only(self):
        self.assertEqual(self.report["source"]["file_name"], "synthetic_security_events.json")
        self.assertNotIn("sample-logs", g.to_json(self.report))

    def test_generated_at_uses_the_given_time(self):
        self.assertEqual(self.report["generated_at"], "2026-01-01T12:00:00+00:00")

    def test_findings_are_ranked_most_severe_first(self):
        rows = self.report["findings"]
        self.assertEqual([r["rank"] for r in rows], list(range(1, 22)))
        self.assertEqual(rows[0]["severity"], "High")
        order = [s.SEVERITIES.index(r["severity"]) for r in rows]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_limitations_are_always_present(self):
        self.assertGreaterEqual(len(self.report["limitations"]), 4)
        self.assertIn("## Limitations", g.to_markdown(self.report))


class SafetyTests(unittest.TestCase):
    def test_safe_cell_neutralizes_formulas(self):
        for text in ("=1+1", "+1", "-1", "@SUM(A1)"):
            self.assertEqual(g.safe_cell(text), "'" + text)
        self.assertEqual(g.safe_cell("alice.test"), "alice.test")
        self.assertEqual(g.safe_cell(None), "")

    def test_md_cell_escapes_pipes_tags_and_newlines(self):
        self.assertEqual(g.md_cell("a|b <i>x</i>\ny"), "a\\|b &lt;i&gt;x&lt;/i&gt; y")

    def test_csv_neutralizes_a_formula_in_the_user_column(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        paths = g.write_reports(report_for_user("=1+1"), folder.name)
        with paths["csv"].open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["user"], "'=1+1")

    def test_markdown_table_keeps_a_pipe_in_a_user_name_escaped(self):
        text = g.to_markdown(report_for_user("a|b"))
        self.assertIn("a\\|b", text)


class FileOutputTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        _, self.report = synthetic_report()
        self.paths = g.write_reports(self.report, Path(folder.name) / "nested")

    def test_three_files_are_created(self):
        self.assertEqual(sorted(self.paths), ["csv", "json", "md"])
        for path in self.paths.values():
            self.assertTrue(path.is_file())

    def test_json_is_valid_and_has_no_bom(self):
        raw = self.paths["json"].read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(json.loads(raw.decode("utf-8")), self.report)

    def test_csv_has_one_row_per_finding(self):
        with self.paths["csv"].open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 21)
        self.assertEqual(list(rows[0].keys()), list(g.CSV_COLUMNS))

    def test_markdown_contains_the_summary_and_findings(self):
        text = self.paths["md"].read_text(encoding="utf-8")
        self.assertIn("Total findings: 21", text)
        self.assertIn("Repeated failed logons", text)
