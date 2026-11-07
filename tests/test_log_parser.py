"""Unit tests for log_parser. They use only synthetic data."""
import csv
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, "src")

import log_parser as p

SAMPLE = "sample-logs/synthetic_security_events.json"


def good(extra=None):
    """Return one valid synthetic record, optionally with changed fields."""
    record = {
        "Timestamp": "2026-01-15T09:00:00+00:00",
        "EventId": 4625,
        "Computer": "PC-TEST",
        "LogName": "Security",
        "User": "u.test",
    }
    if extra:
        record.update(extra)
    return record


class SyntheticSampleTests(unittest.TestCase):
    def setUp(self):
        self.result = p.parse_file(SAMPLE)

    def test_counts(self):
        s = p.summary(self.result)
        self.assertEqual(s["total_records"], 21)
        self.assertEqual(s["usable_events"], 17)
        self.assertEqual(s["rejected"], 3)
        self.assertEqual(s["duplicates_removed"], 1)
        self.assertEqual(s["naive_timestamps_assumed_utc"], 0)
        self.assertEqual(s["events_with_missing_core_fields"], 1)

    def test_rejected_reasons(self):
        reasons = {r["record_number"]: r["reason"] for r in self.result.rejected}
        self.assertEqual(reasons, {
            17: "missing timestamp",
            20: "invalid timestamp: not-a-date",
            21: "invalid event_id: abc",
        })

    def test_duplicate_is_not_kept(self):
        numbers = [e.record_number for e in self.result.events]
        self.assertIn(1, numbers)
        self.assertNotIn(19, numbers)

    def test_incomplete_record_is_kept_and_flagged(self):
        found = [e for e in self.result.events if e.record_number == 18]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].missing_fields, ("computer", "log_name", "user"))


class ParserBehaviorTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def write_json(self, records, name="events.json", encoding="utf-8"):
        path = self.folder / name
        path.write_text(json.dumps(records), encoding=encoding)
        return path

    def test_timezone_offset_is_preserved(self):
        path = self.write_json([good({"Timestamp": "2026-01-15T09:00:00-08:00"})])
        result = p.parse_file(path)
        self.assertEqual(result.events[0].timestamp.utcoffset(), timedelta(hours=-8))

    def test_naive_timestamp_is_assumed_utc_and_counted(self):
        path = self.write_json([good({"Timestamp": "2026-01-15T09:00:00"})])
        result = p.parse_file(path)
        self.assertEqual(result.naive_timestamps, 1)
        self.assertEqual(result.events[0].timestamp.utcoffset(), timedelta(0))

    def test_utf8_bom_file_is_readable(self):
        path = self.write_json([good()], encoding="utf-8-sig")
        result = p.parse_file(path)
        self.assertEqual(len(result.events), 1)

    def test_csv_with_alias_headers(self):
        path = self.folder / "events.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["TimeCreated", "Id", "MachineName", "LogName", "TargetUserName"])
            writer.writerow(["2026-01-15T09:00:00+00:00", "4625", "PC-TEST", "Security", "u.test"])
        result = p.parse_file(path)
        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.event_id, 4625)
        self.assertEqual(event.computer, "PC-TEST")
        self.assertEqual(event.user, "u.test")

    def test_source_file_is_not_modified(self):
        path = self.write_json([good(), good({"EventId": "abc"})])
        before = path.read_bytes()
        p.parse_file(path)
        self.assertEqual(path.read_bytes(), before)

    def test_non_object_records_are_rejected(self):
        path = self.write_json([good(), "text", 5])
        result = p.parse_file(path)
        self.assertEqual(len(result.events), 1)
        self.assertEqual([r["reason"] for r in result.rejected],
                         ["record is not an object", "record is not an object"])

    def test_missing_file_raises(self):
        with self.assertRaises(p.LogParserError):
            p.parse_file(self.folder / "nope.json")

    def test_unsupported_extension_raises(self):
        path = self.folder / "events.txt"
        path.write_text("hello", encoding="utf-8")
        with self.assertRaises(p.LogParserError):
            p.parse_file(path)

    def test_invalid_json_raises(self):
        path = self.folder / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(p.LogParserError):
            p.parse_file(path)
