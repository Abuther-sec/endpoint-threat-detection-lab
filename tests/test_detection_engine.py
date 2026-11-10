"""Unit tests for detection_engine. They use only synthetic data."""
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "src")

import detection_engine as d
import log_parser as p

SAMPLE = "sample-logs/synthetic_security_events.json"
START = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def make_event(number, seconds, user="u.test", source="192.0.2.1", event_id=4625):
    return p.Event(
        timestamp=START + timedelta(seconds=seconds),
        event_id=event_id,
        computer="PC-TEST",
        log_name="Security",
        user=user,
        source_ip=source,
        record_number=number,
    )


def result_of(events, rejected=None):
    result = p.ParseResult(source_file="memory", total_records=len(events))
    result.events = list(events)
    result.rejected = rejected or []
    return result


def of_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


class SyntheticSampleTests(unittest.TestCase):
    def setUp(self):
        self.findings = d.detect(p.parse_file(SAMPLE))

    def test_counts_per_rule(self):
        self.assertEqual(d.count_by_rule(self.findings), {
            "FAILED_LOGON": 15,
            "REPEATED_FAILED_LOGONS": 1,
            "MULTIPLE_USERS_FROM_SOURCE": 1,
            "IMPORTANT_EVENT": 0,
            "MALFORMED_RECORD": 3,
            "INCOMPLETE_RECORD": 1,
        })

    def test_repeated_failures_finding(self):
        found = of_rule(self.findings, "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual(found.record_numbers, [3, 4, 5, 6, 7, 8, 9, 10])
        self.assertEqual(found.count, 8)

    def test_multiple_users_finding(self):
        found = of_rule(self.findings, "MULTIPLE_USERS_FROM_SOURCE")[0]
        self.assertEqual(found.record_numbers, [12, 13, 14, 15])
        self.assertEqual(found.source_ip, "203.0.113.50")


class RuleBehaviorTests(unittest.TestCase):
    def burst(self, count, step, user="u.test", source="192.0.2.1"):
        return [make_event(i + 1, i * step, user, source) for i in range(count)]

    def test_below_threshold_is_not_reported(self):
        findings = d.detect(result_of(self.burst(4, 3)))
        self.assertEqual(len(of_rule(findings, "REPEATED_FAILED_LOGONS")), 0)

    def test_threshold_is_configurable(self):
        config = d.DetectionConfig(repeated_failures_threshold=4)
        findings = d.detect(result_of(self.burst(4, 3)), config)
        found = of_rule(findings, "REPEATED_FAILED_LOGONS")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].count, 4)

    def test_failures_spread_beyond_window_are_not_grouped(self):
        findings = d.detect(result_of(self.burst(5, 30)))
        self.assertEqual(len(of_rule(findings, "REPEATED_FAILED_LOGONS")), 0)

    def test_different_users_trigger_only_the_multi_user_rule(self):
        events = [make_event(i + 1, i, user="user" + str(i)) for i in range(5)]
        findings = d.detect(result_of(events))
        self.assertEqual(len(of_rule(findings, "REPEATED_FAILED_LOGONS")), 0)
        self.assertEqual(len(of_rule(findings, "MULTIPLE_USERS_FROM_SOURCE")), 1)

    def test_unknown_source_is_skipped_by_multi_user_rule(self):
        events = [
            make_event(1, 0, user="a", source=None),
            make_event(2, 1, user="b", source="-"),
            make_event(3, 2, user="c", source=None),
        ]
        findings = d.detect(result_of(events))
        self.assertEqual(len(of_rule(findings, "MULTIPLE_USERS_FROM_SOURCE")), 0)

    def test_successful_logons_are_ignored(self):
        events = [make_event(i + 1, i, event_id=4624) for i in range(10)]
        findings = d.detect(result_of(events))
        self.assertEqual(len(of_rule(findings, "FAILED_LOGON")), 0)
        self.assertEqual(len(of_rule(findings, "REPEATED_FAILED_LOGONS")), 0)

    def test_important_event_is_reported(self):
        findings = d.detect(result_of([make_event(1, 0, event_id=1102)]))
        self.assertEqual(len(of_rule(findings, "IMPORTANT_EVENT")), 1)

    def test_important_events_are_configurable(self):
        config = d.DetectionConfig(important_events={4624: "Custom watch"})
        events = [make_event(1, 0, event_id=4624), make_event(2, 1, event_id=1102)]
        findings = d.detect(result_of(events), config)
        found = of_rule(findings, "IMPORTANT_EVENT")
        self.assertEqual([f.record_numbers for f in found], [[1]])

    def test_incomplete_record_is_reported(self):
        event = make_event(1, 0, event_id=4624)
        event.missing_fields = ("user",)
        findings = d.detect(result_of([event]))
        self.assertEqual(len(of_rule(findings, "INCOMPLETE_RECORD")), 1)

    def test_rejected_record_is_reported(self):
        rejected = [{"record_number": 7, "reason": "missing timestamp"}]
        findings = d.detect(result_of([], rejected))
        found = of_rule(findings, "MALFORMED_RECORD")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].record_numbers, [7])

    def test_invalid_config_raises(self):
        with self.assertRaises(ValueError):
            d.detect(result_of([]), d.DetectionConfig(window_seconds=0))
        with self.assertRaises(ValueError):
            d.detect(result_of([]), d.DetectionConfig(repeated_failures_threshold=1))

    def test_empty_input_gives_no_findings(self):
        self.assertEqual(d.detect(result_of([])), [])


class ConfigAndDescribeTests(unittest.TestCase):
    def test_multi_user_threshold_below_two_raises(self):
        with self.assertRaises(ValueError):
            d.detect(result_of([]), d.DetectionConfig(multi_user_threshold=1))

    def test_describe_gives_one_line_per_finding(self):
        findings = d.detect(result_of([make_event(1, 0), make_event(2, 1)]))
        lines = d.describe(findings)
        self.assertEqual(len(lines), len(findings))
        self.assertTrue(lines[0].startswith("FAILED_LOGON | count=1 | records=1 |"))
