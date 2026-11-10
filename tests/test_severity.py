"""Unit tests for severity. They use only synthetic data."""
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "src")

import detection_engine as d
import log_parser as p
import severity as s

SAMPLE = "sample-logs/synthetic_security_events.json"
START = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def make_event(number, seconds, user="u.test", source="192.0.2.1", event_id=4625,
               logon_type=None, sub_status=None):
    return p.Event(
        timestamp=START + timedelta(seconds=seconds),
        event_id=event_id,
        computer="PC-TEST",
        log_name="Security",
        user=user,
        logon_type=logon_type,
        sub_status=sub_status,
        source_ip=source,
        record_number=number,
    )


def result_of(events, rejected=None):
    result = p.ParseResult(source_file="memory", total_records=len(events))
    result.events = list(events)
    result.rejected = rejected or []
    return result


def assess(events, rejected=None, config=None, det_config=None):
    result = result_of(events, rejected)
    return s.classify_all(d.detect(result, det_config), result, config)


def of_rule(assessments, rule_id):
    return [a for a in assessments if a.finding.rule_id == rule_id]


def burst(count, step=2, user="u.test", source="192.0.2.1", logon_type=None):
    return [make_event(i + 1, i * step, user, source, logon_type=logon_type)
            for i in range(count)]


class SyntheticSampleTests(unittest.TestCase):
    def setUp(self):
        result = p.parse_file(SAMPLE)
        self.assessments = s.classify_all(d.detect(result), result)

    def test_counts_per_severity(self):
        self.assertEqual(s.count_by_severity(self.assessments),
                         {"Informational": 19, "Low": 0, "Medium": 1, "High": 1})

    def test_most_severe_comes_first(self):
        first = self.assessments[0]
        self.assertEqual(first.finding.rule_id, "REPEATED_FAILED_LOGONS")
        self.assertEqual((first.severity, first.confidence), ("High", "Medium"))
        self.assertTrue(any("record 11" in reason for reason in first.reasons))

    def test_nonexistent_users_give_high_confidence(self):
        found = of_rule(self.assessments, "MULTIPLE_USERS_FROM_SOURCE")[0]
        self.assertEqual((found.severity, found.confidence), ("Medium", "High"))


class RatingRuleTests(unittest.TestCase):
    def test_isolated_failure_is_informational(self):
        found = of_rule(assess([make_event(1, 0)]), "FAILED_LOGON")[0]
        self.assertEqual((found.severity, found.confidence), ("Informational", "High"))

    def test_burst_without_success_is_medium(self):
        found = of_rule(assess(burst(5)), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual((found.severity, found.confidence), ("Medium", "Medium"))

    def test_burst_followed_by_success_is_high(self):
        events = burst(5) + [make_event(6, 30, event_id=4624)]
        found = of_rule(assess(events), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual((found.severity, found.confidence), ("High", "Medium"))

    def test_success_outside_window_is_ignored(self):
        events = burst(5) + [make_event(6, 408, event_id=4624)]
        found = of_rule(assess(events), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual(found.severity, "Medium")

    def test_success_window_is_configurable(self):
        events = burst(5) + [make_event(6, 408, event_id=4624)]
        config = s.SeverityConfig(success_window_seconds=500)
        found = of_rule(assess(events, config=config), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual(found.severity, "High")

    def test_success_for_another_user_is_ignored(self):
        events = burst(5) + [make_event(6, 30, user="someone.else", event_id=4624)]
        found = of_rule(assess(events), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual(found.severity, "Medium")

    def test_local_interactive_burst_is_low(self):
        events = burst(5, source=None, logon_type=2)
        found = of_rule(assess(events), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual((found.severity, found.confidence), ("Low", "Low"))

    def test_local_interactive_burst_then_success_is_medium_low(self):
        events = burst(5, source=None, logon_type=2)
        events.append(make_event(6, 30, source=None, event_id=4624))
        found = of_rule(assess(events), "REPEATED_FAILED_LOGONS")[0]
        self.assertEqual((found.severity, found.confidence), ("Medium", "Low"))


class OtherRuleTests(unittest.TestCase):
    def three_users(self, extra=None):
        events = [make_event(i + 1, i, user=name, source="198.51.100.9", sub_status="0xc0000064")
                  for i, name in enumerate(["a", "b", "c"])]
        return events + (extra or [])

    def test_nonexistent_users_raise_confidence(self):
        found = of_rule(assess(self.three_users()), "MULTIPLE_USERS_FROM_SOURCE")[0]
        self.assertEqual((found.severity, found.confidence), ("Medium", "High"))

    def test_multi_user_followed_by_success_from_source_is_high(self):
        success = make_event(4, 30, user="a", source="198.51.100.9", event_id=4624)
        found = of_rule(assess(self.three_users([success])), "MULTIPLE_USERS_FROM_SOURCE")[0]
        self.assertEqual(found.severity, "High")

    def test_important_event_ratings(self):
        events = [make_event(1, 0, event_id=1102), make_event(2, 1, event_id=4740)]
        found = {a.finding.record_numbers[0]: a for a in of_rule(assess(events), "IMPORTANT_EVENT")}
        self.assertEqual((found[1].severity, found[1].confidence), ("High", "Medium"))
        self.assertEqual((found[2].severity, found[2].confidence), ("Low", "Medium"))

    def test_unrated_important_event_defaults_to_low(self):
        det_config = d.DetectionConfig(important_events={9999: "Custom watch"})
        result = assess([make_event(1, 0, event_id=9999)], det_config=det_config)
        found = of_rule(result, "IMPORTANT_EVENT")[0]
        self.assertEqual((found.severity, found.confidence), ("Low", "Low"))

    def test_data_quality_findings_are_informational(self):
        incomplete = make_event(1, 0, event_id=4624)
        incomplete.missing_fields = ("user",)
        rejected = [{"record_number": 7, "reason": "missing timestamp"}]
        found = assess([incomplete], rejected)
        for rule_id in ("MALFORMED_RECORD", "INCOMPLETE_RECORD"):
            item = of_rule(found, rule_id)[0]
            self.assertEqual((item.severity, item.confidence), ("Informational", "High"))

    def test_invalid_config_raises(self):
        with self.assertRaises(ValueError):
            assess([], config=s.SeverityConfig(success_window_seconds=0))
        bad = {1: ("Urgent", "High", "not a valid severity")}
        with self.assertRaises(ValueError):
            assess([], config=s.SeverityConfig(important_event_rating=bad))

    def test_results_are_sorted_most_severe_first(self):
        found = assess([make_event(1, 0), make_event(2, 1000, event_id=1102)])
        self.assertEqual(found[0].severity, "High")
        self.assertEqual(found[-1].severity, "Informational")

    def test_describe_gives_one_line_per_assessment(self):
        found = assess(burst(5))
        lines = s.describe_assessments(found)
        self.assertEqual(len(lines), len(found))
        self.assertTrue(all("(confidence" in line for line in lines))


class UnknownRuleTests(unittest.TestCase):
    def test_unknown_rule_gets_a_safe_default(self):
        finding = d.Finding(rule_id="SOMETHING_NEW", title="t", description="x",
                            record_numbers=[1], count=1)
        found = s.classify_all([finding], result_of([]))
        self.assertEqual((found[0].severity, found[0].confidence), ("Informational", "Low"))
        self.assertIn("No severity rule", found[0].reasons[0])
