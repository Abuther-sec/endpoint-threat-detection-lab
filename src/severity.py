"""Severity classification: labels each finding with a severity and a confidence.

Severity says how much attention a finding deserves. Confidence says how
strongly the available evidence supports that severity. Both come from
explicit rules, and every assessment lists the reasons behind it. These
labels guide triage; they do not prove an attack.
"""
from dataclasses import dataclass, field
from datetime import timedelta

from detection_engine import known

SEVERITIES = ("Informational", "Low", "Medium", "High")
CONFIDENCES = ("Low", "Medium", "High")
SUCCESS_LOGON_ID = 4624
INTERACTIVE_LOGON = 2
NO_SUCH_USER = "0xc0000064"

# Rating for watch-list events: (severity, confidence, reason). Configurable.
IMPORTANT_EVENT_RATING = {
    1102: ("High", "Medium",
           "Clearing the audit log can hide activity, but administrators also do it"),
    4720: ("Medium", "Medium",
           "A new account can be a persistence step, but is also routine administration"),
    4732: ("Medium", "Medium",
           "Group membership changes can grant privileges, but are also routine"),
    4740: ("Low", "Medium",
           "Lockouts often follow ordinary mistyped passwords"),
    7045: ("Medium", "Medium",
           "A new service can be used for persistence, but installers also create services"),
}


@dataclass
class SeverityConfig:
    success_window_seconds: int = 300
    important_event_rating: dict = field(default_factory=lambda: dict(IMPORTANT_EVENT_RATING))

    def validate(self):
        if self.success_window_seconds < 1:
            raise ValueError("success_window_seconds must be at least 1")
        for event_id, rating in self.important_event_rating.items():
            if rating[0] not in SEVERITIES or rating[1] not in CONFIDENCES:
                raise ValueError(f"invalid rating for event {event_id}")


@dataclass
class Assessment:
    finding: object
    severity: str
    confidence: str
    reasons: list = field(default_factory=list)


def later_success(finding, all_events, config, match):
    """Return the earliest successful logon shortly after the finding that matches."""
    if finding.last_seen is None:
        return None
    limit = finding.last_seen + timedelta(seconds=config.success_window_seconds)
    found = [e for e in all_events
             if e.event_id == SUCCESS_LOGON_ID
             and finding.last_seen < e.timestamp <= limit
             and match(e)]
    return min(found, key=lambda e: e.timestamp) if found else None


def rate_repeated(finding, events, all_events, config):
    severity, confidence = "Medium", "Medium"
    reasons = [f"{finding.count} failed logons for one user and source within the detection window"]
    local_only = (not known(finding.source_ip) and bool(events)
                  and all(e.logon_type == INTERACTIVE_LOGON for e in events))
    success = None
    if known(finding.user):
        wanted = known(finding.user).lower()
        success = later_success(finding, all_events, config,
                                lambda e: (known(e.user) or "").lower() == wanted)
    if success is not None:
        reasons.append(f"A successful logon for the same user followed (record {success.record_number}); "
                       "this may be a mistyped password finally corrected, or a guessed one")
    if local_only:
        reasons.append("All attempts were local interactive logons with no network source, "
                       "so a program or the user themselves may be responsible; verify what was running")
    if success is not None and local_only:
        severity, confidence = "Medium", "Low"
    elif success is not None:
        severity, confidence = "High", "Medium"
    elif local_only:
        severity, confidence = "Low", "Low"
    else:
        reasons.append("No successful logon for this user followed within the window")
    return severity, confidence, reasons


def rate_multiple_users(finding, events, all_events, config):
    severity, confidence = "Medium", "Medium"
    reasons = [f"{finding.count} failed logons with different user names from one source"]
    if any(str(e.sub_status or "").lower() == NO_SUCH_USER for e in events):
        confidence = "High"
        reasons.append("Some attempts used user names that do not exist (sub-status 0xC0000064), "
                       "which suggests guessing")
    source = known(finding.source_ip)
    success = later_success(finding, all_events, config,
                            lambda e: source is not None and known(e.source_ip) == source)
    if success is not None:
        severity = "High"
        reasons.append(f"A successful logon from the same source followed (record {success.record_number})")
    return severity, confidence, reasons


def rate_important(finding, events, all_events, config):
    event_id = events[0].event_id if events else None
    rating = config.important_event_rating.get(event_id)
    if rating is None:
        return "Low", "Low", ["The event is on the watch list but has no defined rating"]
    return rating[0], rating[1], [rating[2]]


def rate_fixed(severity, confidence, reason):
    def rate(finding, events, all_events, config):
        return severity, confidence, [reason]
    return rate


RATERS = {
    "FAILED_LOGON": rate_fixed(
        "Informational", "High",
        "A single failed logon is common (a mistyped password); it matters only as part of a pattern"),
    "REPEATED_FAILED_LOGONS": rate_repeated,
    "MULTIPLE_USERS_FROM_SOURCE": rate_multiple_users,
    "IMPORTANT_EVENT": rate_important,
    "MALFORMED_RECORD": rate_fixed(
        "Informational", "High",
        "Data-quality issue: the record could not be used, so detection did not see it"),
    "INCOMPLETE_RECORD": rate_fixed(
        "Informational", "High",
        "Data-quality issue: the record is missing expected fields, so rules may be less reliable"),
}


def classify_all(findings, result, config=None):
    """Return an Assessment per finding, most severe first."""
    config = config or SeverityConfig()
    config.validate()
    by_record = {e.record_number: e for e in result.events}
    assessments = []
    for finding in findings:
        events = [by_record[n] for n in finding.record_numbers if n in by_record]
        rater = RATERS.get(finding.rule_id)
        if rater is None:
            rating = ("Informational", "Low", ["No severity rule is defined for this finding type"])
        else:
            rating = rater(finding, events, result.events, config)
        assessments.append(Assessment(finding, rating[0], rating[1], rating[2]))
    return sorted(assessments, key=lambda a: -SEVERITIES.index(a.severity))


def count_by_severity(assessments):
    counts = {name: 0 for name in SEVERITIES}
    for a in assessments:
        counts[a.severity] += 1
    return counts


def describe_assessments(assessments):
    """Return one readable line per assessment."""
    lines = []
    for a in assessments:
        records = ",".join(str(n) for n in a.finding.record_numbers)
        lines.append(f"{a.severity} (confidence {a.confidence}) | {a.finding.rule_id} | "
                     f"records={records} | " + "; ".join(a.reasons))
    return lines
