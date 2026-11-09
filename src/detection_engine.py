"""Detection engine: applies simple, explainable rules to parsed events.

Each rule returns Finding objects. A finding is an observation that needs
review, not proof of an attack. Every finding lists the record numbers of
the events behind it, so the result can be checked by hand against the
source file. Severity is added in a later phase.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

FAILED_LOGON_ID = 4625

RULE_IDS = (
    "FAILED_LOGON",
    "REPEATED_FAILED_LOGONS",
    "MULTIPLE_USERS_FROM_SOURCE",
    "IMPORTANT_EVENT",
    "MALFORMED_RECORD",
    "INCOMPLETE_RECORD",
)

# Events worth a manual look when they appear. The list is configurable.
IMPORTANT_EVENTS = {
    1102: "Audit log was cleared",
    4720: "User account was created",
    4732: "Member was added to a local security group",
    4740: "User account was locked out",
    7045: "A service was installed on the system",
}


@dataclass
class DetectionConfig:
    window_seconds: int = 60
    repeated_failures_threshold: int = 5
    multi_user_threshold: int = 3
    important_events: dict = field(default_factory=lambda: dict(IMPORTANT_EVENTS))

    def validate(self):
        if self.window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        if self.repeated_failures_threshold < 2:
            raise ValueError("repeated_failures_threshold must be at least 2")
        if self.multi_user_threshold < 2:
            raise ValueError("multi_user_threshold must be at least 2")


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    record_numbers: list
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    count: int = 0


def known(value):
    """Return the value as text, or None when missing or a placeholder."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def shown(value):
    return known(value) or "unknown"


def failed_events(events):
    wanted = (e for e in events if e.event_id == FAILED_LOGON_ID)
    return sorted(wanted, key=lambda e: e.timestamp)


def group_by(events, key_func):
    groups = {}
    for e in events:
        groups.setdefault(key_func(e), []).append(e)
    return groups


def merge_spans(spans):
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def dense_groups(events, window_seconds, qualifies):
    """Slide a time window over sorted events; return merged qualifying bursts."""
    spans = []
    left = 0
    for right in range(len(events)):
        while (events[right].timestamp - events[left].timestamp).total_seconds() > window_seconds:
            left += 1
        if qualifies(events[left:right + 1]):
            spans.append((left, right))
    return [events[a:b + 1] for a, b in merge_spans(spans)]


def make_finding(rule_id, title, description, events, user=None, source_ip=None):
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        record_numbers=[e.record_number for e in events],
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        user=user,
        source_ip=source_ip,
        count=len(events),
    )


def rule_failed_logons(events, config):
    findings = []
    for e in failed_events(events):
        text = (f"Failed logon for user {shown(e.user)} from source {shown(e.source_ip)} "
                f"(logon type {shown(e.logon_type)}, status {shown(e.status)}, "
                f"sub-status {shown(e.sub_status)})")
        findings.append(make_finding("FAILED_LOGON", "Failed logon (event 4625)",
                                     text, [e], e.user, known(e.source_ip)))
    return findings


def rule_repeated_failures(events, config):
    findings = []
    threshold = config.repeated_failures_threshold
    groups = group_by(failed_events(events),
                      lambda e: (shown(e.user).lower(), shown(e.source_ip)))
    for items in groups.values():
        for burst in dense_groups(items, config.window_seconds, lambda w: len(w) >= threshold):
            seconds = int((burst[-1].timestamp - burst[0].timestamp).total_seconds())
            text = (f"{len(burst)} failed logons for user {shown(burst[0].user)} from source "
                    f"{shown(burst[0].source_ip)} within {seconds} seconds "
                    f"(threshold {threshold} in {config.window_seconds} s)")
            findings.append(make_finding("REPEATED_FAILED_LOGONS", "Repeated failed logons",
                                         text, burst, burst[0].user, known(burst[0].source_ip)))
    return findings


def rule_multiple_users(events, config):
    findings = []
    threshold = config.multi_user_threshold
    with_source = [e for e in failed_events(events) if known(e.source_ip)]
    groups = group_by(with_source, lambda e: known(e.source_ip))

    def enough_users(window):
        return len({shown(e.user).lower() for e in window}) >= threshold

    for source, items in groups.items():
        for burst in dense_groups(items, config.window_seconds, enough_users):
            users = sorted({shown(e.user) for e in burst})
            text = (f"{len(users)} different users failed to log on from source {source} "
                    f"within a {config.window_seconds} s window: " + ", ".join(users))
            findings.append(make_finding("MULTIPLE_USERS_FROM_SOURCE",
                                         "Multiple users from one source",
                                         text, burst, None, source))
    return findings


def rule_important_events(events, config):
    findings = []
    for e in events:
        meaning = config.important_events.get(e.event_id)
        if meaning:
            text = (f"Event {e.event_id}: {meaning} "
                    f"(user {shown(e.user)}, computer {shown(e.computer)})")
            findings.append(make_finding("IMPORTANT_EVENT", "Important event " + str(e.event_id),
                                         text, [e], e.user))
    return findings


def rule_malformed(result, config):
    findings = []
    for item in result.rejected:
        number = item["record_number"]
        text = f"Record {number} was rejected: {item['reason']}"
        findings.append(Finding(rule_id="MALFORMED_RECORD", title="Malformed record rejected",
                                description=text, record_numbers=[number], count=1))
    for e in result.events:
        if e.missing_fields:
            text = f"Record {e.record_number} is missing: " + ", ".join(e.missing_fields)
            findings.append(Finding(rule_id="INCOMPLETE_RECORD", title="Incomplete record",
                                    description=text, record_numbers=[e.record_number],
                                    first_seen=e.timestamp, last_seen=e.timestamp,
                                    user=e.user, source_ip=known(e.source_ip), count=1))
    return findings


def detect(result, config=None):
    """Run all rules on a ParseResult and return a list of Findings."""
    config = config or DetectionConfig()
    config.validate()
    findings = []
    findings.extend(rule_failed_logons(result.events, config))
    findings.extend(rule_repeated_failures(result.events, config))
    findings.extend(rule_multiple_users(result.events, config))
    findings.extend(rule_important_events(result.events, config))
    findings.extend(rule_malformed(result, config))
    return findings


def count_by_rule(findings):
    counts = {rule_id: 0 for rule_id in RULE_IDS}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
    return counts


def describe(findings):
    """Return one readable line per finding."""
    lines = []
    for f in findings:
        records = ",".join(str(n) for n in f.record_numbers)
        lines.append(f"{f.rule_id} | count={f.count} | records={records} | {f.description}")
    return lines
