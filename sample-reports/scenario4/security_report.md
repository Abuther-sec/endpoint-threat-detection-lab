# Endpoint Threat Detection Report

- Generated at: 2026-11-11T22:07:35+00:00
- Source file: scenario4_privileged_changes.json
- Data origin: synthetic

## Summary

| Severity | Findings |
|---|---|
| High | 1 |
| Medium | 2 |
| Low | 1 |
| Informational | 0 |

Total findings: 4

## Data quality

| Item | Value |
|---|---|
| total_records | 4 |
| usable_events | 4 |
| rejected | 0 |
| duplicates_removed | 0 |
| naive_timestamps_assumed_utc | 0 |
| events_with_missing_core_fields | 0 |

## Findings that need attention (Medium and High)

### 1. High (confidence Medium): Important event 1102

- Records: 4
- Window: 2026-05-12T09:12:00+00:00 to 2026-05-12T09:12:00+00:00
- Description: Event 1102: Audit log was cleared (user admin.test, computer LAB-PC01)
- Why this rating:
  - Clearing the audit log can hide activity, but administrators also do it

### 2. Medium (confidence Medium): Important event 4720

- Records: 2
- Window: 2026-05-12T09:10:00+00:00 to 2026-05-12T09:10:00+00:00
- Description: Event 4720: User account was created (user admin.test, computer LAB-PC01)
- Why this rating:
  - A new account can be a persistence step, but is also routine administration

### 3. Medium (confidence Medium): Important event 4732

- Records: 3
- Window: 2026-05-12T09:10:30+00:00 to 2026-05-12T09:10:30+00:00
- Description: Event 4732: Member was added to a local security group (user admin.test, computer LAB-PC01)
- Why this rating:
  - Group membership changes can grant privileges, but are also routine

## All findings

| # | Severity | Confidence | Rule | Records | Description |
|---|---|---|---|---|---|
| 1 | High | Medium | IMPORTANT_EVENT | 4 | Event 1102: Audit log was cleared (user admin.test, computer LAB-PC01) |
| 2 | Medium | Medium | IMPORTANT_EVENT | 2 | Event 4720: User account was created (user admin.test, computer LAB-PC01) |
| 3 | Medium | Medium | IMPORTANT_EVENT | 3 | Event 4732: Member was added to a local security group (user admin.test, computer LAB-PC01) |
| 4 | Low | Medium | IMPORTANT_EVENT | 1 | Event 4740: User account was locked out (user alice.test, computer LAB-PC01) |

## Limitations

- Findings are observations that need review, not proof of an attack.
- Thresholds and severity rules are starting points chosen for this lab; their detection accuracy has not been measured.
- Severity and confidence come from fixed rules and the evidence in the exported events only; missing context lowers confidence.
- Timestamps keep the offset found in the data; timestamps without an offset are assumed to be UTC and counted in the parsing summary.
