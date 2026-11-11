# Endpoint Threat Detection Report

- Generated at: 2026-11-11T22:17:25+00:00
- Source file: scenario5_data_quality.json
- Data origin: synthetic

## Summary

| Severity | Findings |
|---|---|
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 6 |

Total findings: 6

## Data quality

| Item | Value |
|---|---|
| total_records | 6 |
| usable_events | 3 |
| rejected | 2 |
| duplicates_removed | 1 |
| naive_timestamps_assumed_utc | 1 |
| events_with_missing_core_fields | 1 |

## Findings that need attention (Medium and High)

None.
## All findings

| # | Severity | Confidence | Rule | Records | Description |
|---|---|---|---|---|---|
| 1 | Informational | High | FAILED_LOGON | 1 | Failed logon for user alice.test from source 192.0.2.10 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 2 | Informational | High | FAILED_LOGON | 3 | Failed logon for user bob.test from source 192.0.2.11 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 3 | Informational | High | FAILED_LOGON | 6 | Failed logon for user unknown from source unknown (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 4 | Informational | High | MALFORMED_RECORD | 4 | Record 4 was rejected: invalid timestamp: not-a-date |
| 5 | Informational | High | MALFORMED_RECORD | 5 | Record 5 was rejected: missing event_id |
| 6 | Informational | High | INCOMPLETE_RECORD | 6 | Record 6 is missing: user |

## Limitations

- Findings are observations that need review, not proof of an attack.
- Thresholds and severity rules are starting points chosen for this lab; their detection accuracy has not been measured.
- Severity and confidence come from fixed rules and the evidence in the exported events only; missing context lowers confidence.
- Timestamps keep the offset found in the data; timestamps without an offset are assumed to be UTC and counted in the parsing summary.
