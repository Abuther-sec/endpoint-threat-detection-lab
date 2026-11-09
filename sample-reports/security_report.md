# Endpoint Threat Detection Report

- Generated at: 2026-11-09T22:42:10+00:00
- Source file: synthetic_security_events.json
- Data origin: synthetic

## Summary

| Severity | Findings |
|---|---|
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Informational | 19 |

Total findings: 21

## Data quality

| Item | Value |
|---|---|
| total_records | 21 |
| usable_events | 17 |
| rejected | 3 |
| duplicates_removed | 1 |
| naive_timestamps_assumed_utc | 0 |
| events_with_missing_core_fields | 1 |

## Findings that need attention (Medium and High)

### 1. High (confidence Medium): Repeated failed logons

- Records: 3, 4, 5, 6, 7, 8, 9, 10
- Window: 2026-01-15T10:00:00+00:00 to 2026-01-15T10:00:35+00:00
- Description: 8 failed logons for user bob.test from source 198.51.100.7 within 35 seconds (threshold 5 in 60 s)
- Why this rating:
  - 8 failed logons for one user and source within the detection window
  - A successful logon for the same user followed (record 11); this may be a mistyped password finally corrected, or a guessed one

### 2. Medium (confidence High): Multiple users from one source

- Records: 12, 13, 14, 15
- Window: 2026-01-15T11:00:05+00:00 to 2026-01-15T11:00:20+00:00
- Description: 4 different users failed to log on from source 203.0.113.50 within a 60 s window: admin.test, svc.test1, svc.test2, svc.test3
- Why this rating:
  - 4 failed logons with different user names from one source
  - Some attempts used user names that do not exist (sub-status 0xC0000064), which suggests guessing

## All findings

| # | Severity | Confidence | Rule | Records | Description |
|---|---|---|---|---|---|
| 1 | High | Medium | REPEATED_FAILED_LOGONS | 3,4,5,6,7,8,9,10 | 8 failed logons for user bob.test from source 198.51.100.7 within 35 seconds (threshold 5 in 60 s) |
| 2 | Medium | High | MULTIPLE_USERS_FROM_SOURCE | 12,13,14,15 | 4 different users failed to log on from source 203.0.113.50 within a 60 s window: admin.test, svc.test1, svc.test2, svc.test3 |
| 3 | Informational | High | FAILED_LOGON | 1 | Failed logon for user alice.test from source 192.0.2.10 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 4 | Informational | High | FAILED_LOGON | 2 | Failed logon for user alice.test from source 192.0.2.10 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 5 | Informational | High | FAILED_LOGON | 3 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 6 | Informational | High | FAILED_LOGON | 4 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 7 | Informational | High | FAILED_LOGON | 5 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 8 | Informational | High | FAILED_LOGON | 6 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 9 | Informational | High | FAILED_LOGON | 7 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 10 | Informational | High | FAILED_LOGON | 8 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 11 | Informational | High | FAILED_LOGON | 9 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 12 | Informational | High | FAILED_LOGON | 10 | Failed logon for user bob.test from source 198.51.100.7 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 13 | Informational | High | FAILED_LOGON | 12 | Failed logon for user svc.test1 from source 203.0.113.50 (logon type 3, status 0xc000006d, sub-status 0xc0000064) |
| 14 | Informational | High | FAILED_LOGON | 13 | Failed logon for user svc.test2 from source 203.0.113.50 (logon type 3, status 0xc000006d, sub-status 0xc0000064) |
| 15 | Informational | High | FAILED_LOGON | 14 | Failed logon for user svc.test3 from source 203.0.113.50 (logon type 3, status 0xc000006d, sub-status 0xc0000064) |
| 16 | Informational | High | FAILED_LOGON | 15 | Failed logon for user admin.test from source 203.0.113.50 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 17 | Informational | High | FAILED_LOGON | 18 | Failed logon for user unknown from source unknown (logon type unknown, status unknown, sub-status unknown) |
| 18 | Informational | High | MALFORMED_RECORD | 17 | Record 17 was rejected: missing timestamp |
| 19 | Informational | High | MALFORMED_RECORD | 20 | Record 20 was rejected: invalid timestamp: not-a-date |
| 20 | Informational | High | MALFORMED_RECORD | 21 | Record 21 was rejected: invalid event_id: abc |
| 21 | Informational | High | INCOMPLETE_RECORD | 18 | Record 18 is missing: computer, log_name, user |

## Limitations

- Findings are observations that need review, not proof of an attack.
- Thresholds and severity rules are starting points chosen for this lab; their detection accuracy has not been measured.
- Severity and confidence come from fixed rules and the evidence in the exported events only; missing context lowers confidence.
- Timestamps keep the offset found in the data; timestamps without an offset are assumed to be UTC and counted in the parsing summary.
