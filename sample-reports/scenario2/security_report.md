# Endpoint Threat Detection Report

- Generated at: 2026-11-11T21:48:59+00:00
- Source file: scenario2_spray.json
- Data origin: synthetic

## Summary

| Severity | Findings |
|---|---|
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Informational | 8 |

Total findings: 9

## Data quality

| Item | Value |
|---|---|
| total_records | 8 |
| usable_events | 8 |
| rejected | 0 |
| duplicates_removed | 0 |
| naive_timestamps_assumed_utc | 0 |
| events_with_missing_core_fields | 0 |

## Findings that need attention (Medium and High)

### 1. Medium (confidence High): Multiple users from one source

- Records: 1, 2, 3, 4, 5, 6, 7, 8
- Window: 2026-03-03T20:00:05+00:00 to 2026-03-03T20:00:40+00:00
- Description: 4 different users failed to log on from source 203.0.113.45 within a 60 s window: alice.test, bob.test, carol.test, ghost.test
- Why this rating:
  - 8 failed logons with different user names from one source
  - Some attempts used user names that do not exist (sub-status 0xC0000064), which suggests guessing

## All findings

| # | Severity | Confidence | Rule | Records | Description |
|---|---|---|---|---|---|
| 1 | Medium | High | MULTIPLE_USERS_FROM_SOURCE | 1,2,3,4,5,6,7,8 | 4 different users failed to log on from source 203.0.113.45 within a 60 s window: alice.test, bob.test, carol.test, ghost.test |
| 2 | Informational | High | FAILED_LOGON | 1 | Failed logon for user alice.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 3 | Informational | High | FAILED_LOGON | 2 | Failed logon for user bob.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 4 | Informational | High | FAILED_LOGON | 3 | Failed logon for user carol.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 5 | Informational | High | FAILED_LOGON | 4 | Failed logon for user ghost.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc0000064) |
| 6 | Informational | High | FAILED_LOGON | 5 | Failed logon for user alice.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 7 | Informational | High | FAILED_LOGON | 6 | Failed logon for user bob.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 8 | Informational | High | FAILED_LOGON | 7 | Failed logon for user carol.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 9 | Informational | High | FAILED_LOGON | 8 | Failed logon for user ghost.test from source 203.0.113.45 (logon type 3, status 0xc000006d, sub-status 0xc0000064) |

## Limitations

- Findings are observations that need review, not proof of an attack.
- Thresholds and severity rules are starting points chosen for this lab; their detection accuracy has not been measured.
- Severity and confidence come from fixed rules and the evidence in the exported events only; missing context lowers confidence.
- Timestamps keep the offset found in the data; timestamps without an offset are assumed to be UTC and counted in the parsing summary.
