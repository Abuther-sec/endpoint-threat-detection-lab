# Endpoint Threat Detection Report

- Generated at: 2026-11-11T21:57:52+00:00
- Source file: scenario3_success_after_failures.json
- Data origin: synthetic

## Summary

| Severity | Findings |
|---|---|
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Informational | 12 |

Total findings: 14

## Data quality

| Item | Value |
|---|---|
| total_records | 14 |
| usable_events | 14 |
| rejected | 0 |
| duplicates_removed | 0 |
| naive_timestamps_assumed_utc | 0 |
| events_with_missing_core_fields | 0 |

## Findings that need attention (Medium and High)

### 1. High (confidence Medium): Repeated failed logons

- Records: 1, 2, 3, 4, 5, 6
- Window: 2026-04-07T10:00:00+00:00 to 2026-04-07T10:00:25+00:00
- Description: 6 failed logons for user dave.test from source 198.51.100.77 within 25 seconds (threshold 5 in 60 s)
- Why this rating:
  - 6 failed logons for one user and source within the detection window
  - A successful logon for the same user followed (record 7); this may be a mistyped password finally corrected, or a guessed one

### 2. Medium (confidence Medium): Repeated failed logons

- Records: 8, 9, 10, 11, 12, 13
- Window: 2026-04-07T11:00:00+00:00 to 2026-04-07T11:00:25+00:00
- Description: 6 failed logons for user erin.test from source 198.51.100.88 within 25 seconds (threshold 5 in 60 s)
- Why this rating:
  - 6 failed logons for one user and source within the detection window
  - No successful logon for this user followed within the window

## All findings

| # | Severity | Confidence | Rule | Records | Description |
|---|---|---|---|---|---|
| 1 | High | Medium | REPEATED_FAILED_LOGONS | 1,2,3,4,5,6 | 6 failed logons for user dave.test from source 198.51.100.77 within 25 seconds (threshold 5 in 60 s) |
| 2 | Medium | Medium | REPEATED_FAILED_LOGONS | 8,9,10,11,12,13 | 6 failed logons for user erin.test from source 198.51.100.88 within 25 seconds (threshold 5 in 60 s) |
| 3 | Informational | High | FAILED_LOGON | 1 | Failed logon for user dave.test from source 198.51.100.77 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 4 | Informational | High | FAILED_LOGON | 2 | Failed logon for user dave.test from source 198.51.100.77 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 5 | Informational | High | FAILED_LOGON | 3 | Failed logon for user dave.test from source 198.51.100.77 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 6 | Informational | High | FAILED_LOGON | 4 | Failed logon for user dave.test from source 198.51.100.77 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 7 | Informational | High | FAILED_LOGON | 5 | Failed logon for user dave.test from source 198.51.100.77 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 8 | Informational | High | FAILED_LOGON | 6 | Failed logon for user dave.test from source 198.51.100.77 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 9 | Informational | High | FAILED_LOGON | 8 | Failed logon for user erin.test from source 198.51.100.88 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 10 | Informational | High | FAILED_LOGON | 9 | Failed logon for user erin.test from source 198.51.100.88 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 11 | Informational | High | FAILED_LOGON | 10 | Failed logon for user erin.test from source 198.51.100.88 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 12 | Informational | High | FAILED_LOGON | 11 | Failed logon for user erin.test from source 198.51.100.88 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 13 | Informational | High | FAILED_LOGON | 12 | Failed logon for user erin.test from source 198.51.100.88 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 14 | Informational | High | FAILED_LOGON | 13 | Failed logon for user erin.test from source 198.51.100.88 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |

## Limitations

- Findings are observations that need review, not proof of an attack.
- Thresholds and severity rules are starting points chosen for this lab; their detection accuracy has not been measured.
- Severity and confidence come from fixed rules and the evidence in the exported events only; missing context lowers confidence.
- Timestamps keep the offset found in the data; timestamps without an offset are assumed to be UTC and counted in the parsing summary.
