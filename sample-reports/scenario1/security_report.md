# Endpoint Threat Detection Report

- Generated at: 2026-11-11T21:34:14+00:00
- Source file: scenario1_bruteforce.json
- Data origin: synthetic

## Summary

| Severity | Findings |
|---|---|
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Informational | 9 |

Total findings: 10

## Data quality

| Item | Value |
|---|---|
| total_records | 9 |
| usable_events | 9 |
| rejected | 0 |
| duplicates_removed | 0 |
| naive_timestamps_assumed_utc | 0 |
| events_with_missing_core_fields | 0 |

## Findings that need attention (Medium and High)

### 1. Medium (confidence Medium): Repeated failed logons

- Records: 2, 3, 4, 5, 6, 7, 8, 9
- Window: 2026-02-10T14:00:05+00:00 to 2026-02-10T14:00:40+00:00
- Description: 8 failed logons for user bob.test from source 198.51.100.23 within 35 seconds (threshold 5 in 60 s)
- Why this rating:
  - 8 failed logons for one user and source within the detection window
  - No successful logon for this user followed within the window

## All findings

| # | Severity | Confidence | Rule | Records | Description |
|---|---|---|---|---|---|
| 1 | Medium | Medium | REPEATED_FAILED_LOGONS | 2,3,4,5,6,7,8,9 | 8 failed logons for user bob.test from source 198.51.100.23 within 35 seconds (threshold 5 in 60 s) |
| 2 | Informational | High | FAILED_LOGON | 1 | Failed logon for user alice.test from source 192.0.2.10 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 3 | Informational | High | FAILED_LOGON | 2 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 4 | Informational | High | FAILED_LOGON | 3 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 5 | Informational | High | FAILED_LOGON | 4 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 6 | Informational | High | FAILED_LOGON | 5 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 7 | Informational | High | FAILED_LOGON | 6 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 8 | Informational | High | FAILED_LOGON | 7 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 9 | Informational | High | FAILED_LOGON | 8 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |
| 10 | Informational | High | FAILED_LOGON | 9 | Failed logon for user bob.test from source 198.51.100.23 (logon type 3, status 0xc000006d, sub-status 0xc000006a) |

## Limitations

- Findings are observations that need review, not proof of an attack.
- Thresholds and severity rules are starting points chosen for this lab; their detection accuracy has not been measured.
- Severity and confidence come from fixed rules and the evidence in the exported events only; missing context lowers confidence.
- Timestamps keep the offset found in the data; timestamps without an offset are assumed to be UTC and counted in the parsing summary.
