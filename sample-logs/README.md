# Sample Logs

synthetic_security_events.json contains synthetic Windows-Security-style events used to test the log analyzer. It is not real data.

- 21 records on a fixed date (2026-01-15), so tests are repeatable.
- Fictional accounts (*.test) and IP addresses from the reserved documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Fields mirror a real export: Timestamp, EventId, Computer, Provider, LogName, User, LogonType, Status, SubStatus, SourceIp.

## Test cases

| Case | Records | Purpose |
|---|---|---|
| Few failed logins | alice.test x2 | Below a repeated-failure threshold |
| Burst of failures | bob.test x8 within 35 seconds, then 1 success | Repeated failed logins |
| One source, many accounts | svc.test1-3, admin.test from one IP | Multiple users from one source |
| Success without failures | carol.test | Negative case |
| Missing timestamp | dave.test | Malformed record |
| Incomplete record | Only Timestamp and EventId | Malformed record |
| Duplicate | Copy of the first alice.test record | Duplicate handling |
| Invalid values | erin.test (bad timestamp), frank.test (non-numeric EventId) | Invalid records |

## Real data

Real log exports are never committed. They are stored in private-data/, which is excluded by .gitignore.
