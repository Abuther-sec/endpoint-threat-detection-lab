# Detection rules and rating logic

This page describes what the tool does as implemented in src/detection_engine.py and
src/severity.py. Values marked "observed" were seen in the scenario reports; the rest
describe the code.

## Parsing before detection

- Records without a valid timestamp or an EventId are rejected and reported (MALFORMED_RECORD).
- Exact duplicates are removed and counted.
- Timestamps without an offset are assumed to be UTC and counted.
- A usable record without a user is reported as INCOMPLETE_RECORD.

## Rules and default thresholds

| Rule | Trigger | Configurable through |
|---|---|---|
| FAILED_LOGON | One failed logon (event 4625) | none |
| REPEATED_FAILED_LOGONS | 5 or more failures for one user and one source within 60 s; overlapping spans are merged into one finding | --window, --repeat-threshold |
| MULTIPLE_USERS_FROM_SOURCE | 3 or more different users failing from one source within the window; a missing source is skipped | --multi-user-threshold |
| IMPORTANT_EVENT | Event IDs 1102, 4720, 4732, 4740, 7045 | DetectionConfig.important_events in code |
| MALFORMED_RECORD | A rejected record | none |
| INCOMPLETE_RECORD | A usable record missing a core field | none |

## Ratings

Severity: Informational, Low, Medium, High. Confidence: Low, Medium, High. Each rating
comes with printed reasons.

| Finding | Rating | Source |
|---|---|---|
| FAILED_LOGON | Informational, confidence High | observed |
| MALFORMED_RECORD, INCOMPLETE_RECORD | Informational, confidence High | observed |
| REPEATED_FAILED_LOGONS, no success after the burst | Medium, confidence Medium | observed (scenarios 1 and 3) |
| REPEATED_FAILED_LOGONS, success for the same user within 300 s | High, confidence Medium | observed (scenario 3) |
| MULTIPLE_USERS_FROM_SOURCE with a nonexistent user name | Medium, confidence High | observed (scenario 2) |
| Event 1102 | High, confidence Medium | observed (scenario 4) |
| Events 4720 and 4732 | Medium, confidence Medium | observed (scenario 4) |
| Event 4740 | Low, confidence Medium | observed (scenario 4) |

Defined in the code but not exercised by the published scenarios: a burst of local
interactive logons (type 2, no source address) is rated lower (Low, confidence Low); this
was seen only on private local data, which is not published. Event 7045 has its own
rating in severity.py.

## How to read the status codes

- 0xc000006d: logon failure; the sub-status gives the reason.
- 0xc000006a: the user name is correct, the password is wrong.
- 0xc0000064: the user name does not exist.
- 0xc000006e: an account restriction applied.

## Known limits

- Thresholds and ratings are starting points chosen for this lab; accuracy has not been measured.
- Events are rated one by one. A success after failures is looked for only within 300 s
  (--success-window), and a later success is not mentioned in the finding (scenario 3).
- The windows are short by default, so a slow spray over hours would not be grouped.
- Confidence does not yet account for missing fields (scenario 5).
