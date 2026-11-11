# SOC scenarios (synthetic data)

All scenarios use invented logs (documentation address ranges 192.0.2.0/24 and
198.51.100.0/24, accounts such as alice.test). No real data is used. Each section keeps
what the tool reported (facts) apart from how it is read (interpretation, not proof).

## Scenario 1: repeated failed logons against one account

Input: sample-logs/scenarios/scenario1_bruteforce.json (9 records).

Command:

    python src/analyze.py sample-logs/scenarios/scenario1_bruteforce.json --origin synthetic --out sample-reports/scenario1

### Facts (from the generated report)

- 9 of 9 records usable, 0 rejected.
- 10 findings: 1 Medium (confidence Medium) and 9 Informational (confidence High).
- The Medium finding is REPEATED_FAILED_LOGONS: 8 failed logons for user bob.test from
  198.51.100.23 within 35 seconds (14:00:05 to 14:00:40 UTC), records 2 to 9,
  threshold 5 in 60 s.
- Reasons printed by the tool: 8 failures for one user and source inside the window, and
  no successful logon for that user followed within the window.
- All failures are logon type 3 with status 0xc000006d and sub-status 0xc000006a.
- Record 1 (alice.test, one failure from 192.0.2.10) is a separate Informational finding.

### Reading (interpretation, not proof)

- The pattern fits password guessing against one account from one source.
- Sub-status 0xc000006a means the user name exists and the password was wrong, so
  whoever tried seems to know the account name. This is an observation about the log
  entry, not about intent.
- The Medium rating is about the burst alone. A successful logon after the burst would
  raise it (the rules look 300 s ahead); none exists in this data.
- Not determined: who is behind the source, whether it is inside or outside the network,
  and whether a password was guessed after the window.

### What an analyst would check next

- Successful logons (4624) for bob.test from the same source after 14:00:40, also beyond 300 s.
- Account lockout events (4740) for bob.test.
- Whether the source is expected (scanner, misconfigured service, test host).
- Other accounts targeted by the same source in the same period.

## Scenario 2: one source, several accounts (password spray pattern)

Input: sample-logs/scenarios/scenario2_spray.json (8 records).

Command:

    python src/analyze.py sample-logs/scenarios/scenario2_spray.json --origin synthetic --out sample-reports/scenario2

### Facts (from the generated report)

- 8 of 8 records usable, 0 rejected.
- 9 findings: 1 Medium (confidence High) and 8 Informational (confidence High).
- The Medium finding is MULTIPLE_USERS_FROM_SOURCE: 4 different users (alice.test,
  bob.test, carol.test, ghost.test) failed to log on from 203.0.113.45 inside a
  60 s window, records 1 to 8, 20:00:05 to 20:00:40 UTC.
- Reasons printed by the tool: 8 failed logons with different user names from one source,
  and some attempts used user names that do not exist (sub-status 0xC0000064).
- No REPEATED_FAILED_LOGONS finding: each account failed only twice, below the threshold of 5.
- Records 4 and 8 (ghost.test) carry sub-status 0xc0000064; the other six carry 0xc000006a.

### Reading (interpretation, not proof)

- Few attempts per account across several accounts fits a password spray: it stays under
  per-account thresholds, which is why the per-account rule stays silent here while the
  per-source rule fires. Compare scenario 1.
- A name that does not exist, tried twice, suggests the list of names was guessed or
  taken from somewhere else. The log does not show which passwords were tried.
- Not determined: whether any attempt succeeded, whether the source is internal or
  external, and whether ghost.test is a typo or part of a name list.

### Limits of this detection

- The rule groups failures inside a 60 s window by default. A slower spray spread over
  hours would not be grouped by it. That case was not tested here.

### What an analyst would check next

- Successful logons (4624) from 203.0.113.45 for any of the four names, at any time after.
- Lockout events (4740) for the three existing accounts.
- Other names tried by the same source before 20:00:05 or after 20:00:40.
- Whether the source is expected (scanner, test host).

## Scenario 3: successful logon after repeated failures

Input: sample-logs/scenarios/scenario3_success_after_failures.json (14 records).

The file holds two cases built the same way: six failed logons 5 seconds apart, then a
successful logon (4624) from the same source for the same user. Only the delay differs:
95 s after the last failure for dave.test (record 7) and 575 s for erin.test (record 14).

Command:

    python src/analyze.py sample-logs/scenarios/scenario3_success_after_failures.json --origin synthetic --out sample-reports/scenario3

### Facts (from the generated report)

- 14 of 14 records usable, 0 rejected, 0 with missing core fields (the 4624 records have
  no Status or SubStatus and were still accepted).
- 14 findings: 1 High (confidence Medium), 1 Medium (confidence Medium), 12 Informational.
- High: REPEATED_FAILED_LOGONS for dave.test from 198.51.100.77, records 1 to 6,
  6 failures within 25 s. Reasons printed: 6 failures for one user and source, and a
  successful logon for the same user followed (record 7).
- Medium: REPEATED_FAILED_LOGONS for erin.test from 198.51.100.88, records 8 to 13,
  6 failures within 25 s. Reasons printed: 6 failures, and no successful logon for this
  user followed within the window.
- The two successful logons (records 7 and 14) produce no finding of their own.

### Reading (interpretation, not proof)

- The two cases differ only in the delay of the success, and their ratings differ. The
  tool words the success as a possible mistyped password finally corrected, or a guessed
  one; the log alone cannot tell which.
- The finding for erin.test says no success followed within the window, but record 14
  shows one 575 s later. The 300 s look-ahead is a lab choice, so a later success is not
  mentioned in that finding. An analyst reading only the finding would miss it.
- Not determined: whether either success came from the person who owns the account.

### What an analyst would check next

- What the account did after the successful logon (new sessions, privilege use, other hosts).
- Whether the source address is known for that user.
- Whether the account password was reset or the user was contacted.
- For any burst of failures, search the whole log for successful logons by the same user
  and source, not only inside the 300 s window.

## Scenario 4: account creation, group change and log clearing

Input: sample-logs/scenarios/scenario4_privileged_changes.json (4 records).

The file holds four events on one computer within seven minutes: a lockout (4740), then
an account creation (4720), a group membership change (4732) and a security log clear
(1102) performed by admin.test. The data has a single user field, so the name of the
created account and the group are not in it.

Command:

    python src/analyze.py sample-logs/scenarios/scenario4_privileged_changes.json --origin synthetic --out sample-reports/scenario4

### Facts (from the generated report)

- 4 of 4 records usable, 0 rejected, 0 with missing core fields.
- 4 findings, all IMPORTANT_EVENT, one per record: 1 High, 2 Medium, 1 Low (all confidence Medium).
- High: event 1102, audit log cleared (record 4, 09:12:00). Reason printed: clearing the
  audit log can hide activity, but administrators also do it.
- Medium: event 4720, user account created (record 2, 09:10:00). Reason printed: a new
  account can be a persistence step, but is also routine administration.
- Medium: event 4732, member added to a local security group (record 3, 09:10:30). Reason
  printed: group membership changes can grant privileges, but are also routine.
- Low: event 4740, account locked out (alice.test, record 1, 09:05:00).
- Each event is rated alone. No finding connects them.

### Reading (interpretation, not proof)

- In time order the events are account creation, group change, then log clearing, within
  two minutes, by one account. An analyst may read that order as a possible cover-up
  pattern, but the same sequence can also be a normal administrator task.
- Not determined: which account was created, which group received it, whether the
  changes were approved, and whether admin.test is a legitimate administrator.
- Events before the log clear may no longer exist on the machine, so the clear limits
  what the rest of this log can show.

### Limits of this detection

- The tool rates events one by one. A rule that links related events in sequence is not
  implemented; it is possible future work.
- The format has one user field, so the actor and the target of an event are not
  separated.

### What an analyst would check next

- The created account and the group in the original events, and who requested them.
- Logon events for admin.test before 09:10:00, and the source of those logons.
- A copy of the log held elsewhere (forwarded events or a backup), since the local log was cleared.
- Whether a change ticket or approval exists for these actions.

## Scenario 5: dirty input (duplicates, bad and missing fields)

Input: sample-logs/scenarios/scenario5_data_quality.json (6 records).

The file mixes one valid record with five problems: an exact duplicate (record 2), a
timestamp without an offset (record 3), an invalid timestamp (record 4), a missing
EventId (record 5), and a failed logon with no user and no source address (record 6).

Command:

    python src/analyze.py sample-logs/scenarios/scenario5_data_quality.json --origin synthetic --out sample-reports/scenario5

### Facts (from the generated report)

- Data quality: 6 records, 3 usable events, 2 rejected, 1 duplicate removed, 1 naive
  timestamp assumed UTC, 1 event with missing core fields.
- Record 4 was rejected: invalid timestamp not-a-date. Record 5 was rejected: missing
  event id. Both appear as MALFORMED_RECORD findings (Informational).
- Record 6 appears as an INCOMPLETE_RECORD finding: the tool reports it as missing user.
- 6 findings, all Informational: 3 FAILED_LOGON (records 1, 3 and 6), 2 MALFORMED_RECORD,
  1 INCOMPLETE_RECORD.
- Record 6 also produced a FAILED_LOGON finding with user unknown and source
  unknown, with confidence High.
- The duplicate (record 2) is counted in the summary only; it has no finding of its own.
- Record numbers refer to the position in the input file, so record 2 is absent from the findings.

### Reading (interpretation, not proof)

- Problem records are counted and shown, not dropped silently: 2 rejected, 1 incomplete,
  1 duplicate removed.
- The High confidence on the FAILED_LOGON of record 6 reflects the event type only; it
  does not take the missing user and source into account. Data quality has to be read
  together with individual findings.
- The timestamp of record 3 was assumed to be UTC. If its real zone differs, its position
  relative to other events could change.

### Limits and possible improvements

- Duplicate removal covers exact copies only; near-duplicates are not detected.
- Lowering the confidence of findings built on incomplete records is a possible future change.

### What an analyst would check next

- Where the rejected and incomplete records came from (export tool, collector, field mapping).
- Whether the source system can export again with the missing fields.
- The time zone of the system that produced the record without an offset.
