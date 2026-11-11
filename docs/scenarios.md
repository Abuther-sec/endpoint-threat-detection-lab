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
