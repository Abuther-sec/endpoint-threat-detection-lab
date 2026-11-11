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
