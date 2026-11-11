# MITRE ATT&CK mapping (candidates)

Purpose: show how the lab's findings may relate to ATT&CK techniques, without claiming
that any technique was used.

## Method and rules

- Each technique was read on attack.mitre.org on 2026-11-12. The ATT&CK version number
  was not recorded.
- A mapping means "may correspond to": a hypothesis for the analyst, never proof.
- Where a page does not mention an event ID, the link from the lab's event to the
  technique is my reading, not MITRE's, and the table says so.
- A row marked "Not verified" is listed only so the gap is visible.

## Mapping table

| Scenario | Lab observation | Candidate technique | Tactic as listed on the page | Status |
|---|---|---|---|---|
| 1 | Many failed logons for one account from one source | T1110.001 Brute Force: Password Guessing | Credential Access | Verified |
| 2 | One source, several accounts, few attempts each | T1110.003 Brute Force: Password Spraying | Credential Access | Verified |
| 3 | Success after repeated failures | T1078 Valid Accounts (only if the success is unauthorized) | Stealth, Persistence, Privilege Escalation, Initial Access | Verified, weak fit |
| 4 | Account creation (4720) | T1136.001 Create Account: Local Account | Persistence | Verified; local or domain account is unknown |
| 4 | Group membership change (4732) | T1098.007 Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | Verified; event link is my reading |
| 4 | Security log cleared (1102) | Candidate T1070.001 Clear Windows Event Logs | not read | Not verified |
| 4 | Account lockout (4740) | none | - | No mapping made |
| 5 | Dirty input | not applicable | - | - |

## What the pages say (read on 2026-11-12)

- T1110.001: adversaries with no prior knowledge of legitimate credentials may guess
  passwords. Its detection text cites a series of authentication failures (event 4625).
- T1110.003: a single or small list of commonly used passwords is tried against many
  accounts, which avoids the lockouts that brute forcing one account would cause. The
  page names event 4625 and notes that LDAP or Kerberos authentication may avoid it.
- T1078: abuse of credentials of existing accounts. The page does not mention events
  4624 or 4625; its Windows detection idea is about logon patterns and logon types.
- T1136.001: creating a local account to keep access. Its detection text links event
  4720 to the earlier start of a suspicious process such as net.exe or PowerShell.
- T1098.007: adding local or domain groups to an adversary-controlled account. The page
  names no Windows event IDs.

## Caveats

- The lab has no process-creation data, so the 4720 context that the T1136.001 page
  describes cannot be checked.
- The data does not say whether the account in scenario 4 was adversary-controlled, so
  T1098.007 stays a hypothesis.
- The lab's own reasons note benign explanations: a mistyped password finally corrected
  (scenario 3) and routine administration (scenario 4).
- T1070.001 could not be verified: the official page could not be fetched in this
  session. It stays unverified until the page is read.
- The lab flags events. It does not detect techniques.

## Source

- https://attack.mitre.org/techniques/T1110/001/
- https://attack.mitre.org/techniques/T1110/003/
- https://attack.mitre.org/techniques/T1078/
- https://attack.mitre.org/techniques/T1136/001/
- https://attack.mitre.org/techniques/T1098/007/
