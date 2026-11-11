# Investigation methodology

A repeatable way to go from a report of this lab to a written conclusion. It is a study
framework built from the five scenarios in docs/scenarios.md; it is not a company
procedure and its thresholds are starting points, not measured values.

## 1. Check the data before the findings

- Is the data origin synthetic or real? Real data stays out of the repository.
- Read the Data quality table first: rejected records, duplicates removed, naive
  timestamps assumed UTC, events with missing core fields (scenario 5).
- Ask what is missing: time range, computers, event IDs that were never exported.

## 2. Triage the findings

- Start with High and Medium findings, then read the Informational ones in groups.
- Read severity and confidence separately: severity is how much attention the pattern
  deserves, confidence is how well the evidence supports it.
- Read the printed reasons. They say why a rating was given and, as in scenario 3,
  what the rule did not look at.

## 3. Pivot on the entities

For each finding that needs attention, collect around three anchors:

| Anchor | Questions |
|---|---|
| User | Which other events involve this account, before and after? |
| Source address | Which other accounts and computers does it touch? Is it known? |
| Time | What happened just before and just after the window? |

## 4. Correlate across events

The tool rates events one by one (scenario 4), so the analyst links them:

- Failures followed by a success for the same user and source (scenario 3), also beyond
  the 300 s look-ahead.
- Account creation, group change and log clearing close together (scenario 4).
- One source against many accounts, or many failures against one account (scenarios 1 and 2).

## 5. Separate facts from hypotheses

Write two lists. Facts come from the report and the raw events. Hypotheses are
explanations that fit the facts, each with what would confirm or reject it. Words such
as "attack" or "compromise" are not used for a hypothesis that is not confirmed.

## 6. Decide and record

Choose one outcome and give the reason:

| Outcome | When |
|---|---|
| Benign explanation found | A known cause matches the evidence (for example a mistyped password). |
| Escalate | The evidence fits an unauthorized action and cannot be explained otherwise. |
| Need more data | The log cannot answer the question (for example the log was cleared). |

Record: what was seen, what was checked, what was concluded, what is still unknown.

## Investigation note template

    Finding / scenario:
    Data origin and quality notes:
    Facts (with record numbers):
    Hypotheses (and what would confirm or reject each):
    Checks done:
    Outcome (benign / escalate / need more data) and reason:
    Still unknown:

## Limits

- The rules are fixed and simple; accuracy has not been measured.
- A finding is an observation to review, not proof of an attack.
- Records without a time zone offset are assumed to be UTC.
- The scenarios use synthetic data only; no claim is made about real networks.
