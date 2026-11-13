# Endpoint Threat Detection & Network Analysis Lab

A lightweight, defensive home lab for Windows event log analysis and network traffic
investigation, built with Python (standard library only) and Wireshark.

> Status: work in progress. Everything stated here comes from commands that were run;
> what was not measured is listed under Limitations.

## What it does

- Reads exported Windows security events (JSON) and normalizes them.
- Applies configurable detection rules and rates each finding by severity and confidence,
  with the reasons printed.
- Writes reports as JSON, CSV and Markdown.
- Documents five SOC scenarios on synthetic data and the analysis of two public PCAP files.

It runs on a low-specification Windows 10 PC. All published data is synthetic or public.

## Quick start (Windows PowerShell)

    git clone <repository-url>
    cd endpoint-threat-detection-lab
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    python src\analyze.py sample-logs\scenarios\scenario1_bruteforce.json --origin synthetic --out sample-reports\scenario1

The report files are written to the folder given by --out: security_report.json,
security_report.csv and security_report.md.

## Command-line options

| Option | Meaning | Default |
|---|---|---|
| input | JSON file of events | required |
| --origin | synthetic or real | required |
| --out | output folder | output |
| --window | seconds for the repeated-failure window | 60 |
| --repeat-threshold | failures needed for REPEATED_FAILED_LOGONS | 5 |
| --multi-user-threshold | users needed for MULTIPLE_USERS_FROM_SOURCE | 3 |
| --success-window | seconds to look for a success after a burst | 300 |

With --origin real the tool only writes into output/, which is git-ignored.

## Detection rules (defaults)

| Rule | What it flags |
|---|---|
| FAILED_LOGON | Each failed logon (event 4625) |
| REPEATED_FAILED_LOGONS | 5 or more failures for one user and source within 60 s |
| MULTIPLE_USERS_FROM_SOURCE | 3 or more different users failing from one known source within 60 s |
| IMPORTANT_EVENT | Events 1102, 4720, 4732, 4740, 7045 (configurable) |
| MALFORMED_RECORD | A record that was rejected (for example an invalid timestamp) |
| INCOMPLETE_RECORD | A usable record that lacks a core field (for example the user) |

Each finding gets a severity (Informational, Low, Medium, High) and a confidence (Low,
Medium, High) with printed reasons. For example, a success for the same user within 300 s
after a burst of failures raises the rating. Details: docs/detection-rules.md.

## Results (from runs of this repository)

| Scenario | Input records | Findings |
|---|---|---|
| 1. Repeated failures, one account | 9 | 10: 1 Medium, 9 Informational |
| 2. One source, several accounts | 8 | 9: 1 Medium, 8 Informational |
| 3. Success after repeated failures | 14 | 14: 1 High, 1 Medium, 12 Informational |
| 4. Account creation, group change, log clear | 4 | 4: 1 High, 2 Medium, 1 Low |
| 5. Dirty input | 6 | 6 Informational; 2 rejected, 1 duplicate removed |

Details, readings and what is not determined: docs/scenarios.md.

Tests: 73 unit tests, all passing at the last run; coverage 99% (463 statements, 2 not
covered, both known and left on purpose).

## Testing

    pip install -r requirements-dev.txt
    python -m unittest discover -s tests
    coverage run -m unittest discover -s tests
    coverage report

## Project structure

    src/            log_parser, detection_engine, severity, report_generator, analyze
    tests/          unit tests for each module
    sample-logs/    synthetic input, including five scenario files
    sample-reports/ reports generated from the synthetic input
    docs/           scenarios, PCAP analysis, investigation method, ATT&CK mapping

## Documentation

- docs/scenarios.md: five SOC scenarios, facts and interpretation kept apart
- docs/pcap-analysis.md: two public PCAP samples read with tshark
- docs/investigation-methodology.md: how to go from a finding to a conclusion
- docs/mitre-attack-mapping.md: candidate ATT&CK techniques, one still unverified
- docs/detection-rules.md: rules, thresholds and rating logic

## Security and privacy

- Only synthetic data and public sample captures are published.
- Real logs, PCAP files, credentials and keys are excluded through .gitignore.
- Reports name the input file only, not its full path, and CSV cells that could be read
  as formulas are neutralized.
- All testing is local and authorized.

## Limitations

- The rules are fixed and simple; their detection accuracy has not been measured.
- Events are rated one by one; there is no rule that links events in sequence.
- A success after failures is looked for only within 300 s.
- The input format has a single user field, so actor and target are not separated.
- Findings are observations that need review, not proof of an attack.
- Two small public PCAP files were analyzed by hand; the PCAP work is not part of the tool.

## Future work

- A rule that links related events in sequence (for example account creation, group
  change, log clearing).
- Lower confidence for findings built on incomplete records.
- A Wazuh-based lab after a memory upgrade; Kali for further network exercises.
- Verify the remaining ATT&CK technique (T1070.001) against the official page.

## What this project practices

- Reading Windows security events and writing detection logic in Python
- Testing and measuring code coverage
- Writing reports that separate facts from interpretation
- Reading network captures with Wireshark and tshark
- Mapping findings to MITRE ATT&CK as hypotheses, with sources

## License

MIT License. See the LICENSE file.
