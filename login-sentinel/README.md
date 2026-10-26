# Login Sentinel

An offline authentication-log analyzer for a cybersecurity portfolio. Built with Python 3.10+ and the standard library; no installation or external service is required.

## Problem and approach

Authentication logs are noisy. This project normalizes CSV records, orders events by timestamp, and correlates failures in an inclusive sliding time window. It produces explainable triage alerts rather than declaring that an account is compromised.

Pipeline: CSV → validation → chronological ordering → per-source/per-account windows → console and JSON alerts.

## Run

Open a terminal in this project folder:

```sh
python sentinel.py sample-auth.csv --json sample-report.json
python -m unittest -v
```

The synthetic sample contains 11 events and produces three alerts:

```text
[MEDIUM] repeated_failures | 198.51.100.23 | admin
[HIGH] success_after_failures | 198.51.100.23 | admin
[MEDIUM] password_spray | 203.0.113.8 | sam
```

Exit codes: 0 = no alerts, 1 = alerts found, 2 = input or execution error. A return code of 1 is expected for the demo.

## Rules

| Rule | Default trigger | Investigative next step |
|---|---|---|
| Repeated failures | Five failures against the same username from the same IP within ten minutes | Check source, user history, and lockout events |
| Password spray | Failures against four distinct users from one IP within ten minutes | Check shared NAT/proxy context and account targeting |
| Success after failures | Success after five failures against the same account from the same IP in the window | Validate the login with the user and review session activity |

Use `--threshold`, `--minutes`, and `--spray-users` to tune the rules. Continuous failure bursts generate one alert per rule/key; a rule rearms when its window falls below threshold. Successful-login alerts clear that account's failure history; source-level spray history remains.

## Input contract

Required columns: `timestamp,source_ip,username,outcome`. Timestamps must include a UTC offset or Z. IPv4 and IPv6 are accepted; outcomes are `success` or `failure`. Invalid rows fail the whole import with a row number. Usernames are case-sensitive. The parser does not directly ingest Windows Event XML, syslog, or vendor-specific schemas.

## Demonstrate in your portfolio

1. Run the provided sample and capture the console output.
2. Explain how a rolling window differs from a fixed time bucket.
3. Change the failure threshold and compare the alerts.
4. Discuss false positives: forgotten passwords, shared IPs, and automated services.
5. Show tests for time boundaries, duplicate-alert suppression, distinct users, invalid data, and account/source isolation.

Suggested description after running and understanding it: “Implemented a Python authentication-log analyzer with configurable sliding-window detections for repeated login failures, password spraying, and suspicious successful logins, with structured JSON evidence and automated tests.”

## Limitations and next steps

This is a batch lab tool, not a production SIEM. It loads the input in memory and retains per-key queues; large exports require streaming and eviction. Duplicate input records are not removed. It cannot detect distributed attacks across many IPs or low-and-slow activity outside the window. Severity is a heuristic. Next steps: streaming adapters, account-aware baselines, deduplication, and evaluation against a labeled dataset. All supplied data is synthetic; no real incidents or accuracy benchmarks are claimed.
