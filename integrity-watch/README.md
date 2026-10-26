# Integrity Watch

A file-integrity monitoring CLI for a cybersecurity portfolio. Python 3.10+; no third-party dependencies.

## Problem and approach

Unexpected configuration changes can indicate mistakes or compromise. This project establishes a SHA-256 baseline and reports files added, modified, or deleted in later scans. It reads monitored files without modifying them.

Pipeline: directory → chunked SHA-256 hashing → baseline JSON → later scan → comparison report.

## Quick demo

Open a terminal in this project folder:

```sh
python demo.py
python -m unittest -v
```

The demo copies the sample files into a temporary directory, modifies a configuration, deletes a policy, and adds a new file. It prints and saves `sample-report.json` with one added, one modified, and one deleted file. The original demo files remain unchanged.

## Monitor a directory

```sh
python integrity.py baseline demo-files --baseline baseline.json
python integrity.py check demo-files --baseline baseline.json --json report.json
```

The first check should report two unchanged files. Edit a file in `demo-files`, run the check again, and inspect the result. Run this walkthrough on a fresh copy if you want to preserve the original examples.

Exit codes: 0 = baseline created or no content changes, 1 = changes detected, 2 = error. Skipped paths are reported separately; code 0 does not mean all possible filesystem objects were checked.

Baseline files cannot be overwritten by the baseline command. To accept an intentional change, review it and create a new baseline under a new filename. Baselines and reports must be stored outside the monitored directory; reports cannot overwrite the baseline. A baseline is tied to its original absolute target path.

## Design decisions

- Hash file contents in 1 MiB chunks rather than loading an entire file into memory.
- Compare hashes, so same-size changes are detected.
- Treat a rename as an addition and a deletion.
- Skip symbolic links, special files, and directory junctions recognized by the Python runtime. Python 3.12+ is recommended on Windows for junction detection.
- Fail on unreadable files rather than silently marking them unchanged.
- Check file metadata before and after hashing to catch common concurrent writes.
- Preserve the baseline with exclusive file creation.

## Demonstrate in your portfolio

1. Show the initial baseline and clean scan.
2. Run the isolated demo and explain all three change categories.
3. Explain why hashes detect same-size edits better than file sizes alone.
4. Show tests covering nested and empty files, malformed baselines, overwrite protection, and content changes.
5. Discuss how a production system would authenticate and protect its baseline.

Suggested description after running and understanding it: “Implemented a SHA-256 file-integrity monitor with baseline management, added/modified/deleted file detection, JSON reports, and automated validation of filesystem edge cases.”

## Limitations and next steps

Changes are evidence, not proof of malicious activity. This is a one-shot scanner, not a real-time agent. The baseline is unsigned: someone able to modify both files and baseline can conceal changes. Keep the baseline in a separately protected location. Permissions, ownership, alternate data streams, and empty-directory changes are not monitored. Metadata checks are not an atomic snapshot and do not defeat adversarial race conditions or all concurrent edits. Use this lab tool on ordinary, idle directories. Next steps: signed baselines, filesystem snapshots, scheduled scanning, and alert integrations.
