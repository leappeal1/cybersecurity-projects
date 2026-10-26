# Validation

Validated on Windows with Python 3.15 on 2026-10-26.

- Login Sentinel: 8 automated tests passed.
- Integrity Watch: 5 automated tests passed.
- Login sample: 11 synthetic events produced the expected three alerts.
- Integrity demo: detected one addition, one modification, and one deletion.

Tests cover detection windows, account/IP separation, suppression and rearming, input rejection, file changes, empty and nested files, and baseline overwrite protection. They do not establish production readiness or detection accuracy on real logs. The documented Python 3.10 minimum has not been separately tested. This execution environment required its temporary directory to be set to the writable workspace; the tests passed after that environment adjustment.
