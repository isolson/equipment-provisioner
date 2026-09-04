---
name: Bench evidence capture
about: Request or record a device capture (HAR, no-config backup, known-good backup)
title: "evidence: <vendor> <model> <firmware>: <what is missing>"
labels: bench-evidence
---

## Record

- Vendor:
- Model (exact, as the device reports it):
- Firmware (running, and target):
- Bench unit label (not the serial):
- Record path: `bench-evidence/<vendor>/<model>/<firmware>/`

## What is missing

Tick what this issue will produce. See `bench-evidence/INVENTORY.md`.

- [ ] no-config backup
- [ ] upgrade capture (`upgrade.har`)
- [ ] config-apply capture (`config-apply.har`)
- [ ] known-good backup
- [ ] capture summary
- [ ] bench transition(s): fresh->sm / sm->ap / ap->sm / sm->ptp / ptp->sm

## Capture plan

Follow `docs/EVIDENCE_RUNBOOK.md`. Note anything that differs.

## Result

- Raw files copied to the host secure directory: yes / no
- `check_bench_evidence.py` on the host: OK / problems
- Summary and fixtures generated: yes / no
- PR:

Do not paste HAR or backup content here.
