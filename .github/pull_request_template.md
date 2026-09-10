## Change type

- [ ] Bug fix
- [ ] Handler or provisioning behavior
- [ ] New vendor or model
- [ ] Configuration template
- [ ] Documentation or tooling

## Verification

- [ ] `python scripts/check_docs.py`
- [ ] `python scripts/check_py39.py`
- [ ] `python scripts/check_templates.py`
- [ ] `python scripts/check_bench_evidence.py --all --repo-only`
- [ ] `pytest`

## Hardware verification

Complete this section for a new vendor, new model, new endpoint, firmware
change, configuration change, or verification change. Capture with
`docs/EVIDENCE_RUNBOOK.md`; flow in `docs/EVIDENCE_CONTRIBUTING.md`.

- Model and firmware:
- Evidence check command:
- Bench result:
- Confirmed behavior recorded in the vendor document:
- Regression test:

- [ ] The manifest identifies the exact model and firmware.
- [ ] The secure bench directory contains the upgrade and configuration-apply
  HAR files.
- [ ] The secure bench directory contains the no-configuration and known-good
  device backups.
- [ ] The repository contains redacted structure fixtures and a capture summary only.
- [ ] Every changed template or handler value has a fixture witness (`values` map).
- [ ] No credentials, tokens, keys, PSKs, serials, or private network data are
  in this pull request.

## Notes

Describe any missing hardware evidence or follow-up bench work.
