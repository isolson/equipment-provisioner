# Contributing Evidence: Issue to PR

How a capture becomes a committed record. Read `docs/EVIDENCE_RUNBOOK.md`
for the capture itself and `docs/BENCH_EVIDENCE.md` for the rules.

## 1. Open the issue

Use the "Bench evidence capture" issue template. Name the exact model and
firmware, the record path, and which artifacts the issue will produce. The
current gap list is `bench-evidence/INVENTORY.md`.

## 2. Capture

Follow the runbook. Copy raw files to the bench host secure directory and to
`~/bench-evidence-staging/`. Raw files never enter the checkout.

## 3. Branch and generate

```bash
git checkout -b evidence/<vendor>-<model>-<firmware>
python scripts/summarize_har.py <capture.har> --out bench-evidence/<vendor>/<model>/<firmware>/capture-summary.md --title "..." --note "..."
python scripts/redact_bench_fixture.py --vendor <vendor> --model "<model>" --firmware <firmware> --kind no-config --source <raw>
python scripts/redact_bench_fixture.py --vendor <vendor> --model "<model>" --firmware <firmware> --kind known-good --source <raw>
```

Write `manifest.yaml`. Set `fixture_witness` (`baseline` or `role`),
`no_config_backup` (`captured` or `missing`), `raw_files`, and
`transitions` for every bench run you completed.

## 4. Check

```bash
python scripts/check_bench_evidence.py --all --repo-only
python scripts/check_templates.py configs/templates
python scripts/check_docs.py
pytest -q
```

On the host: `sudo -n python scripts/check_bench_evidence.py --vendor <vendor> --model "<model>" --firmware <firmware>`.

## 5. Change values only through the record

If the capture changes a template or handler value, change the fixture
first, then the template or table, and let `tests/test_cambium_evidence.py`
(or the vendor's equivalent) prove they agree. A PR that changes a value
without a fixture witness is refused.

## 6. Open the PR

Base `main`. Fill the "Hardware verification" section of the PR template
with the model, firmware, the evidence check command, and the bench result.
Link the issue. The PR must contain only the manifest, the summary, the
redacted fixtures, and any template or test change. Reviewers check that no
credential, token, key, PSK, serial, or private address is in the diff.

## 7. After merge

Promote `main` to `production` and deploy from a production checkout
(`docs/BRANCHING.md`). Copy changed templates into the host repo directory.
Close the issue with the record path.
