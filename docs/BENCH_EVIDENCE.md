# Bench Evidence SOP

Use this procedure for device API, firmware, configuration, and verification
work. Read the evidence before you change a handler. A prose contract does not
replace a capture from the device.

Use `docs/EVIDENCE_RUNBOOK.md` for the per-vendor capture steps,
`docs/EVIDENCE_CONTRIBUTING.md` for the issue and PR flow, and
`bench-evidence/INVENTORY.md` for the current gap list.

## Evidence has two locations

Keep the evidence index and redacted structure in git. Keep raw captures and
device backups in the secure evidence directory on the bench host.

The default bench-host directory is:

```text
/var/lib/provisioner/bench-evidence/
```

Set `PROVISIONER_BENCH_EVIDENCE_ROOT` when a development machine uses a mounted
copy. The repository contains the redacted index under
[`bench-evidence/`](../bench-evidence/README.md). The deploy script excludes
HAR files and `.context` files.

## Current Tachyon bench records

The exact final-firmware record for `TNA-303L-65` on `1.15.1 rev 8541` is
indexed at `bench-evidence/tachyon/TNA-303L-65/1.15.1-rev-8541/`. The secure
bench host has the transition HAR and the known-good post-apply backup at the
matching raw path. The exact pre-first-apply no-config backup is still
missing. Do not mark this evidence set complete until that baseline is
captured.

The 303L record is also process evidence. Its secure HAR and backups may
contain device or site identity. They are not templates. The separately
bundled 303L SM asset is a sanitized library asset, not a copy of the raw
backup, and still requires the evidence and hardware gates below.

The exact final-firmware record for `TNA-301` on `1.15.1 rev 55177` is
indexed at `bench-evidence/tachyon/TNA-301/1.15.1-rev-55177/`. The secure
bench host has the transition HAR and the supplied with-config TAR at the
matching raw path. The exact no-config backup and a post-apply device backup
are still missing. Do not mark this evidence set complete until both backups
are captured.

The TNA-301 record documents the overall upgrade and config-apply process. It
is an AP-configured, tower/customer-specific capture. It is process evidence,
not a canonical config template, and must not be copied into the standard
asset library. Do not use it as the default config for TNA-302. TNA-301 and
TNA-302 share a firmware/config family, but TNA-301 upload packaging defaults
to AP and TNA-302 upload packaging defaults to SM. TNA-303X remains
role-ambiguous and requires an explicit mode. An AP asset also needs a
directional profile when the library has directional profiles. Standard
provisioning remains the verified SM baseline until an operator selects a
post-provision AP profile.

The supplied Wave Nano HAR is indexed at
`bench-evidence/ubiquiti/Wave-Nano/unknown/`. It records setup, configuration,
upgrade, and reboot requests. Its configuration has
`network.interfaces.data.mgmtVLAN: null`; it does not prove the VLAN-12
transition. The firmware version and device backups are also missing. Keep it
as process evidence only. Do not use it as a canonical template.

This PR defines the current Tachyon support scope as TNA-301, TNA-302,
TNA-303X, and TNA-303L. The checked-in records provide process evidence for
TNA-301 and TNA-303L. Do not claim hardware validation for TNA-302 or TNA-303X
until their model-specific evidence is captured and checked in. TNA-305X,
TNA-305A, and TNS-100 are out of scope until their evidence exists.

Use this layout in both locations:

```text
<vendor>/<model>/<firmware>/
  manifest.yaml
  capture-summary.md          # redacted request sequence + what the capture did
  upgrade.har
  config-apply.har
  # Use workflow.har when one capture covers both operations.
  reset.har                   # optional
  no-config.device-backup.json
  known-good.device-backup.json
  no-config.structure.json
  known-good.structure.json
```

`capture-summary.md` is committed in the repository record and copied beside
the raw HAR on the bench host. It is the first thing to read. It names the
endpoints, form fields, status codes, and firmware the device reported. It
never contains a credential, token, key, or body.

The four raw files are sensitive. Store them only in the secure bench
directory. The two `*.structure.json` files are redacted fixtures. Commit them
with the manifest when they contain no credentials, tokens, keys, PSKs, serials,
or private network data.

Use separate `upgrade.har` and `config-apply.har` files, or use one
`workflow.har` file when it contains both complete operations. Keep the original
capture name in the manifest notes.

## Required evidence for a new model

Before a new model handler or model-specific template is complete, capture:

1. A successful upgrade flow. Include login, upload, status polling, reboot,
   and the first post-reboot status request.
2. A successful configuration-apply flow. Include the configuration read,
   apply request, status polling, and the post-apply read.
3. A no-configuration device backup captured before the first apply.
4. A known-good provisioned device backup captured after a successful apply.
5. Redacted request and response structure fixtures derived from the captures.

Reuse a capture only when the model, firmware, API family, and operation match.
Record that reuse in the manifest. Capture a new flow when any of those values
change or when the device rejects a request.

The no-configuration backup is a baseline. Do not replace it with a backup from
a device that already received a configuration.

## Management VLAN transition

A device management VLAN is different from the provisioner's isolation VLAN.
The default bench switch path carries each device on one isolated VLAN, such as
1991–1996. It does not automatically carry a device's internal management VLAN
12.

When a model requires a management VLAN, encode that requirement in the
sanitized model baseline and the workflow. Do not make a technician remember
the setting or enter it as an optional site value. Keep customer, tower, IP,
and credential values outside that baseline.

Before enabling a device management VLAN, confirm all of these items:

1. The switch port has the required tagged and untagged membership.
2. The bench host has a VLAN 12 interface with a valid source address.
3. The handler binds probes and API requests to that interface after the
   transition.
4. A post-apply read-back or reconnect test proves the device is reachable.

If any item is not proven, stop before the apply step. Do not mark the model
baseline as ready. Record the transition as unvalidated process evidence.

For a Tachyon radio, capture the complete management-tag set. Include the
wired port and the station backhaul. Do not infer one field from another. The
handler must preserve the coherent set from the sanitized baseline or a
verified export.

## Current Cambium bench records

Known-good SM export records exist for `ePMP 4518` and `ePMP 4616` on `5.11.1`
(`fixture_witness: baseline`) and for `Force 300-25` on `5.11.1`
(`fixture_witness: role`). Their `values` maps are the source for the family
SM baselines and the handler role table. The `ePMP 4518` record also has a
factory no-config backup (5.10.4, after only the forced first-boot password
and WPA2 key). It proves the factory radio role is already SM, that antenna
gain and GPS priority are hardware defaults, and that nine fleet-policy
fields differ at factory, so a clean-device result cannot pass by accident.
No bench transition is recorded yet, so no Cambium post-provision mode is
offered. The Force 300-25 record also indexes the reset process HAR.

## Fixture values and witnesses

Structure fixtures at `fixture_version: 2` carry a `values` map. Generate it
with `scripts/redact_bench_fixture.py`. The map holds only `fleet_policy`,
`role`, and `device_default` fields; device-default keys that look dynamic
(address, name, serial, MAC, identity) are skipped. Secrets never appear.

Set `fixture_witness: baseline` when the export came from a unit that
received our baseline. Set `fixture_witness: role` for a working field radio
with other policy values; it witnesses only the role set and device defaults.

## Bench acceptance protocol

Run this list per model and firmware on one unit, on the dev bench host,
before any `transitions:` row is written:

1. Reset the unit. Capture `no-config.device-backup.json`. Provision SM. Read
   back and diff against the known-good values. The `fleet_policy` and
   `role` diff must be empty. Device defaults must equal the no-config
   capture. Record `fresh->sm`.
2. `sm->ap`, then `ap->sm`. Read back after each. Record any `mode_action`
   field that persisted after the return to SM as a finding.
3. `sm->ptp` (side A and side B with a partner), then `ptp->sm`. Same checks.
4. Standard provisioning from an AP unit and from a PTP unit (not restore).
5. Run `check_bench_evidence.py` on the host, `redact_bench_fixture.py`, and
   commit the manifest and fixtures.

## Manifest

The manifest is versioned. It identifies the evidence without storing a device
serial or a secret.

```yaml
vendor: tachyon
model: TNA-303L-65
firmware: 1.15.1-rev-8541
config_role: SM
unit: unit-a
captured_utc: 2026-08-31T00:00:00Z
artifact_purpose: process-evidence
reusable_template: false
canonical_template_status: not-included
operations:
  - upgrade
  - config-apply
result: success
notes: "Record the confirmed endpoint or schema fact."
```

Use a bench unit label, such as `unit-a`, in the manifest. Do not use a serial
number in a committed file.

Set `config_role` to the role of the captured upload (`AP`, `SM`, or `PTP`).
For AP captures, record the directional profile when it is known. The model
and firmware family are separate facts: a shared family does not make every
model an AP. Use the handler's model hint only for known models and record an
explicit mode for ambiguous models.

Record bench transitions under `transitions:` as
`{from, to, result}` with `from`/`to` in `fresh`, `sm`, `ap`, `ptp` and
`result` in `success`, `failure`. A later `failure` row withdraws the
transition. Declare `no_config_backup: missing` while the exact
pre-first-apply backup is outstanding; the record then needs no `no-config`
fixture and `fresh->sm` stays unproven.

Set `artifact_purpose: process-evidence` and `reusable_template: false` for
raw HAR and device-backup records. These files prove the device process. They
are not config templates. A capture can contain customer names, tower names,
SSIDs, credentials, or other device identity. `canonical_template_status`
records whether a separate sanitized template exists. Keep that template in
the approved asset tree only after it has been reviewed and bench-tested.

Check evidence before handler work:

```bash
python scripts/check_bench_evidence.py \
  --vendor tachyon \
  --model TNA-303L-65 \
  --firmware 1.15.1-rev-8541
```

Run the command on the bench host for the full check. Run it with
`--repo-only` in a checkout when the raw evidence is not mounted. The command
reports file names and metadata only. It does not print HAR or backup content.
On the bench host, run the command with `sudo -n` because the raw evidence root
is root-owned.

## Capture procedure

1. Reset the unit to the required baseline.
2. Start the browser network recorder before login.
3. Perform one complete operation without unrelated browser actions.
4. Export the HAR before closing the recorder.
5. Export the device backup before and after the operation.
6. Copy the raw files to the matching secure evidence directory.
7. Set directory mode to `700` and file mode to `600`.
8. Run `scripts/summarize_har.py` on the capture. Add `--note` lines that say
   what the capture did and what it proves. Commit the summary in the record
   and copy it beside the raw HAR on the host.
9. Add the manifest and redacted structure fixtures to the repository.
10. Record confirmed facts in the vendor development document and cite the
    capture by record path.

When packaging a structured upload, provide the detected model to the asset
upload path. The registry derives the family and the handler derives a known
model default role. Supply an explicit role or mode for models that support
multiple roles, and supply the AP direction/profile when required. A family
name that disagrees with the model is rejected.

Do not upload the raw capture as the canonical package. Create a separate
sanitized asset with only reusable model, family, role, and profile values.
Keep customer and tower identity in the job-specific mode-rendering path.

Do not paste raw HAR or backup content into chat, issues, or pull requests.
Do not place raw files in the repository checkout. Use the secure evidence
directory on the bench host.

## Agent troubleshooting procedure

When a device rejects an operation, an agent must:

1. Read this SOP and the relevant vendor development document.
2. Run `check_bench_evidence.py` for the exact model and firmware.
3. Read the manifest and `capture-summary.md` before opening a raw capture.
   The summary usually answers the endpoint question without the HAR.
4. Compare the captured method, endpoint, fields, body shape, status, and
   response structure with the handler.
5. Compare the live configuration with the no-configuration and known-good
   structure fixtures.
6. Record only redacted facts in the repository.
7. Add a regression test for each confirmed device behavior.
8. Run the full test gate before another bench deployment.

If required evidence is missing, stop endpoint or payload guessing. Request a
capture from the bench or perform the capture on the bench. Keep vendor
behavior in the vendor handler and keep raw evidence outside runtime code.

## Review checklist

For a new model or hardware API change, review these items:

- The exact model and firmware appear in `manifest.yaml`.
- The captured upload role and AP profile are recorded when known.
- Upgrade and configuration-apply HAR files exist in the secure bench path.
- Both device backups exist in the secure bench path.
- Redacted structure fixtures contain no private data.
- Raw files are not tracked by git and are not in the pull request.
- The vendor document records the confirmed behavior.
- A regression test covers each confirmed behavior.
- The Python 3.9, template, documentation, and full test gates pass.
- The pull request records the bench result without device secrets.
