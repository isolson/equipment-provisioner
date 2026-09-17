# Evidence Capture Runbook

One page per capture. Use it with `docs/BENCH_EVIDENCE.md` (rules) and
`docs/EVIDENCE_CONTRIBUTING.md` (issue and PR flow). Every value the
provisioner writes must trace to a capture made this way.

## Before you start

1. Cable the unit directly to your laptop, not to a bench port. The bench
   auto-provisions on detection and changes a factory unit.
2. Open the browser developer tools, Network tab. Turn on "Preserve log".
   Start the recorder before the first login.
3. Write down the model, serial location (not the serial), and the firmware
   shown after login. Use a bench unit label such as `unit-4518-b`.
4. One operation per capture when possible. A combined capture is fine when
   it covers the full flow in order (name it `workflow.har`).

## The five artifacts

| Artifact | When | File name |
| --- | --- | --- |
| No-config backup | Right after the first login on a factory unit, before any change except a forced first-boot password | `no-config.device-backup.json` (Cambium) or `.tar` (Tachyon) |
| Upgrade capture | The firmware upload, status polling, and reboot | `upgrade.har` |
| Config-apply capture | The configuration import or apply, polling, and post-apply read | `config-apply.har` |
| Known-good backup | Export after a successful apply and reboot | `known-good.device-backup.json` or `.tar` |
| Capture summary | Generated from the HAR with your notes | `capture-summary.md` |

## Cambium ePMP (4518, 4616, 4625, Force 300)

1. Log in. On a factory unit the UI forces a password and WPA2 key first.
   Complete it. The capture will show `set_param` and `set_account_params`.
2. Export the configuration now. The request is `config_export`. Save it as
   the no-config backup.
3. Upload the target firmware. On 5.10.x the UI calls `local_upload_image`
   and polls `get_upload_status`. On 5.11 and newer it calls
   `upload_sw_image_local`, `upgrade_sw_image_local`, and polls
   `get_upgrade_status`. Reboot. Upload once more after the reboot so both
   banks are current, then reboot again.
4. Import the known-good SM export for the model family (`config_import`),
   then reboot.
5. Export the configuration again. Save it as the known-good backup.
6. Save the HAR. A factory reset, when needed, is `reset_to_def` with
   `mask=1` then `reboot`.

## Tachyon TNA (301, 302, 303X, 303L)

1. Log in. Export the configuration backup (`.tar` with `config.json`).
   Save it as the no-config backup.
2. Upload the target firmware and reboot. Log in again.
3. Apply the family SM configuration (or the AP profile for an AP unit).
   Wait for the read-back. Reboot.
4. Export the backup again. Save it as the known-good backup.
5. Check the export for the 1.15 fields before you call it good:
   SNMP trap port, SNMPv3 encryption mode, VAP `isolate`, `latitude`. An SM
   export must keep its AP profile list. An empty list means re-check.

## Ubiquiti Wave

1. Log in. Export the backup before any change. Save it as the no-config
   backup.
2. Upgrade and reboot. Apply the baseline. The management VLAN transition
   must be captured with the reconnect on the new VLAN, or it is not proven.
3. Export the backup again. Save the HAR.

## After the capture

1. Copy the raw files to the bench host:
   `/var/lib/provisioner/bench-evidence/<vendor>/<model>/<firmware>/`
   (root-owned, directories `700`, files `600`). Keep a copy in
   `~/bench-evidence-staging/`. Never put raw files in the checkout.
2. Generate the summary:
   `python scripts/summarize_har.py <capture.har> --out bench-evidence/<vendor>/<model>/<firmware>/capture-summary.md --title "<model>: <what it did> (<date>)" --note "<fact>"`.
   Copy the summary beside the HAR on the host.
3. Generate the fixtures:
   `python scripts/redact_bench_fixture.py --vendor <vendor> --model "<model>" --firmware <firmware> --kind no-config --source <raw backup>`
   and again with `--kind known-good`.
4. Write or update `manifest.yaml`. Record `fixture_witness`,
   `no_config_backup`, and any `transitions` you ran.
5. Run `python scripts/check_bench_evidence.py --vendor <vendor> --model "<model>" --firmware <firmware>` on the host, then `pytest`.
6. Open the PR (`docs/EVIDENCE_CONTRIBUTING.md`).

## Do not

- Do not paste HAR or backup content into chat, an issue, or a PR.
- Do not treat an AP capture as an SM baseline, or one model's export as
  another model's evidence.
- Do not accept a clean-device pass when the device already had the values.
