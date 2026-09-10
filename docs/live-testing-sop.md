# Live Deployment and Hardware Test SOP

Use this procedure for a feature-branch deploy and a live hardware test.
Use one device on one isolated port. Keep the test reversible.

Related procedures:

- [Branching and Deployment Contract](BRANCHING.md)
- [Hardware Provisioning SOP](hardware-provisioning-sop.md)
- [Vendor Hardware Notes](VENDOR_HARDWARE_NOTES.md)

## 1. Define the test

Record these items before the deploy:

- Code branch and commit.
- Host, port, vendor, model, and firmware.
- Configuration asset and role.
- Expected service, device, and readback results.
- Stop conditions and the rollback command.

For the current Tachyon test, use port 4 and the TNA-303L-65 model. Skip
firmware when both device banks already contain the target version. Test the
configuration request first.

## 2. Capture the rollback point

Save the current device export in the protected audit directory. Set its file
mode to `0600`. Do not print the export.

Record the current code revision, configuration asset path, asset checksum,
firmware bank state, service state, and health response.

Run these commands from the repository root:

```bash
git status --short
git rev-parse --short HEAD
python3 scripts/check_py39.py
python3 scripts/check_templates.py configs/templates
python3 scripts/check_docs.py
git diff --check
```

Run the full test suite in the project test environment:

```bash
python3 -m pytest -q
```

If the local Python environment lacks a declared dependency, use the project
test environment. Record the command and result. Do not use `--skip-tests`
without a completed full test run.

Record the host state:

```bash
ssh -i ~/.ssh/id_conductor -o IdentitiesOnly=yes \
  serveradmin@192.168.10.50 \
  'cat /opt/provisioner/.deployed-rev; \
   systemctl is-active provisioner-web; \
   curl -sS -m 5 -o /dev/null -w "%{http_code}\n" \
   http://127.0.0.1:8080/health'
```

Do not include credentials, tokens, or raw device data in the test record.

## 3. Prepare the bench

Connect only the device under test to the isolated provisioning port.

Close other device sessions. Keep the switch VLAN and host interface state
unchanged unless the test requires a recorded change.

CAUTION: Do not reset the device before you save its export. A reset can remove
the only working recovery path.

Do not change the device watchdog for this test. Record its state instead.

## 4. Deploy the feature branch

Confirm the branch and dirty state before the deploy. A dirty deploy records a
`-dirty` marker on the host.

Run:

```bash
./scripts/deploy.sh --allow-branch
```

The script performs these actions:

1. Runs the full test suite.
2. Saves the current host tree at `/opt/provisioner.prev`.
3. Copies code to `/opt/provisioner/`.
4. Restarts `provisioner-web`.
5. Restarts the enabled kiosk watchdog.
6. Confirms service health, `/health`, and `/api/ports`.

The deploy script does not copy `/etc/provisioner/config.yaml` or the runtime
data repo at `/var/lib/provisioner/repo/`. Copy a changed asset separately,
after you save the old asset and record both checksums.

Stop if the deploy health check fails. Use the rollback procedure in section 7.

## 5. Run the live test

Confirm the deployed revision and service health:

```bash
ssh -i ~/.ssh/id_conductor -o IdentitiesOnly=yes \
  serveradmin@192.168.10.50 \
  'cat /opt/provisioner/.deployed-rev; \
   systemctl is-active provisioner-web; \
   curl -sS http://127.0.0.1:8080/health'
```

Confirm detection and login from the dashboard. Then start one provisioning
job through the dashboard, or send a request without credential fields:

```bash
curl -sS -X POST http://192.168.10.50:8080/api/provision \
  -H 'Content-Type: application/json' \
  --data '{"port_number":4,"skip_firmware":true}'
```

Confirm these results in order:

1. Port 4 detects Tachyon and TNA-303L-65.
2. Login succeeds.
3. Firmware stays unchanged when `skip_firmware` is true.
4. Config POST returns success.
5. Config readback confirms non-secret fields.
6. The port reports `success` or `COMPLETE`.

For the Tachyon fix, inspect the service log for the config result. The log
must not contain HTTP 400 from `/cgi.lua/config`.

If the device reboots, wait for one normal reconnect. Stop the test if the
device enters a repeating reboot cycle or loses its management path.

## 6. Run the firmware test

Run this section only after the configuration test passes.

Record both bank versions and the active bank. Use the target firmware asset.

Start one firmware update. Confirm that the device reboots, reconnects, logs
in, and reports the expected active bank.

Read the configuration after the firmware update. Record the result separately
from the configuration-only test.

For a watchdog with a five-minute interval, observe the device for at least
thirty minutes. Record every reboot and the related device log entry.

## 7. Roll back

Roll back code when the service fails health, the handler causes an unknown
device result, or the test reaches a stop condition.

Restore the immediately previous code tree:

```bash
./scripts/deploy.sh --rollback
```

Confirm the rollback revision, service state, and health endpoint. Then restore
the device configuration with the vendor-supported operation.

Code rollback does not restore device configuration or firmware.

If the test changed a runtime asset, restore the saved asset in
`/var/lib/provisioner/repo/` and record its checksum. Restart the service after
the asset restore.

If firmware restore is not supported, mark the test as non-reversible. Use a
replacement bench device for the next test.

After rollback, confirm that the device returns to its recorded management
state. Record the rollback result before you close the test.

## 8. Close the test

Record the branch, deployed revision, device result, service result, readback
result, reboot count, and rollback result.

Remove temporary resolved files and raw captures after the retention decision.
Keep only the sanitized trace. Do not commit secrets or device identity data.

After a feature-branch test, deploy the approved `production` branch to return
the host to the production code pin.
