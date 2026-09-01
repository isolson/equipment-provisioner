# New Hardware Provisioning SOP

Use this procedure before you add hardware support or a field configuration to
the provisioner.

The procedure has four goals:

1. Record the intended device behavior.
2. Capture the vendor process and configuration format.
3. Prove the full provisioning path on hardware.
4. Leave enough evidence for another operator to repeat the result.

## 1. Record the intent

Create a short hardware intent record before you edit code or configuration.
Store the record in the pull request or in the project issue.

Record these items:

- Vendor, model, hardware revision, and supported firmware versions.
- Factory IP address, login method, and factory credential source.
- Initial provisioning role and all supported operating modes.
- Management VLAN, management protocol, address method, and DNS source.
- Required services, such as SNMP, syslog, NTP, SSH, and controller access.
- Wireless association policy, such as any compatible AP or a preferred AP list.
- Optional wireless profile behavior and security requirements.
- Fields that must stay unique per device, such as hostname, serial number, MAC address, BSSID, and static IP address.
- Fields that contain secrets, such as passwords, PSKs, SNMP communities, and private keys.
- The expected result after a reboot and after a firmware update.
- Whether the normal path must run without operator input.

Treat device names and wireless profiles as deployment data. The provisioner
must support the behavior that the selected deployment requires. It must not
require one site's names or number of profiles.

## 2. Capture the vendor process

Collect the source material before you build a configuration asset.

- Get the vendor API or export documentation.
- Capture one factory-default device before you change it.
- Capture one working device for each required firmware version.
- Capture one example for each role that uses different configuration.
- Capture a `.har` file during login, download, upload, apply, polling, reboot, and readback.
- Record the export format, firmware version, model, and capture date.

Store raw HAR files and source exports under `/var/lib/provisioner/audit/` on
the bench host. Keep this directory outside the Git checkout and web-served
directories. Set directory mode `0700` and file mode `0600`.

Use the service account as the owner of the audit directory. Keep raw files
only for the audit. Create a sanitized trace for the pull request. Delete raw
files after the pull request closes unless an owner records a reason and an
expiry date.

CAUTION: Do not attach raw HAR files or exports to issues or pull requests. They
can contain cookies, credentials, tokens, configuration bodies, and secrets.

Inspect source files with secret values masked. Record field names and value
types. Record secret presence, not secret values.

Use the HAR file to record the vendor process. Record the request method, URL
path, content type, request shape, response shape, status, and timing. Record
the authentication state without recording credentials or tokens.

Record the exact steps for configuration download and upload. Include the file
name, upload field, wrapper object, content type, apply request, and polling
request. Record the condition that ends polling and the condition that starts a
new login after a reboot.

Use this safe trace table:

| Step | Handler action | Method and path | Auth state | Body shape | Success or polling condition | Reconnect or retry |
| --- | --- | --- | --- | --- | --- | --- |
| Login |  |  | Present or absent |  |  |  |
| Download |  |  | Present or absent |  |  |  |
| Upload |  |  | Present or absent |  |  |  |
| Apply |  |  | Present or absent |  |  |  |
| Poll |  |  | Present or absent |  |  |  |
| Reboot |  |  | Present or absent |  |  |  |
| Readback |  |  | Present or absent |  |  |  |

## 3. Classify every field

Place each field in one of these groups:

| Group | Use | Examples |
| --- | --- | --- |
| Portable | Copy to every device in the same role | Management VLAN, DHCP mode, SNMP enable, syslog destination |
| Role-specific | Copy only to the selected role | AP radio mode, PTP side, optional profile list |
| Organization-specific | Keep in a protected runtime asset | PSKs, SNMP community, controller endpoint |
| Per-device | Generate or preserve for one device | Hostname, MAC, BSSID, serial number, static IP |
| Firmware-specific | Apply only when that firmware accepts it | Interface names, DHCP scope paths, radio fields |

Do not copy per-device fields from one device to every device. Do not place
organization-specific secrets in a tracked role overlay.

Compare exports from each supported firmware version. Record fields that moved,
changed type, or changed interface name. Treat a missing field as unknown until
the device accepts the resulting configuration.

## 4. Select the apply method

Classify the source as a full export or a reduced profile.

- A full export contains the device configuration document. If the vendor
  supports a full-document operation, apply the export with that operation.
- A reduced profile contains selected fields. If the handler supports this
  behavior, merge the profile with live configuration.
- A list value replaces the complete list under normal deep-merge semantics.
  Do not assume that list items merge by index.
- If a reduced profile touches a list, add vendor-specific merge behavior only
  after a hardware test proves the list semantics.

Do not infer a role from an SSID, model text, or a captured field. The selected
role is authoritative.

Keep vendor behavior in the vendor handler. Keep the shared provisioning engine
vendor-neutral. Follow [AGENTS.md](../AGENTS.md) and
[HANDLER_DEVELOPMENT.md](HANDLER_DEVELOPMENT.md).

## 5. Map the device modes

Define the relationship between the initial configuration and each operating
mode before you add mode code.

- Name the initial provisioning mode.
- List the available operating modes and their required input.
- Record which mode changes happen after initial provisioning.
- Record which values each mode changes, preserves, or replaces.
- Record how two devices pair for a point-to-point mode.
- Record how the operator returns a device to the initial mode.
- If modes use different configuration documents, use separate assets.

Do not assume that a mode changes only a name or an SSID. Use exports and HAR
files to identify every request and field that the vendor changes.

Use one transition row for each supported path:

| From | To | Trigger or input | Operation | Asset or request | Changes | Preserves | Reboot or reconnect | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SM | AP or PTP | Select the qualified AP or PTP action. | Apply the selected mode profile and verify the result. | The AP or PTP action request. | Mode fields and generated site identity. | The approved device identity and baseline policy. | Follow the handler result. | A verified AP or PTP mode. |
| AP or PTP | SM | Select **Restore SM config** in the port modal. | Apply the standard SM config and verify the result. | The resolved standard SM template. | SM policy fields and PTP state. | Device identity fields excluded by the template. | Follow the handler result. | A verified SM config with cleared PTP link state. |
|  |  |  |  |  |  |  |  |  |

Require separate hardware evidence for each advertised path. Use separate
assets only for vendor processes that require them.

## 6. Add the implementation

Select the implementation path that matches the change.

### Existing vendor configuration

- Add or update the configuration asset.
- Change the handler only for new vendor behavior.
- Add tests for the asset and the changed request behavior.
- Add hardware results for each affected role and firmware version.

### New model for an existing vendor

- Add the firmware filename pattern.
- If the device reports a different model name, add the model alias.
- If the model needs different configuration, add a model-specific asset.
- If the model needs a different flow, add a handler property.
- Test the new model and one existing model.

### New vendor

Follow the complete vendor checklist in
[HANDLER_DEVELOPMENT.md](HANDLER_DEVELOPMENT.md). Add the handler, detection,
registry entry, firmware data, configuration assets, tests, and hardware
results in one change.

Keep vendor behavior in the vendor handler. Do not add vendor names to shared
flow code. Do not add a new source of truth for vendor enumeration.

Use the data paths that the provisioner uses:

- Code: `/opt/provisioner/`
- Runtime data: `/var/lib/provisioner/repo/`
- Host configuration: `/etc/provisioner/config.yaml`

The deploy script copies code. It does not copy runtime configuration assets or
host configuration. Copy those assets through the setup flow or the documented
runtime procedure.

Load device credentials from protected host configuration. Do not place secret
values in command arguments, shell history, logs, or the pull request.

## 7. Prepare the bench

Create a rollback record before you change the device or bench.

Record these items:

- Current device configuration export.
- Current firmware version and firmware bank state.
- Current code revision and runtime asset.
- Current switch VLAN and host interface state.
- Open device sessions and the vendor session limit.
- The planned restore operation for the device and bench.

Complete these actions before you connect the device:

1. Install the target code on the bench host.
2. Install the target firmware in the runtime firmware directory.
3. Install the configuration asset in the runtime data directory.
4. Record the asset path, firmware version, and asset type.
5. Isolate the provisioning port from other device ports.
6. Connect only the device under test.

Stay below the vendor session limit. Reuse an existing session only after you
assess its state. If the vendor provides a logout operation, log out after each
completed workflow.

CAUTION: Do not reset a device until you save the current export and the test
has approval for the reset. A reset can remove the only working recovery path.

## 8. Run the hardware validation

If the vendor supports factory-state provisioning, run the full flow from
factory state.

If the intent record requires no-touch operation, provide no operator input
after you connect the device. Record every prompt as a failure until you classify
the prompt as an approved vendor requirement.

### Clean-device result

If the vendor supports this test, use a factory-default or known-clean device.

- Connect the device to an isolated provisioning port.
- Record the detected vendor and model.
- Record the factory address and login result.
- Record the reported firmware and hardware revision.
- Apply the selected role asset.
- Read the configuration back from the device.
- Record every required field that the provisioner created.
- Read the configuration again after a reboot.

Do not accept a clean-device result that passes only because the device already
contained the required values.

### Populated-device result

If the vendor supports this test, use a device with known configuration.

- Save the original configuration export.
- Apply the selected role asset.
- Read the configuration back from the device.
- Record every field that the device preserved, replaced, or removed.
- Explain every missing path as per-device, firmware-specific, unsupported, or secret.
- Read the configuration again after a reboot.

Use the full export or reduced profile semantics that the intent record defines.
If the handler merges reduced profiles with live data, run both results.

### Firmware result

- If the device is not at the target version, apply the target firmware.
- If the device has two banks, record the active bank and inactive bank.
- Wait for the device to reboot.
- Record that the handler reconnects after the reboot.
- Repeat the configuration result after the firmware update.

### Required service and network results

Record a pass or failure for each item that the intent record requires:

- Management VLAN and management protocol.
- DHCP address and DNS source.
- Management access after the device leaves the bench network.
- SNMP access with the required security level.
- Remote syslog delivery.
- NTP synchronization.
- Controller or management endpoint access.
- SSH access and Telnet state.
- Wireless association and radio mode.
- Optional wireless profiles and association behavior.

Read back the configuration after every mode transition. Use a separate result
for each mode and each supported firmware version.

## 9. Test configuration edge cases

If a case applies to the vendor, run the case:

- A full export with secrets.
- A reduced profile with no optional profile block.
- A reduced profile with one optional profile.
- A reduced profile with multiple optional profiles.
- A profile with equal priority values.
- A profile with different priority values.
- A firmware version with changed interface or address fields.
- An unsupported field that the vendor must skip.
- A model that requires a hardware-specific field and a model that does not.
- A captured static address or identity field that the handler must not copy.
- A failed readback after a successful HTTP response.
- A device reboot between apply and readback.

If the vendor exposes a priority field, apply priority tests. If the vendor
exposes a profile list, apply profile tests.

For a full export, validate that the apply request uses the vendor-supported
full-document operation. Do not send a full export through a per-field operation.

## 10. Record the result

Add this information to the pull request:

- Device model and hardware revision.
- Firmware before and after the test.
- Bench port and test date.
- Asset path and asset type.
- Role and deployment mode.
- Required fields and readback result.
- Services tested and result for each service.
- Reboot, reconnect, and mode transition results.
- Safe HAR trace table.
- Known limitations and rejected fields.
- Rollback plan and result.

Never include passwords, PSKs, private keys, SNMP communities, session tokens,
raw HAR files, raw exports, or customer identity values in the pull request.

## 11. Run the software gates

Run these commands from the repository root:

```bash
python3 scripts/check_py39.py
python3 scripts/check_templates.py configs/templates
python3 scripts/check_docs.py
python3 -m pytest -q
```

Run focused tests for the changed handler before the full test suite. Run
`git diff --check` before you commit.

The pull request is ready after the software gates pass, the hardware result is
repeatable, and the rollback path is documented.

## 12. Restore the bench

Use the rollback record after validation or after a failed test.

1. Restore the device configuration with the vendor-supported operation.
2. If the vendor supports firmware restore, restore the previous firmware or firmware bank.
3. If firmware restoration is not supported, mark the test as non-reversible and use a replacement bench device.
4. Restore the switch VLAN and host interface state.
5. Close device sessions.
6. If a feature branch was deployed, restore the production code revision.
7. If the test asset is not approved, restore the previous runtime asset.
8. Restart the service.
9. Read the service health endpoint.
10. Read the device configuration back and record the restore result.
11. Remove temporary exports, resolved configuration artifacts, and raw HAR files after the retention decision.

Use the documented deployment rollback procedure in
[BRANCHING.md](BRANCHING.md). Do not leave the production bench on an unapproved
feature branch.

## Reusable lessons

These lessons apply to every vendor audit:

- A HAR file records the vendor process. It does not prove that the provisioner matches the process.
- A downloaded file is not an upload contract until the bench accepts it.
- A full export and a reduced profile need different apply semantics.
- A successful HTTP response does not prove that the device accepted a field.
- A list merge can replace every existing item and silently remove required fields.
- A working export is evidence for one firmware version, not every firmware version.
- A changed interface or address path requires export comparison and a clean-device test.
- Optional profiles and association policy belong to the selected organization and role.
- A generic handler must preserve optional data without requiring one naming scheme.
- Management services need a readback after the device reboots.
- A vendor full-document operation must not use a per-field operation.
- A mode change needs separate evidence for each supported transition.
