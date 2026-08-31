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
- Factory IP address, login method, and factory credentials source.
- Device roles, such as SM, AP, Main, or PTP SM.
- Management VLAN, management protocol, address method, and DNS source.
- Required services, such as SNMP, syslog, NTP, SSH, and controller access.
- Wireless association policy, such as any compatible AP or a preferred AP list.
- Wireless security requirements and optional profile behavior.
- Fields that must stay unique per device, such as hostname, serial number, MAC address, BSSID, and static IP address.
- Fields that contain secrets, such as passwords, PSKs, SNMP communities, and private keys.
- The expected result after a reboot and after a firmware update.
- Whether the normal path must run without operator input.

Treat device names and wireless profiles as deployment data. The provisioner
must support the device behavior that the selected deployment requires.
It must not require one site's names or number of profiles.

## 2. Gather source evidence

Collect the source material before you build a configuration asset.

- Get the vendor API or export documentation.
- Capture one factory-default device before you change it.
- Capture one working device for each required firmware version.
- Capture one example for each role that uses different configuration.
- Capture a `.har` file during login, download, upload, apply, polling, reboot, and readback.
- Record the export format, firmware version, model, and capture date.
- Keep the original exports in protected runtime storage.
- Keep the original `.har` file in protected runtime storage.

Use the `.har` file to record the vendor process. Record the request method,
URL path, content type, request shape, response shape, status, and timing.
Remove cookies, credentials, tokens, and secret values from any working copy.

Record the exact steps for configuration download and upload. Include the file
name, upload field, wrapper object, content type, apply request, and polling
request. Record whether the vendor uses a full import or a per-field operation.

Use a working export as evidence, not as a ready-made portable template. A
working export can contain device identity, static addresses, and secrets.

CAUTION: Do not commit customer exports or real secrets. They can expose device
access, wireless access, or private network data.

Inspect source files with secret values masked. Record field names and value
types. Record secret presence, not secret values. Do not treat a downloaded
file as a valid upload until the bench accepts it.

## 3. Classify every field

Place each field in one of these groups:

| Group | Use | Examples |
| --- | --- | --- |
| Portable | Copy to every device in the same role | Management VLAN, DHCP mode, SNMP enable, syslog destination |
| Role-specific | Copy only to the selected role | AP radio mode, PTP side, station-profile list |
| Organization-specific | Keep in a protected runtime asset | WPA2 PSKs, SNMP community, controller endpoint |
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
  supports native import, apply the export with that operation.
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

The selected mode is authoritative. Do not infer it from a device name, SSID,
model text, or an existing field.

## 6. Add the implementation

Follow the existing vendor checklist before you add a new handler or model.

- Add or update the handler and its class properties.
- Add detection evidence and preserve probe order.
- Add the vendor registry entry and firmware source data.
- Add the firmware filename pattern.
- If the device reports a different model name, add the model alias.
- Add the correct configuration asset for each role.
- Add unit tests for pure logic and HTTP request behavior.
- Add a hardware validation report to the pull request.

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

Before you connect a device, complete these actions:

1. Install the target code on the bench host.
2. Install the target firmware in the runtime firmware directory.
3. Install the configuration asset in the runtime data directory.
4. Record the asset path, firmware version, and asset type.
5. Back up the current runtime asset and device export.
6. Isolate the provisioning port from other device ports.
7. Connect only the device under test.
8. Close unused device sessions before you open a new session.

If the device supports four sessions, keep no more than four sessions open. If
the device supports five sessions, keep no more than five sessions open. If the
vendor provides a handler logout operation, use it.

CAUTION: Do not reset a device until you save the current export and the test
has approval for the reset. A reset can remove the only working recovery path.

## 8. Run the hardware validation

If the vendor supports factory-state provisioning, run the full flow from
factory state.

If the intent record requires no-touch operation, provide no operator input
after you connect the device. Record every prompt as a failure until you classify
the prompt as an approved vendor requirement.

### Detection and login

- Connect the device to an isolated provisioning port.
- Record the detected vendor and model.
- Record the factory address and login result.
- Record the reported firmware and hardware revision.

### Firmware

- If the device is not at the target version, apply the target firmware.
- If the device has two banks, record the active bank and inactive bank.
- Wait for the device to reboot.
- Record that the handler reconnects after the reboot.
- Repeat the configuration test after the firmware update.

### Configuration

- Apply the selected role asset.
- Record the apply operation and its result.
- Read the configuration back from the device.
- Compare the source and readback property paths.
- Explain every missing path as per-device, firmware-specific, unsupported, or secret.
- Compare every required field with the intent record.
- Record secret presence without recording secret values.
- Read the configuration again after a reboot.

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
- Optional wireless profiles, association behavior, priorities, and security.

The validation must use the correct role asset. An AP test does not prove an SM
profile. An SM test does not prove a PTP side.

## 9. Test configuration edge cases

If a case applies to the vendor, run the case:

- A full export with secrets.
- A reduced profile with no optional profile block.
- A reduced profile with one optional profile.
- A reduced profile with multiple optional profiles.
- A profile with equal priority values.
- A profile with different priority values.
- A firmware version with changed interface or DHCP fields.
- An unsupported field that the vendor must skip.
- A model that requires a hardware-specific field and a model that does not.
- A captured static address or identity field that the handler must not copy.
- A failed readback after a successful HTTP response.
- A device reboot between apply and readback.

For a full export, validate that the apply request uses the native import
operation. Do not send a full export through a per-field operation.

## 10. Record the result

Add this information to the pull request:

- Device model and hardware revision.
- Firmware before and after the test.
- Bench port and test date.
- Asset path and asset type.
- Role and deployment profile.
- Required fields and readback result.
- Services tested and result for each service.
- Reboot and reconnect result.
- Known limitations and rejected fields.
- Rollback asset path.

Never include passwords, PSKs, private keys, SNMP communities, session tokens,
or customer identity values in the pull request.

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

After validation, complete these actions:

1. If the test asset is not approved, restore the previous runtime asset.
2. If a feature branch was deployed, restore the production code revision.
3. Restart the service.
4. Read the service health endpoint.
5. Remove temporary exports and resolved configuration artifacts.
6. Keep only the approved protected runtime asset and the test report.

Use the documented deployment rollback procedure in
[BRANCHING.md](BRANCHING.md). Do not leave the production bench on an unapproved
feature branch.

## Reusable lessons

These lessons apply to every vendor audit:

- A full export and a reduced profile need different apply semantics.
- A successful HTTP response does not prove that the device accepted a field.
- A list merge can replace every existing item and silently remove required fields.
- A working export is evidence for one firmware version, not every firmware version.
- A changed interface or address path requires export comparison and a clean-device test.
- Optional profiles belong to the selected organization and role.
- A generic handler must preserve optional profile data without requiring one naming scheme.
- Management services need a readback after the device reboots.
- A vendor full-import operation must not use a per-field operation.
- A mode change needs its own asset and hardware result when it changes more than identity.

For vendor-specific rules, read [cambium-config.md](cambium-config.md),
[HANDLER_DEVELOPMENT.md](HANDLER_DEVELOPMENT.md), and the vendor API
documentation before you change an apply operation.
