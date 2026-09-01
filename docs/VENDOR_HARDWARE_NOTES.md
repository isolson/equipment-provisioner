# Vendor Hardware Notes

This page records verified hardware behavior that affects provisioning.
Use it with the [hardware provisioning SOP](hardware-provisioning-sop.md).

Add a note after a bench test confirms the behavior. Record the model, firmware,
operation, result, and date. Record field names and types. Never record secrets,
cookies, device passwords, wireless keys, or private addresses.

Keep raw HAR files and exports in the protected bench audit directory. Do not
commit them to Git. Use a sanitized trace for a code or documentation change.

## Tachyon

Applies to Tachyon TNA radio devices and TNS switches. Confirm the model before
you select a firmware or configuration asset.

### Config request shape

Tachyon uses HTTPS and a session token cookie.

- `GET /cgi.lua/config` returns the config document directly.
- `POST /cgi.lua/config` requires `{"data": <config-document>}`.
- A raw config document returns HTTP 400 with a configuration conversion error.
- The device can return HTTP 200 with an error object. Check the response body.
- Read the config after apply and compare non-secret fields.

The 2026-08-31 TNA-303L-65 HAR contains an accepted config POST with the
`data` wrapper. The handler applies this wrapper on both transport paths.

### Firmware 1.15.x config shape

Firmware 1.15.x uses a full export with these top-level keys:

`ethernet`, `network`, `services`, `system`, `version`, and `wireless`.

The `ethernet` section contains `ports`. The `network` section contains mode,
port-forwarding, routes, and zones. Do not place `ethernet` below `network`.

Some older exports omit fields that the 1.15.x device accepts as required
defaults. The handler fills these paths before apply:

- `system.description`, `system.latitude`, and `system.longitude`
- `services.cloud.enabled`
- `services.snmp_traps.port`
- `services.snmp.v3.ro.encryption_mode`
- `services.ssh.password_login`
- `network.zones.wan.lldp_forward`
- `network.zones.wan.carrier_drop`
- `network.zones.wan.dhcp.enabled_options`
- `ethernet.ports.eth0.network.mgmt_vlan_enabled`
- Radio VAP isolation and management VLAN fields

The checked-in TNA-303L-65 `SM/default.tar` template uses the old
`network.ethernet` location and lacks many full-export fields. The handler
moves that section to top-level `ethernet` and merges the archive with live
configuration. For this legacy archive path, list entries merge by index so
the device keeps required fields that the archive omits. New templates must
use the 1.15.x full-export shape.

Full exports contain per-device values and secrets. Do not copy a device export
into a tracked template without removing those fields and testing the result.

### Firmware update and reboot

Tachyon devices use two firmware banks. The handler uploads firmware with
`PUT /cgi.lua/update`, then starts the update with `POST /cgi.lua/update`.

The device reboots after the update. The handler waits for link recovery, logs
in again, and checks the active bank. Do not send an extra reboot command after
the update.

### Ping watchdog on an isolated bench

Tachyon exports include `services.ping_watchdog`. The watchdog can reboot a
device when its configured targets stay unreachable. An isolated bench can
trigger this condition even when the device and provisioner work correctly.

Separate these two symptoms:

- A repeating reboot and login cycle points to the device watchdog or another
  reboot cause.
- HTTP 400 from `/cgi.lua/config` points to the request or config shape.

Check the watchdog state and the device log before you treat a reboot as a
provisioning failure. Do not copy target addresses from one device export to
another device.

### Bench validation record

For a Tachyon change, capture these results:

- Login succeeds after a cold boot.
- Both firmware banks report the expected version.
- Config POST returns a success response.
- Config readback confirms non-secret fields.
- Firmware update reboots the device and the handler reconnects.
- A watchdog test does not hide the provisioning result.
