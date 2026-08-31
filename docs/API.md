# REST API & WebSocket Reference

The provisioner web server exposes a REST API and WebSocket endpoint for monitoring and control. REST endpoints use the `/api` prefix. WebSocket status updates use `/ws/status`.

Base URL: `http://<host>:8080/api`

## First-Run Setup

### GET /setup/readiness

Returns a first-run readiness checklist for the current bench.

This report covers:

- host config and env files
- management VLAN interface presence
- primary and custom credentials
- default config templates
- shared Cambium SM baseline
- local firmware inventory
- MikroTik provisioning switch state for the six provisioning ports, WAN uplink, and host trunk

### POST /setup/bundle/import

Import a setup bundle archive into the local provisioner filesystem layout.

Accepted bundle formats:

- `.zip`
- `.tar`
- `.tar.gz`
- `.tgz`

Supported bundle contents:

- `configs/...`
- `firmware/...`
- `credentials.json`
- `manifest.yaml`
- `settings/config.yaml` or root `config.yaml`
- `settings/provisioner.env` or root `provisioner.env`

Multipart form fields:

- `file` - the archive
- `apply_system_files` - `true` to apply the bundled `config.yaml` and `provisioner.env` files to `/etc/provisioner/`

**Warning:** These files can contain credentials. Import them only on a trusted host.

### GET /setup/bundle/export

Export the current bench state as a portable `.zip` bundle.

Query parameters:

- `include_system_files=true` to include `/etc/provisioner/config.yaml` and `/etc/provisioner/provisioner.env`

Protected runtime config assets, including Cambium field deployment exports,
are omitted from the bundle. The bundle can still contain
`credentials.json` and optional system files. Export only to a trusted host.

### GET /config-assets

List installed configuration assets. Use `device_type`, `family`, `firmware`,
`role`, `mode`, `scope`, and `config_type` as optional filters.

Protected assets return metadata only. Their content is not returned by the
list endpoint or by `GET /config-assets/content`.

### GET /config-assets/metadata

Return the registry-derived family, role, mode, scope, and asset-kind choices
for the upload form. This endpoint works on a new install with no assets.

### POST /config-assets/upload

Upload a standard template or a Cambium field deployment export.

Multipart form fields:

- `file` - the configuration file
- `config_type` - `template` or `override`
- `device_type` - a provisionable device type
- `family` - the model family for a family asset
- `firmware` - the firmware version
- `role` - `AP`, `SM`, or `PTP`
- `mode` - `ap`, `sm`, `ptp-a`, or `ptp-b`
- `profile` - an AP profile or PTP side profile
- `link_profile` - a PTP link profile
- `scope` - `family` or `shared`
- `asset_kind` - `standard` or `field_export`

For `field_export`, the file must be a native Cambium JSON export with
`device_props` and `template_props`. The role is required. Shared SM exports
must use `scope=shared`, `mode=sm`, and a firmware version. AP and PTP exports
must use a family and firmware; PTP exports also require link and side
profiles. The response includes metadata such as firmware version, property
count, and whether protected fields were found. It does not include secret
values or the protected source file.

### POST /setup/switch/configure

Run the MikroTik provisioning-switch setup flow non-interactively.

This is intended for a directly connected, defaulted MikroTik switch. It applies the six-port provisioning layout with a WAN uplink and a host trunk:

- `ether1-ether6` provisioning ports
- `ether7` WAN uplink
- `ether8` trunk to the host

**Request:**
```json
{
  "ip": "192.168.88.1",
  "username": "admin",
  "password": "<switch-password>",
  "skip_password_change": false
}
```

### POST /setup/templates/seed

Copy bundled repo templates from `configs/templates/` into the live data store.

**Request:**
```json
{
  "overwrite": false
}
```

### POST /setup/restart-service

Schedule a delayed `systemctl restart provisioner-web` so imported system files can take effect without shell access.

## Port Status

### GET /ports

Returns the status of all six provisioning ports.

**Response:**
```json
[
  {
    "port_number": 1,
    "vlan_id": 1991,
    "link_up": true,
    "device_detected": true,
    "device_type": "cambium",
    "device_ip": "169.254.1.1",
    "device_model": "ePMP 3000",
    "provisioning": false,
    "last_activity": null
  }
]
```

### GET /ports/{port_number}

Returns the status of one port.

**Response:** Same shape as one element of the `/ports` array.

### POST /ports/{port_number}/identify

Runs device fingerprinting again on a port. The port must have link-up status.

**Response:**
```json
{
  "device_detected": true,
  "device_type": "cambium",
  "device_ip": "169.254.1.1"
}
```

## Provisioning

### POST /provision

Starts manual provisioning for a port.

**Request:**
```json
{
  "port_number": 1,
  "custom_password": "<device-password>",
  "custom_username": "admin",
  "skip_firmware": false,
  "skip_config": false,
  "config_override": null,
  "role": null
}
```

Only `port_number` is required. All other fields are optional.

`role` selects a site-role config overlay for this job (an opaque string, for
example `tower`). When omitted or `null`, the server falls back to
`provisioning.default_role` in `config.yaml`; when neither is set, the job runs
role-less resolution. See
[HANDLER_DEVELOPMENT.md](HANDLER_DEVELOPMENT.md) "Site-Role Config Overlays".

**Response:**
```json
{
  "success": true,
  "job_id": null,
  "message": "Provisioning started for port 1"
}
```

**Errors:**
- `404` — Port not found
- `400` — No device detected on port
- `409` — Port already provisioning
- `503` — Provisioner not available

### POST /netinstall

Starts MikroTik Netinstall on a port. The device must be in BOOTP/Netinstall
listening mode.

The pipeline fetches the fleet credentials and two scripts from the configured
backend. It flashes RouterOS, verifies the base-flash and phone-home state, and
registers the device. The device has no internet path during this process.

The pipeline also verifies the ship-ready response. It clears stale role-lock
or check-in-secret state and repeats registration when required.

The per-port BOOTP listener calls this endpoint when it detects Netinstall mode.
An operator normally does not call it directly. See
[mikrotik-netinstall.md](mikrotik-netinstall.md).

**Request:**
```json
{
  "port_number": 5
}
```

**Response:**
```json
{
  "success": true,
  "job_id": null,
  "message": "Netinstall started for port 5"
}
```

The request returns immediately. The Netinstall pipeline runs in the
background and normally takes two to four minutes. Progress appears in the
checklist and WebSocket events used by other provisioning operations.

**Errors:**
- `404` — Port not found
- `409` — Port already provisioning
- `503` — Provisioner not available

## Credentials

### POST /credentials

Sets a temporary credential override for a port. The override is cleared after
use or when the service restarts.

**Request:**
```json
{
  "port_number": 1,
  "username": "admin",
  "password": "<device-password>",
  "device_type": "cambium"
}
```

### GET /credentials

List ports with credential overrides (passwords hidden).

### DELETE /credentials/{port_number}

Clear credential override for a port.

### GET /default-credentials

Returns all custom and built-in credentials for all device types. Passwords are masked.

**Response:**
```json
[
  {
    "device_type": "cambium",
    "username": "admin",
    "password_hint": "*****",
    "is_custom": false,
    "index": -1
  }
]
```

### GET /default-credentials/{device_type}

Get credentials for a specific device type.

### POST /default-credentials/{device_type}

Add a custom credential for a device type. Persisted to `credentials.json`.

**Request:**
```json
{
  "username": "admin",
  "password": "<device-password>"
}
```

### DELETE /default-credentials/{device_type}/{index}

Delete a custom credential by index. Built-in credentials cannot be deleted.

## Firmware Management

### GET /firmware

List all firmware files on disk, organized by device type.

**Response:**
```json
[
  {
    "device_type": "cambium",
    "filename": "ePMP-3000-v4.7.1.bin",
    "version": "4.7.1",
    "size": 15728640,
    "modified": "2026-01-25T10:30:00",
    "path": "firmware/cambium/ePMP-3000-v4.7.1.bin"
  }
]
```

### POST /firmware/upload

Upload a firmware file. Multipart form data.

**Form fields:**
- `file` — The firmware binary
- `device_type` — One of: `cambium`, `mikrotik`, `tachyon`, `tarana`, `ubiquiti`

### POST /firmware/url

Download firmware from a URL to the local store.

**Request:**
```json
{
  "url": "https://example.com/firmware.bin",
  "device_type": "cambium",
  "filename": "ePMP-v4.7.1.bin"
}
```

`filename` is optional; auto-detected from the URL if omitted.

### DELETE /firmware/{device_type}/{filename}

Delete a firmware file.

## Config Management

### GET /configs

List all config files (templates and overrides).

**Response:**
```json
[
  {
    "device_type": "cambium",
    "filename": "default.json",
    "config_type": "template",
    "size": 4096,
    "modified": "2026-01-25T10:30:00",
    "path": "configs/templates/cambium/default.json"
  }
]
```

### GET /configs/{config_type}/{device_type}/{filename}

Read a config file's content. For JSON files, returns both raw content and parsed object.

`config_type` is `template` or `override`.

### POST /configs/upload

Upload a config file. Multipart form data.

**Form fields:**
- `file` — The config file (`.json`, `.rsc`, `.yaml`, `.tar`, `.tar.gz`)
- `config_type` — `template` or `override`
- `device_type` — One of: `cambium`, `mikrotik`, `tachyon`, `tarana`, `ubiquiti`

JSON files are validated before saving.

### PUT /configs/{config_type}/{device_type}/{filename}

Update a config file's content in place.

**Request:**
```json
{
  "content": "{\"wirelessInterfaceSSID\": \"tower-01\"}"
}
```

### DELETE /configs/{config_type}/{device_type}/{filename}

Delete a config file.

## Snapshots

Config snapshots captured from devices (R3 of the config-resolution epic).
Every response is **redacted** at a single choke point on the server: secrets
never leave the service. `identity.wireless.psk` is replaced by
`psk_present`/`psk_length`, the raw vendor blob is replaced by a
`content_present` marker, and any identity field not explicitly classified
public is omitted and listed in `redacted_fields`. There is **no** HTTP write
endpoint — snapshots are written in-process by the capture path.

### GET /snapshots

List snapshots, newest first.

**Query parameters** (all optional): `vendor`, `serial_number`, `mac_address`
filters; `limit` (default 50, maximum 200); `offset` (default 0).

Corrupt or newer-schema files on disk are skipped and counted in
`skipped_unreadable`.

### GET /snapshots/{id}

Get one snapshot, masked per the redaction map.

**Errors:**
- `404` — Unknown or invalid snapshot id
- `409` — Snapshot has a newer schema version than this service reads
- `422` — Snapshot file is corrupt or unreadable (it can still be deleted)

### DELETE /snapshots/{id}

Delete a snapshot. Allowed even for corrupt or newer-schema files, so manual
cleanup always works regardless of retention.

**Errors:**
- `404` — Unknown snapshot id

## System

### GET /status

Get overall system status.

**Response:**
```json
{
  "running": true,
  "mode": "vlan",
  "uptime_seconds": 3600.0,
  "total_ports": 6,
  "active_ports": 3,
  "devices_detected": 2,
  "provisioning_in_progress": 1
}
```

### GET /device-types

Get list of supported device types and their firmware file extensions.

### GET /test

Health check endpoint. Returns `{"status": "ok"}`.

## Switch Integration

### POST /switch/port-event

Receive port link-state webhooks from the MikroTik switch. This enables immediate device detection without polling.

**Request:**
```json
{
  "port": "ether1",
  "link_up": true,
  "speed": "1Gbps"
}
```

### GET /switch/port-mapping

Get the mapping of MikroTik port names (e.g., `ether1`) to provisioner port numbers (1-6).

## Display Control

### POST /display/sleep

Put the kiosk display to sleep (blank screen).

### POST /display/wake

Wake the kiosk display.

### GET /display/status

Get display state and configuration.

**Response:**
```json
{
  "available": true,
  "sleeping": false,
  "sleep_timeout": 300,
  "wake_on_connect": true
}
```

---

## WebSocket

### WS /ws/status

Real-time status updates over WebSocket.

**Connection:** `ws://<host>:8080/ws/status`

On connect, the server sends an `initial_status` message with all port states. The server then broadcasts updates every 2 seconds (when clients are connected) and immediately on state changes.

### Server → Client Messages

All messages are JSON with a `type` field and `timestamp`.

#### `initial_status`
Sent once on connection. Contains full port state snapshot.
```json
{
  "type": "initial_status",
  "data": {
    "ports": {
      "1": {"vlan_id": 1991, "link_up": true, "device_detected": true, ...},
      "2": {"vlan_id": 1992, "link_up": false, ...}
    },
    "running": true
  },
  "timestamp": "2026-01-28T10:30:00"
}
```

#### `status_update`
Periodic full status broadcast (every 2s when clients are connected).
Same shape as `initial_status`.

#### `port_update`
Single port status change.
```json
{
  "type": "port_update",
  "port_number": 1,
  "data": {"link_up": true, "device_detected": true, "device_type": "cambium", ...},
  "timestamp": "..."
}
```

#### `provisioning_started`
```json
{
  "type": "provisioning_started",
  "port_number": 1,
  "device_type": "cambium",
  "job_id": 42,
  "timestamp": "..."
}
```

#### `provisioning_progress`
```json
{
  "type": "provisioning_progress",
  "port_number": 1,
  "job_id": 42,
  "step": "firmware_upload",
  "progress": null,
  "timestamp": "..."
}
```

#### `provisioning_completed`
```json
{
  "type": "provisioning_completed",
  "port_number": 1,
  "job_id": 42,
  "success": true,
  "data": {
    "message": "Complete",
    "label": {
      "type": "mikrotik_netinstall",
      "serial": "HKC0TEST123",
      "mac": "04:f4:1c:c2:06:80",
      "model": "hAP ax S",
      "copies": 1
    }
  },
  "timestamp": "..."
}
```

`data.label` is optional and currently emitted only for successful MikroTik
Netinstall runs after wifi-api registration and ship-ready assertions pass,
when `label_printer.enabled` is true.

#### `credentials_required`
Login failed; UI should prompt for credentials.
```json
{
  "type": "credentials_required",
  "port_number": 1,
  "device_type": "cambium",
  "device_ip": "169.254.1.1",
  "error": "Invalid credentials",
  "timestamp": "..."
}
```

#### `display_state`
```json
{
  "type": "display_state",
  "sleeping": true,
  "timestamp": "..."
}
```

### Client → Server Messages

#### `ping`
Server replies with `{"type": "pong"}`.

#### `subscribe`
Subscribe to specific update channels (currently all clients receive all updates).
```json
{"type": "subscribe", "channels": ["ports", "jobs"]}
```

#### `request_status`
Request an immediate full status update (same as `status_update`).
```json
{"type": "request_status"}
```
