# REST API & WebSocket Reference

The provisioner web server exposes a REST API and WebSocket endpoint for monitoring and control. All REST endpoints are prefixed with `/api/v1`.

Base URL: `http://<orangepi-ip>:8080/api/v1`

## Port Status

### GET /ports

Get status of all 6 provisioning ports.

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

Get status of a single port.

**Response:** Same shape as one element of the `/ports` array.

### POST /ports/{port_number}/identify

Re-run device fingerprinting on a port. Requires link to be up.

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

Trigger manual provisioning for a port.

**Request:**
```json
{
  "port_number": 1,
  "custom_password": "secret",
  "custom_username": "admin",
  "skip_firmware": false,
  "skip_config": false,
  "config_override": null
}
```

Only `port_number` is required. All other fields are optional.

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

## Credentials

### POST /credentials

Set a temporary credential override for a port. Cleared after use or on restart.

**Request:**
```json
{
  "port_number": 1,
  "username": "admin",
  "password": "secret",
  "device_type": "cambium"
}
```

### GET /credentials

List ports with credential overrides (passwords hidden).

### DELETE /credentials/{port_number}

Clear credential override for a port.

### GET /default-credentials

Get all credentials (custom + built-in) for all device types. Passwords are masked.

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
  "password": "newpassword"
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
- `device_type` — One of: `cambium`, `mikrotik`, `tachyon`, `tarana`

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
- `device_type` — One of: `cambium`, `mikrotik`, `tachyon`, `tarana`

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

**Connection:** `ws://<orangepi-ip>:8080/ws/status`

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
  "data": {},
  "timestamp": "..."
}
```

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
