# Cambium ePMP Config API Reference

> **WARNING TO AI AGENTS AND DEVELOPERS**: Do NOT guess or assume Cambium API
> behavior. Every endpoint in this document is labeled CONFIRMED or UNCONFIRMED.
> If an endpoint is UNCONFIRMED, do NOT write code that uses it until it has been
> verified against an actual device using browser dev tools or curl. Cambium's
> web API is undocumented and varies by firmware version. Getting it wrong wastes
> deployment cycles.

## Authentication

All API calls require an authenticated session. Login returns a `stok` token
and sets a session cookie.

### Login — CONFIRMED

```
POST /cgi-bin/luci
Content-Type: application/x-www-form-urlencoded
Cookie jar: -c /tmp/cookies.txt

username=admin&password=admin
```

Response (HTML with embedded token):
```
stok token is extracted from redirect URL: /cgi-bin/luci/;stok={stok}/...
```

Session cookie: `sysauth_{ip}_{port}={session_id}`

---

## Endpoints

### config_import — Upload and apply config file (JSON or TAR) — CONFIRMED

> **Confirmed via HAR capture 2026-01-28.** This is the correct endpoint for
> applying full JSON config files. Previously we incorrectly used `set_param`
> for this, which fails with `success: 0` on large key sets.

```
POST /cgi-bin/luci/;stok={stok}/admin/config_import
Content-Type: multipart/form-data
Cookie: sysauth_{ip}_{port}={session}

Fields:
  skipIllegal = 1
  image = @filename.json (type: application/json)
```

Response:

```json
{"success": 1, "filepath": "/tmp/uploaded_file", "err": ""}
```

**After upload, config is applied asynchronously.** Poll for completion:

```
POST /cgi-bin/luci/;stok={stok}/admin/get_param
Content-Type: application/x-www-form-urlencoded

act=status&applyStatusNeeded=true&debug=true
```

Poll until response contains:
```json
{"template_props": {"applyFinished": 1}}
```

During apply, the response may contain `"initiatorState": {"import": true}`
indicating the import is still in progress.

**No reboot required.** Config takes effect once `applyFinished` = 1.

**curl example:**

```bash
curl -s -k --interface eth0.104 \
  -b /tmp/cookies.txt \
  -X POST \
  -F "skipIllegal=1" \
  -F "image=@f4518-sm-defaultconfig.json;type=application/json" \
  "https://169.254.1.1/cgi-bin/luci/;stok=abc123/admin/config_import"
```

**Key details:**
- `skipIllegal=1` tells the device to skip keys it cannot set (read-only,
  tables, hardware info, etc.) rather than rejecting the entire upload
- The `image` field name is required — this is the same field used for TAR uploads
- Works for both JSON config files and TAR backup archives
- The JSON file uses flat `device_props` key names directly (no wrapper needed)

---

### get_param — Read device config / status — CONFIRMED

Two modes:

**Status polling (used during config apply):**
```
POST /cgi-bin/luci/;stok={stok}/admin/get_param
Content-Type: application/x-www-form-urlencoded

act=status&applyStatusNeeded=true&debug=true
```

**Full config read (used for verification):**
```
POST /cgi-bin/luci/;stok={stok}/admin/get_param
Content-Type: application/x-www-form-urlencoded

act=config_regular&debug=true
```

Response:

```json
{
  "success": "1",
  "device_props": {
    "wirelessInterfaceSSID": "my-ssid",
    "snmpSystemName": "my-hostname",
    "systemConfigDeviceName": "my-hostname",
    "cambiumCurrentuImageVersion": "5.10.4",
    ...hundreds of keys...
  },
  "template_props": { ... }
}
```

---

### set_param — Write individual config fields — CONFIRMED (small key sets only)

```
POST /cgi-bin/luci/;stok={stok}/admin/set_param
Content-Type: application/x-www-form-urlencoded
Cookie: sysauth_{ip}_{port}={session}

changed_elements=<url-encoded JSON>&debug=true
```

JSON structure:

```json
{
  "device_props": {
    "wirelessInterfaceSSID": "my-ssid",
    "snmpSystemName": "my-hostname"
  },
  "template_props": {
    "config_id": "0"
  }
}
```

Response:

```json
{"result": {}, "success": 1, "err": ""}
```

**Known behavior:**
- Works for small sets of writable keys (SSID, hostname, password, etc.)
- Does NOT work for full config dumps (~273+ keys) — returns `success: 0, err: ""`
- No reboot required — changes take effect immediately
- Used by `apply_ap_naming()` for post-provisioning SSID/hostname changes

**Do NOT use this for full config apply. Use `config_import` instead.**

**curl example (small key set):**

```bash
curl -s -k --interface eth0.104 \
  -b /tmp/cookies.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "changed_elements=%7B%22device_props%22%3A%7B%22wirelessInterfaceSSID%22%3A%22test%22%7D%2C%22template_props%22%3A%7B%22config_id%22%3A%220%22%7D%7D&debug=true" \
  "https://169.254.1.1/cgi-bin/luci/;stok=abc123/admin/set_param"
```

---

## When to Use Which Endpoint

| Scenario | Endpoint | Notes |
|---|---|---|
| Apply full JSON config file | `config_import` | Multipart upload, skipIllegal=1, poll for applyFinished |
| Apply full TAR backup archive | `config_import` | Same endpoint, same flow |
| Change a few fields (SSID, hostname) | `set_param` | Form-encoded, immediate, no polling needed |
| Read current config | `get_param` | act=config_regular for full config, act=status for polling |
| Post-provisioning AP naming | `set_param` | Only 3 keys: SSID, snmpName, deviceName |

---

## How Config Apply Works (current implementation)

### Full config file (config_import path)
1. Template is loaded from `configs/templates/cambium/`
2. Model alias is resolved (e.g., `ePMP 4518` → `f4518-sm-defaultconfig`)
3. Files starting with `ap` are excluded (AP config is post-provisioning only)
4. JSON file is uploaded to `/admin/config_import` with `skipIllegal=1`
5. Poll `get_param` with `act=status&applyStatusNeeded=true` until `applyFinished=1`
6. Applied keys stored for verification

### Individual fields (set_param path)
1. Used by `apply_ap_naming()` and `apply_config()` (dict input)
2. Flat keys wrapped: `{"device_props": {...}, "template_props": {"config_id": "0"}}`
3. URL-encoded and POSTed to `/admin/set_param`
4. Response checked for `"success": 1`

**SM config is always used for provisioning. AP config is only applied
post-provisioning via `apply_ap_naming()`.**

---

## How Config Verify Works

1. POST to `/admin/get_param` with `act=config_regular&debug=true`
2. Parse `device_props` from JSON response
3. Compare values against what was applied:
   - `wirelessInterfaceSSID` → expected `ssid`
   - `snmpSystemName` → expected `hostname`
   - `systemConfigDeviceName` → expected `devicename`
4. Log pass/fail for each field

---

## Key Categories

### Settable via set_param (CONFIRMED)

| device_props key | Description |
|---|---|
| `wirelessInterfaceSSID` | Wireless SSID |
| `snmpSystemName` | SNMP system name |
| `systemConfigDeviceName` | Device name shown in UI |
| `admin_password` | Admin password |
| `wirelessInterfaceEncryptionKey` | WPA key |
| `crashReporterEnable` | Crash reporter (0/1) |

### Read-only (NOT settable via set_param)

These are handled automatically by `config_import` with `skipIllegal=1`.

| device_props key / pattern | Description |
|---|---|
| `cambiumCurrentuImageVersion` | Active firmware version |
| `cambiumCurrentuImageIVersion` | Inactive firmware version |
| `cambiumCurrent*`, `cambiumConnected*` | System state / connection info |
| `cambiumEffective*` | Computed effective values |
| `cambiumSystem*`, `cambiumHardware*` | Hardware identifiers |
| `cambiumLicense*` | License state |
| `*Table` | Table/list data (MAC filter, QoS rules, etc.) |
| `*Certificate`, `*Pem` | Certificate blobs |
| `*MacAddress`, `*SerialNumber` | Hardware IDs |
| `sysUpTime*`, `ethTx*`, `ethRx*` | Counters / statistics |
| `systemConfigSWLockBit`, `systemConfigHWLockBit` | Lock bits |

---

## Adding New Config Properties

1. Find the `device_props` key name (browser dev tools on Cambium web UI)
2. Add it to the JSON config template file
3. `config_import` with `skipIllegal=1` will apply it if settable, skip if not
4. If you need to set it individually (not via file upload), confirm it works
   with `set_param` and add to the "Settable" table above
5. Update this document

---

## Firmware Upload

See `provisioner/handlers/cambium.py` — firmware uses `/admin/flashops`
endpoint with multipart upload. This is separate from config.

---

## Debugging Tips

- Always check `journalctl -u provisioner -f` during provisioning
- `config_import` logs the full response including `filepath` and `err`
- The apply-status poll logs progress and final `applyFinished` state
- `set_param` failures log the full response body (up to 2000 chars)
- Use `curl` directly on the provisioner to test endpoints in isolation
- To capture new endpoint behavior, export a HAR file from browser dev tools

---

## Confirmation Log

| Date | Endpoint | How confirmed | Firmware |
|---|---|---|---|
| 2026-01-28 | `config_import` (JSON) | HAR capture from browser | 5.10.4 |
| 2026-01-28 | `get_param` (status poll) | HAR capture from browser | 5.10.4 |
| 2026-01-28 | `get_param` (config_regular) | HAR capture from browser | 5.10.4 |
| 2026-01-27 | `set_param` (small key set) | Provisioner logs | 5.10.4 |
| 2026-01-27 | Login (`/cgi-bin/luci`) | Provisioner logs | 5.10.4 |

---

*Last updated: 2026-01-28*
*This document is the source of truth for Cambium API behavior. Update it
when new endpoints or behaviors are confirmed on actual hardware.*
