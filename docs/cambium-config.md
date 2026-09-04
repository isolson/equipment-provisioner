# Cambium ePMP Config API Reference

Store and review new Cambium captures by following the
[Bench Evidence SOP](BENCH_EVIDENCE.md). The endpoint notes below are derived
from hardware captures; raw files belong in the secure bench evidence
directory.

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

username=<device-user>&password=<device-password>
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
  tables, and hardware information) rather than rejecting the entire upload
- The `image` field name is required — this is the same field used for TAR uploads
- Works for both JSON config files and TAR backup archives
- A native full export uses the `device_props` and `template_props` wrapper
- A small partial template may use flat `device_props` keys

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
- Works for small sets of writable keys such as SSID, hostname, and password
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

## Field deployment exports

Use the `/files` upload type **Field deployment export** for a complete
Cambium export. Select the model family, firmware, and role. The selected role
is authoritative; the provisioner does not infer AP or SM from an SSID or
model string. An export whose radio role fields do not match the selected
role is refused, so an AP export can never become an SM baseline.

The upload stores the exact original in private runtime storage. It activates
a reduced copy in the family tree, for example
`configs/templates/cambium/ePMP-4K/5.11.1/SM/default.json`. The runtime-only
shared profile is retired: git and CI could not lint it.

The reduced copy keeps only the fields the field ownership contract lets a
profile own (`docs/PROVISIONING_NORTH_STAR.md`). Secrets, device defaults,
unit identity, and captured addresses are dropped. The API refuses an upload
that still breaks the contract and names the fields, never the values.

The SM baseline (fleet policy, verified exact on read-back):

| Policy | Value |
|---|---|
| Management VLAN | Enabled, VLAN 12 |
| Management address | DHCP |
| DNS | From DHCP |
| NTP | `time.google.com`, `time.cloudflare.com` |
| Syslog | 100.126.15.28, UDP 514, mask 31 |
| cnMaestro | `cnmaestro.infra.treehouse.mn`, agent on, zero touch on |
| SNMP | Protocol version 1, remote access on; community via the secret path |
| SSH / Telnet | SSH on, Telnet off |
| Country | US |
| Scan mask (per family) | Bits: 1 = 20 MHz, 2 = 40, 16 = 80, 32 = 160. ePMP-4K `51` (20/40/80/160), ePMP-3K `19` (20/40/80). Factory is `3` (20 and 40 only), which cannot follow an 80 MHz access point. |

The SM radio role (verified exact on read-back):

| Field | SM | AP | PTP-A | PTP-B |
|---|---|---|---|---|
| `wirelessInterfaceMode` | `2` | `1` | `1` | `2` |
| `wirelessInterfacePTPMode` | `1` | `0` | `1` | `1` |
| `wirelessInterfaceProtocolMode` | `1` | `1` | `3` | `3` |

Every value traces to a known-good export fixture under
`bench-evidence/cambium/` (`tests/test_cambium_evidence.py`). A change starts
with a new fixture. The handler holds the same values in `SM_FLEET_POLICY` and
`SM_ROLE_VALUES`.

Device defaults are never written and never verified as exact values:
`wirelessInterfaceTDDAntennaGain` (integrated radios), `systemConfigMinAntGain`,
`cambiumGPSConfigPrioritizeUSB`, and `wirelessInterface2PTPMode`. The
fixtures show these vary per unit (gain 18 on 4518, 16 on 4616, 25 on 4625;
GPS USB 1 or 0).

Site identity and RF (SSID, hostname, device name, center frequency, TX power,
TDD frame and ratio, preferred AP list) belong to the AP and PTP workflow.
They never appear in the SM baseline.

Secrets (admin password, `wirelessInterfaceEncryptionKey`, SNMP community,
RADIUS) never appear in a template. The handler writes them through
`apply_secrets()` from the host credentials after the config step. Presence
is verified, never the value.

Full exports always use native `config_import` with `skipIllegal=1`. They
never use `set_param`. The export is imported as-is; there is no per-model
projection of device defaults.

Antenna gain: standard SM provisioning never writes gain. Integrated radios
are never written. During AP or PTP setup a connectorized radio (ePMP 4600C)
requires an explicit operator value; there is no default.

## When to Use Which Endpoint

Every row below traces to a capture summary under `bench-evidence/cambium/`
(`capture-summary.md`, `reset-capture-summary.md`, `upgrade-capture-summary.md`).
Read the summary before changing a row. The raw HAR stays on the bench host.


| Scenario | Endpoint | Notes |
|---|---|---|
| Firmware upload, running 5.11 or newer | `upload_sw_image_local` then `upgrade_sw_image_local` (`type=device`) then poll `get_upgrade_status` | Force 300-25 captures at 5.11.1 |
| Firmware upload, running older than 5.11 | `local_upload_image` then poll `get_upload_status` | ePMP 4518 workflow HAR at 5.10.4; `upload_sw_image_local` answered 404 |
| Factory reset | `reset_to_def` (`mask=1`) then `reboot` | ePMP 4518 and Force 300-25 HARs |
| Apply full JSON config file | `config_import` | Multipart upload, skipIllegal=1, poll for applyFinished |
| Apply full TAR backup archive | `config_import` | Same endpoint, same flow |
| Change a few fields (SSID, hostname) | `set_param` | Form-encoded, immediate, no polling needed |
| Read current config | `get_param` | act=config_regular for full config, act=status for polling |
| Post-provisioning AP naming | `set_param` | Only 3 keys: SSID, snmpName, deviceName |
| Restore SM after AP or PTP | `config_import` | Apply the standard SM profile, verify it, then clear local PTP state |

---

## How Config Apply Works (current implementation)

### Full config file (config_import path)
1. Template is loaded from `configs/templates/cambium/`
2. The model family SM baseline is selected (`ePMP-3K` or `ePMP-4K`). There
   is no shared profile and no cross-family fallback.
3. A native full export is uploaded to `/admin/config_import` with `skipIllegal=1`.
4. Poll `get_param` with `act=status&applyStatusNeeded=true` until `applyFinished=1`.
5. The contract-owned applied fields (fleet policy and role) are stored for verification.

### Individual fields (set_param path)
1. Used by `apply_ap_naming()` and `apply_config()` (dict input)
2. Flat keys wrapped: `{"device_props": {...}, "template_props": {"config_id": "0"}}`
3. URL-encoded and POSTed to `/admin/set_param`
4. Response checked for `"success": 1`

**The family SM baseline is used for initial provisioning and for SM restore.
AP and PTP exports are separate role profiles. The later mode workflow applies
the selected AP or PTP profile, then injects the generated site identity. A
mode is offered only after the bench recorded both transition directions
(`provisioner/qualification.py`).**

## Certified ePMP PTP family link profiles

The PTP workflow certifies ePMP 3K and ePMP 4K family pairings. This includes
links between two 46xx models and links between an ePMP 3K model and an ePMP
4K model. Each endpoint still needs a PTP settings profile for its own family.
The API rejects the link when the family pairing is not certified or either
profile is missing.

The supplied 46xx native exports are the ePMP 4K `tw32-tw18` link profile.
Upload each export from the `/files` page. Use these values:

| Field | PTP-A export | PTP-B export |
|---|---|---|
| Type | Field deployment export | Field deployment export |
| Family | `ePMP-4K` | `ePMP-4K` |
| Firmware | `5.11.1` | `5.11.1` |
| Role | `PTP` | `PTP` |
| Mode | `ptp-a` | `ptp-b` |
| Scope | `family` | `family` |
| Link profile | `tw32-tw18` | `tw32-tw18` |
| Side profile | `Main` | `SM` |

The firmware field must match the native export version in `template_props`.
The service rejects an upload when the versions do not match.

The service stores link IDs in ascending tower order. The generated SSID uses
this same order. Reversing the two tower values does not change the link ID or
SSID. For this pair the runtime ID is `tw18-tw32`; the resolver also accepts
the reverse order shown in the field export names.

The upload stores the active profiles under the protected runtime path:

```text
configs/templates/cambium/ePMP-4K/5.11.1/PTP/tw32-tw18/Main/default.json
configs/templates/cambium/ePMP-4K/5.11.1/PTP/tw32-tw18/SM/default.json
```

The source exports and active PTP profiles contain secrets and site identity.
They are host-only. Do not commit them or include them in a setup bundle.
The protected profile must retain the native PTP radio settings, including the
radio mode, PTP role, protocol mode, TDD frame size, TDD ratio, and center
frequency. The handler generates the link identity (hostname and SSID) from
the two tower numbers and leaves these hardware-specific settings from the
profile unchanged.

The PTP action appears only after the device has completed and verified SM
provisioning. The operator enters the two tower numbers. The backend reserves
one side before it starts the background task, checks the peer family, matches
the device firmware to the profile version, and injects the generated link
identity. A PTP-A upload must use the `Main` profile. A PTP-B upload must use
the `SM` profile.

---

## How Config Verify Works

1. POST to `/admin/get_param` with `act=config_regular&debug=true`.
2. Parse `device_props` from the JSON response.
3. Compare the expectation set from the field ownership contract
   (`field_ownership.expected_values`): fleet policy and role fields as exact
   values, plus identity fields when the mode workflow applied them. Secrets
   and device defaults are never compared.
4. The result is tri-state: `True` when every field matched, `False` on a
   mismatch, `UNVERIFIED` when the read-back was incomplete.
5. Mismatched field names (never values) are recorded on
   `handler.last_verify_mismatches`, shown in the failure message and the port
   timeline.

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
| `*Table` | Table or list data, such as MAC filters and QoS rules |
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
- `config_import` logs success state and error presence, not response secrets
- The apply-status poll logs progress and final `applyFinished` state
- `set_param` failures log error presence, not response values
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
| 2026-05-28 | `upload_sw_image_local` + `upgrade_sw_image_local` + `get_upgrade_status` (FW2 alt-bank flash) | HAR capture from browser, Force 300-25 | 5.11.1 |
| 2026-08-24 | `upload_sw_image_local` + `upgrade_sw_image_local` + `get_upgrade_status` (both passes) | Successful HAR capture, ePMP AX SKU 53560 | 5.11.0 |

---

## Dual-bank firmware update (issue #58)

Cambium ePMP devices have two firmware banks (Image A and Image B). A
full provisioning that ends with **both banks at the target version**
needs two separate flash passes, each using a different endpoint set.
This was confirmed via HAR capture of the web UI doing a successful
manual dual-bank upgrade on a Force 300-25 running 5.11.1.

ePMP AX uses the explicit second-pass sequence for both banks. The trigger
and status requests use `type=device&debug=true`. A successful HAR confirmed
status progression from 0 through 7. The AX web UI does not expose
`local_upload_image`; that endpoint returns HTTP 404.

### First pass — first-bank flash

Targets the currently inactive bank; reboot then swaps it active.

```
POST /cgi-bin/luci/;stok={stok}/admin/local_upload_image    # multipart, field=image
POST /cgi-bin/luci/;stok={stok}/admin/get_upload_status × N # poll until status=7
POST /cgi-bin/luci/;stok={stok}/admin/reboot
```

### Second pass — alternate-bank flash

After the bank swap from the first reboot, hitting `local_upload_image`
again is a silent no-op. The web UI uses a different endpoint set to
target the *new* inactive bank (the former active bank):

```
POST /cgi-bin/luci/;stok={stok}/admin/upload_sw_image_local      # multipart, field=image
POST /cgi-bin/luci/;stok={stok}/admin/upgrade_sw_image_local
  body: type=device&debug=true
POST /cgi-bin/luci/;stok={stok}/admin/get_upgrade_status × N
  body: type=device&debug=true
POST /cgi-bin/luci/;stok={stok}/admin/reboot
```

The `upgrade_sw_image_local` step is the explicit "now actually flash
the inactive bank with what was just uploaded" trigger — without it,
the upload sits idle and the bank version is never updated. This is
the step the provisioner was missing before #58.

`get_upgrade_status` returns the same status-7 sentinel as
`get_upload_status` (verified empirically). The form body is mandatory;
without it the endpoint returns a 400.

Handler implementation: `CambiumHandler.upload_firmware()` derives the
flow from the model and bank. Force-series devices use the original
first-pass and second-pass split. ePMP AX uses the explicit sequence for
both passes.

---

*Last updated: 2026-08-24*
*This document is the source of truth for Cambium API behavior. Update it
when new endpoints or behaviors are confirmed on actual hardware.*
