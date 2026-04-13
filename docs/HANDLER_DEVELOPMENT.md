# Handler Development Guide

This document outlines the standards and flow for building device handlers in the network provisioner.

## Handler Architecture

Each vendor handler inherits from `BaseHandler` and implements vendor-specific API communication.

```
provisioner/handlers/
├── base.py          # Base class with provisioning orchestration + property defaults
├── cambium.py       # Cambium Networks (ePMP, Force)
├── mikrotik.py      # MikroTik RouterOS (SSH-based)
├── tachyon.py       # Tachyon Networks (TNA APs, TNS switches)
├── tarana.py        # Tarana Wireless (gRPC-web)
├── ubiquiti.py      # Ubiquiti (Wave + AirOS)
└── mock.py          # Mock handler for testing
```

## Handler Properties (Provisioning Behavior Flags)

BaseHandler defines properties that control the provisioning flow. Override them in your handler to change behavior for your device type. **Only override what you need** — defaults are designed for the common case.

| Property | Default | Effect When True |
|----------|---------|-----------------|
| `supports_dual_bank` | `False` | Enables bank 2 firmware update after bank 1 |
| `supports_password_change` | `False` | Enables password change phase before firmware |
| `update_triggers_reboot` | `False` | Skips explicit `reboot()` call after `update_firmware()` — device reboots itself |
| `verify_active_bank` | `= update_triggers_reboot` | FW verification checks the active bank (not hardcoded bank1). Use when device installs to inactive bank then activates it |
| `fw2_skips_reboot` | `False` | Bank 2 update writes to inactive bank without activating. No reboot after FW2. Preserves auto-discovered state (azimuth, location) |
| `config_after_all_firmware` | `False` | Moves config apply to AFTER all firmware updates and skips config verification. Use when config changes the management network (VLAN, DHCP), making the device unreachable for further operations |

### Property Combinations by Vendor

| Handler | dual_bank | update_triggers_reboot | verify_active_bank | fw2_skips_reboot | config_after_all_firmware | password_change |
|---------|-----------|----------------------|-------------------|-----------------|-------------------------|----------------|
| Cambium | Yes | No | No | No | No | Yes |
| MikroTik | No | No | No | No | No | No |
| Tachyon (APs) | Yes | Yes | Yes | No | No | Yes |
| Tachyon (TNS switches) | Yes | Yes | Yes | No | **Yes** | Yes |
| Tarana | Yes | No | Yes | **Yes** | No | No |
| Ubiquiti (Wave) | Yes | No | No | No | No | Yes |
| Ubiquiti (AirOS) | No | No | No | No | No | No |

### When `config_after_all_firmware` Is True

The provisioning order changes from the default:

```
DEFAULT:           FW1 → Reboot → Verify → Config → Config Verify → FW2 → Reboot → Verify
config_after_all:  FW1 → Reboot → Verify → FW2 → Reboot → Verify → Config (no verify)
```

Config verification is skipped because the device may become unreachable after config changes the management network. The UI shows config_verify as "skipped" with a message explaining why.

**This property can be conditional on model.** For example, Tachyon only enables it for TNS switches (not APs):

```python
@property
def config_after_all_firmware(self) -> bool:
    model = getattr(self._device_info, 'model', '') or ''
    return model.lower().startswith('tns-')
```

The property is checked after `get_info()` has populated `self._device_info`, so model data is available.

### Post-Config Link Loss (the "unreachable after config" pattern)

When `config_after_all_firmware` is true, the device typically becomes unreachable after config apply (e.g., it moves to a different VLAN or switches to DHCP). This triggers a chain of events that multiple layers must handle correctly:

1. **Config apply succeeds** — the API call returns success before the device applies network changes
2. **Internal read-back fails** — `apply_config()` may attempt a read-back verification that times out (this is caught and logged as a warning, not an error)
3. **Link drops** — the device's network change causes a physical link flap or the device stops responding on the provisioning VLAN
4. **Port manager preserves result** — `_clear_port_state_on_disconnect()` checks if we're in the 3-minute post-provisioning grace period. If so, it clears device/link state (needed for re-detection) but preserves `last_result`, `checklist`, and `provision_attempted`
5. **UI shows "COMPLETE"** — `getCardState()` and `getStatusCenterInfo()` check `last_result` before `link_up`, so the completion state survives link-down

**If you modify any of these layers, test with a device that changes networks after config.** A common regression is checking `link_up` or `device_detected` before `last_result` in UI code, which causes the card to show "NO LINK" instead of "COMPLETE".

### When `fw2_skips_reboot` Is True

Bank 2 firmware is written but NOT activated. The device stays on its current bank. This is used when the device has auto-discovered state (e.g., Tarana azimuth/location) that would be lost on bank switch. Both banks end up with the same firmware, but the device doesn't reboot after FW2.

## Required Methods

Every handler MUST implement these methods:

### 1. `connect() -> bool`
Authenticate with the device.

**Flow:**
1. Try default credentials first
2. Try custom credentials from UI (alternate_credentials)
3. If all fail, set `self.login_error` and return `False`

**Must set:**
- `self._connected = True` on success
- `self.login_error` on failure (for UI display)

### 2. `get_info() -> DeviceInfo`
Retrieve device information after successful login.

**Must populate:**
- `info.model` - Device model (e.g., "TNA-301", "ePMP 3000")
- `info.serial_number` - Serial number
- `info.hostname` - Current hostname
- `info.firmware_version` - Current firmware version
- `info.mac_address` - MAC address (if available)

**Important:** This data is displayed in the UI. If `model` is None, the UI shows "true" instead.

### 3. `get_firmware_banks() -> Dict` (for dual-bank devices)
Get firmware bank versions for UI display.

**Must return:**
```python
{
    "bank1": "1.12.2",      # Firmware version in bank 1
    "bank2": "1.12.3",      # Firmware version in bank 2
    "active": 2,            # Which bank is active (1 or 2)
}
```

### 4. `apply_config(config: Dict) -> bool`
Apply configuration dictionary to device.

### 5. `apply_config_file(config_path: str) -> bool`
Apply configuration from file. Must support:
- `.json` files - Parse and apply
- `.tar` / `.tar.gz` files - Extract `config.json` and apply

### 6. `upload_firmware(firmware_path: str) -> bool`
Upload firmware file to device.

### 7. `update_firmware(bank: int = None) -> bool`
Trigger firmware update after upload.

### 8. `reboot() -> bool`
Reboot the device.

### 9. `wait_for_reboot(timeout: int = 180) -> bool`
Wait for device to come back online after reboot.

## Authentication Flow

```
┌─────────────────────────────────────────────────────┐
│                    connect()                         │
├─────────────────────────────────────────────────────┤
│  1. Try DEFAULT_CREDENTIALS (e.g., root/admin)      │
│     └─ Success? Return True                         │
│                                                     │
│  2. Try alternate_credentials from web UI           │
│     └─ Success? Return True                         │
│                                                     │
│  3. All failed                                      │
│     └─ Set login_error = "Invalid credentials"      │
│     └─ Return False                                 │
│                                                     │
│  UI will prompt user for credentials if needed      │
└─────────────────────────────────────────────────────┘
```

## Provisioning Flow (called by base.py)

The `provision()` method in `base.py` orchestrates the full flow. The order of config vs FW2 depends on the `config_after_all_firmware` property.

```
┌─────────────────────────────────────────────────────┐
│              provision() in base.py                  │
├─────────────────────────────────────────────────────┤
│  1. connect()                                       │
│     └─ notify("login", success, error)              │
│                                                     │
│  2. get_info()                                      │
│     └─ notify("model_confirmed", True, model_name)  │
│     └─ notify("device_info", True, "mac:XX|serial:YY") │
│                                                     │
│  3. get_firmware_banks() (if supported)             │
│     └─ notify("firmware_banks", True, "bank1:X|bank2:Y|active:Z") │
│                                                     │
│  ══════════════ BANK 1 FIRMWARE ═══════════════════ │
│                                                     │
│  4. upload_firmware() → update_firmware(bank=1)     │
│     └─ reboot() (or auto-reboot if update_triggers_reboot) │
│     └─ wait_for_reboot() → connect() → verify      │
│     └─ notify("firmware_update_1", success, version)│
│                                                     │
│  ══════════════ CONFIG vs FW2 ORDERING ════════════ │
│                                                     │
│  IF config_after_all_firmware = False (DEFAULT):    │
│  ┌──────────────────────────────────────────────┐   │
│  │  5. Config Apply → Config Verify             │   │
│  │  6. Bank 2 FW → Reboot → Verify             │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  IF config_after_all_firmware = True:               │
│  ┌──────────────────────────────────────────────┐   │
│  │  5. Bank 2 FW → Reboot → Verify             │   │
│  │  6. Config Apply (verify SKIPPED)            │   │
│  │     Device may become unreachable here       │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  ══════════════ COMPLETION ════════════════════════ │
│                                                     │
│  7. Final verification                              │
│     └─ notify("verify", True, firmware_version)     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**CRITICAL:** Every `notify()` call triggers a WebSocket broadcast to the UI.
This is handled in `main.py`'s `on_checklist_progress` callback which:
1. Updates `port_manager.update_checklist()`
2. Broadcasts via `notify_port_change()` → WebSocket → UI refresh

## Firmware Update Flow (Detailed)

### Default Order (most devices)

Config is applied between FW1 and FW2 so the device runs new firmware + new config, and the provisioner can verify config was applied before moving on.

```
BANK 1 → reboot → verify → CONFIG → verify config → BANK 2 → reboot → verify
```

### config_after_all_firmware Order (e.g., Tachyon TNS switches)

Config is applied last because it changes the management network (VLAN, DHCP mode), making the device unreachable. Config verification is skipped — the UI shows it as "skipped" with explanation.

```
BANK 1 → reboot → verify → BANK 2 → reboot → verify → CONFIG (no verify)
```

### Dual-Bank Firmware Detail

```
┌─────────────────────────────────────────────────────┐
│           Dual-Bank Firmware Update                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─── BANK 1 ───┐                                   │
│  │ upload_firmware(path)                            │
│  │ update_firmware(bank=1)                          │
│  │ reboot() [or auto-reboot]                        │
│  │ wait_for_reboot() ◄── Port may go offline here   │
│  │ connect()                                        │
│  │ verify: get_firmware_version() == expected       │
│  └──────────────┘                                   │
│         │                                           │
│    ┌────┴────────────────────────────────────────┐   │
│    │  IF !config_after_all_firmware:             │   │
│    │  ┌─── CONFIG ───┐                           │   │
│    │  │ apply_config() + verify_config()         │   │
│    │  └──────────────┘                           │   │
│    └─────────────────────────────────────────────┘   │
│         │                                           │
│         ▼                                           │
│  ┌─── BANK 2 ───┐                                   │
│  │ upload_firmware(path)                            │
│  │ update_firmware(bank=2)                          │
│  │ reboot() [unless fw2_skips_reboot]               │
│  │ wait_for_reboot()                                │
│  │ connect()                                        │
│  │ verify: both banks now have same version         │
│  └──────────────┘                                   │
│         │                                           │
│    ┌────┴────────────────────────────────────────┐   │
│    │  IF config_after_all_firmware:              │   │
│    │  ┌─── CONFIG (final) ───┐                   │   │
│    │  │ apply_config() — no verify_config()      │   │
│    │  │ Device may leave provisioning network    │   │
│    │  └──────────────────────┘                   │   │
│    └─────────────────────────────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Port Offline During Firmware

When firmware is uploaded/applied, the device may:
- Briefly go offline during flash write
- Reboot automatically after update
- Cause port link to drop

**Important:** The provisioner should:
1. Track device by MAC address (not just port)
2. Not restart provisioning flow if link drops temporarily
3. Use `wait_for_reboot()` to handle expected downtime

### Firmware Version Comparison

Before updating, compare current vs available:

```python
# In main.py provisioning flow
if firmware_manager.needs_update(device_type, current_version, model):
    # Proceed with firmware update
    firmware_path = firmware_info.path
else:
    # Skip firmware, just do config
    firmware_path = None
```

## UI Display Requirements

### Port Card

Each port card shows two zones:

1. **Identity line** (top) — vendor tag, model name, port number, link speed.
   Only appears when a device is detected.
2. **Status center** (fills the card) — large icon + text showing current state:
   - `NO LINK` (gray) — no cable / no device
   - `DETECTING` (amber spinner) — waiting for device
   - `READY` (green check) — device detected, tap to provision
   - `LOGGING IN` / `CHECKING FIRMWARE` / `APPLYING CONFIG` / etc. (blue spinner) — active provisioning step with "Step N of 7" subtitle
   - `COMPLETE` (green check) — all steps passed
   - `FAILED` (red X) — error with truncated message
   - `NEEDS CREDENTIALS` (red alert) — tap to enter password

### Modal (tap a card)

Opens an activity log view with:

**Device summary** (top grid):
- MAC Address, Serial, IP, Link Speed
- FW Bank 1 and FW Bank 2 with version and active indicator

**Activity log** — timestamped step-by-step entries in provisioning order:

| Step | Checklist Key | Detail Shown |
|------|---------------|--------------|
| Login | `login` | MAC address |
| Model | `model_confirmed` | Model name string |
| FW Check | `firmware_banks` | "bank1_ver / bank2_ver (bank N)" |
| FW Bank 1 | `firmware_update_1` | Firmware version |
| Config | `config_upload` | — |
| FW Bank 2 | `firmware_update_2` | Firmware version |
| Reboot | `reboot` | — |
| Verify | `verify` | — |

Each entry shows a state indicator: ✓ success (green), ✗ error (red), ● loading (blue pulse), ○ pending (gray), — skipped (gray strikethrough).

Steps not yet logged but visible in the checklist appear without timestamps.
The current active step (matching `port.current_step`) shows with a blue loading indicator and highlighted background.

**Footer:**
- During provisioning: "Close" button only
- After completion/failure: "Retry" + "Close" buttons. Retry opens the provision options modal to restart from the beginning.

## Config File Locations

```
configs/
├── templates/
│   ├── cambium/
│   │   └── default.json       # Default Cambium config
│   ├── mikrotik/
│   │   └── default.rsc        # Default MikroTik config
│   ├── tachyon/
│   │   └── default.json       # Default Tachyon config
│   └── tarana/
│       └── default.json       # Default Tarana config
└── overrides/
    └── {MAC-ADDRESS}.json     # Per-device overrides
```

**Config lookup order:**
1. `templates/{device_type}/{model}.json` - Model-specific
2. `templates/{device_type}/default.json` - Default for type
3. `templates/{device_type}/*.json` - First file found

## Firmware File Locations

```
firmware/
├── cambium/
│   └── ePMP-3000-v4.7.1.bin
├── mikrotik/
│   └── routeros-7.12.1.npk
├── tachyon/
│   └── tna-30x-1.12.3.bin
└── tarana/
    └── tarana-g1-2.5.0.bin
```

**Firmware lookup:**
1. `firmware/{device_type}/{model}-{version}.*` - Model-specific
2. `firmware/{device_type}/*` - First file found

## Credentials

**Default credentials** (per vendor):
```python
# In handler class
DEFAULT_CREDENTIALS = [
    {"username": "root", "password": "admin"},
]
```

**Custom credentials** (from web UI):
- Stored in `data/credentials.json`
- Passed to handler via `alternate_credentials` parameter

## API Response Handling

### Always check for errors in JSON responses

Many APIs return HTTP 200 but include error in JSON body:

```python
# BAD - assumes 200 means success
if response.status == 200:
    return True

# GOOD - check JSON for errors
if response.status == 200:
    data = await response.json()
    if data.get("statusCode") == 401:
        self.login_error = "Invalid credentials"
        return False
```

### Cookie-based vs Bearer token auth

Check the vendor API documentation:
- **Tachyon**: Cookie-based (`Cookie: token=...`)
- **Cambium**: Session cookie or Bearer token
- **MikroTik**: RouterOS API protocol

## Testing a Handler

1. **Local test without provisioner:**
```python
handler = TachyonHandler(
    ip='192.168.1.1',
    credentials={'username': 'root', 'password': 'admin'},
    interface='en0'  # Optional, for VLAN binding
)

# Test connect
connected = await handler.connect()
print(f"Connected: {connected}, Error: {handler.login_error}")

# Test get_info
info = await handler.get_info()
print(f"Model: {info.model}, Serial: {info.serial_number}")

# Test firmware banks
banks = await handler.get_firmware_banks()
print(f"Banks: {banks}")
```

2. **Test full provision flow:**
```python
result = await handler.provision(
    config_path='/path/to/config.json',
    firmware_path='/path/to/firmware.bin',
    on_progress=lambda step, ok, detail: print(f"{step}: {ok} - {detail}")
)
print(f"Success: {result.success}, Error: {result.error_message}")
```

## Common Mistakes

1. **Not returning model from get_info()** - UI shows "true" instead of model name
2. **Not handling 401 in JSON body** - Login appears successful but API calls fail
3. **Wrong cookie/token name** - Auth works but subsequent calls fail
4. **Not URL-encoding tokens** - Some tokens contain special characters
5. **Not clearing state between credential attempts** - Old tokens interfere

## Adding a New Vendor

### 1. Handler (`provisioner/handlers/{vendor}.py`)

- Inherit from `BaseHandler`
- Set `DEFAULT_CREDENTIALS` for factory-default login
- Implement all required methods (see above)
- Override only the handler properties that differ from defaults (see table above)
- If a property depends on model (e.g., switches vs APs from the same vendor), make it conditional on `self._device_info.model` — this is populated before the property is checked

### 2. Device Detection (`provisioner/fingerprint.py`)

- Add to `DeviceType` enum
- Add HTTP header signatures with appropriate weights (see existing patterns)
- Add API probe if the device has a distinctive REST endpoint
- Detection must work on factory-default devices at their default IP

### 3. Boot-Ping Discovery (`provisioner/port_manager.py`)

- Add the vendor's default IP(s) to `DeviceLinkLocalIP` class
- Add to `DeviceLinkLocalIP.ALL` with vendor tag
- Add to the boot-ping `ips_to_try` list in `_boot_ping_detect()`

### 4. Handler Registration (`provisioner/handler_manager.py`)

- Add `DeviceType.{VENDOR}: {Vendor}Handler` to `HANDLER_MAP`

### 5. Firmware Matching (`provisioner/firmware.py`)

- Add model-to-filename patterns in `MODEL_FIRMWARE_PATTERNS`
- Add firmware version extraction regex if the vendor uses non-standard naming
- Create `firmware/{vendor}/` directory

### 6. Config Templates (`configs/templates/{vendor}/`)

- Create vendor subdirectory
- Add model-specific templates as `{model}.json` (or `.rsc`, `.yaml`, `.tar`)
- Add model aliases to `CONFIG_MODEL_ALIASES` in `config_store.py` if needed
- Template format is vendor-specific — match what the handler's `apply_config_file()` expects

### 7. Testing

- [ ] Device detection works (factory-default state)
- [ ] Boot-ping finds the device after power-on
- [ ] Login with default credentials succeeds
- [ ] `get_info()` returns model, serial, firmware, MAC
- [ ] `get_firmware_banks()` returns correct bank info (if dual-bank)
- [ ] Firmware upload and update works
- [ ] Reboot and reconnection works
- [ ] Config apply works
- [ ] Config verify works (or is correctly skipped with `config_after_all_firmware`)
- [ ] Full provisioning flow completes end-to-end
- [ ] UI shows all steps correctly (check activity log modal)

### Adding a New Model to an Existing Vendor

If the new model has different provisioning behavior than existing models (e.g., a switch vs AP from the same vendor):

1. Add firmware patterns to `MODEL_FIRMWARE_PATTERNS`
2. Add config template as `configs/templates/{vendor}/{model}.json`
3. If the model needs different flow (e.g., `config_after_all_firmware`), make the handler property conditional on model name
4. Add model alias to `CONFIG_MODEL_ALIASES` if the API-reported model name differs from the template filename
