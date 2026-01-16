# Handler Development Guide

This document outlines the standards and flow for building device handlers in the network provisioner.

## Handler Architecture

Each vendor handler inherits from `BaseHandler` and implements vendor-specific API communication.

```
provisioner/handlers/
├── base.py          # Base class with common logic
├── cambium.py       # Cambium Networks (ePMP, cnPilot)
├── mikrotik.py      # MikroTik RouterOS
├── tachyon.py       # Tachyon Networks 30x series
├── tarana.py        # Tarana Wireless
└── mock.py          # Mock handler for testing
```

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

The `provision()` method in `base.py` orchestrates the full flow:

```
┌─────────────────────────────────────────────────────┐
│              provision() in base.py                  │
├─────────────────────────────────────────────────────┤
│  1. connect()                                       │
│     └─ notify("login", success, error)              │
│     └─ WebSocket broadcast → UI shows lock icon     │
│                                                     │
│  2. get_info()                                      │
│     └─ notify("model_confirmed", True, model_name)  │
│     └─ notify("device_info", True, "mac:XX|serial:YY") │
│     └─ WebSocket broadcast → UI shows model/MAC     │
│                                                     │
│  3. get_firmware_banks() (if supported)             │
│     └─ notify("firmware_banks", True, "bank1:X|bank2:Y|active:Z") │
│     └─ WebSocket broadcast → UI shows bank versions │
│                                                     │
│  ══════════════ IF FIRMWARE UPDATE NEEDED ══════════ │
│                                                     │
│  4. BANK 1 UPDATE:                                  │
│     └─ upload_firmware()                            │
│     └─ notify("firmware_upload", success, "bank 1") │
│     └─ update_firmware(bank=1)                      │
│     └─ notify("firmware_update", success, "bank 1") │
│     └─ reboot()                                     │
│     └─ notify("reboot", success, "bank 1")          │
│     └─ wait_for_reboot()                            │
│     └─ connect()                                    │
│     └─ verify firmware version                      │
│     └─ notify("verify", success, version)           │
│                                                     │
│  5. APPLY CONFIG (after firmware, before bank 2):   │
│     └─ apply_config() or apply_config_file()        │
│     └─ notify("config_upload", success, error)      │
│     └─ WebSocket broadcast → UI shows config icon   │
│                                                     │
│  6. BANK 2 UPDATE (if dual_bank enabled):           │
│     └─ upload_firmware()                            │
│     └─ update_firmware(bank=2)                      │
│     └─ reboot()                                     │
│     └─ wait_for_reboot()                            │
│     └─ connect()                                    │
│     └─ verify firmware version                      │
│                                                     │
│  ══════════════ IF NO FIRMWARE UPDATE ══════════════ │
│                                                     │
│  4. APPLY CONFIG ONLY:                              │
│     └─ apply_config() or apply_config_file()        │
│     └─ notify("config_upload", success, error)      │
│     └─ WebSocket broadcast → UI shows config icon   │
│                                                     │
│  ══════════ SKIPPED STEPS (no firmware/config) ═════ │
│                                                     │
│  If no config provided:                             │
│     └─ notify("config_upload", "skipped", "No config")│
│                                                     │
│  If no firmware provided:                           │
│     └─ notify("firmware_upload", "skipped", ...)    │
│     └─ notify("firmware_update", "skipped", ...)    │
│     └─ notify("reboot", "skipped", ...)             │
│     └─ notify("verify", "skipped", ...)             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**CRITICAL:** Every `notify()` call triggers a WebSocket broadcast to the UI.
This is handled in `main.py`'s `on_checklist_progress` callback which:
1. Updates `port_manager.update_checklist()`
2. Broadcasts via `notify_port_change()` → WebSocket → UI refresh

## Firmware Update Flow (Detailed)

**Order is critical:**
1. Firmware bank 1 → reboot → verify
2. Config (after first firmware so device has latest code)
3. Firmware bank 2 → reboot → verify

```
┌─────────────────────────────────────────────────────┐
│           Dual-Bank Firmware Update                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─── BANK 1 ───┐                                   │
│  │ upload_firmware(path)                            │
│  │ update_firmware(bank=1)                          │
│  │ reboot()                                         │
│  │ wait_for_reboot() ◄── Port may go offline here   │
│  │ connect()                                        │
│  │ verify: get_firmware_version() == expected       │
│  └──────────────┘                                   │
│         │                                           │
│         ▼                                           │
│  ┌─── CONFIG ───┐                                   │
│  │ apply_config() or apply_config_file()            │
│  │ (Device now has new firmware + new config)       │
│  └──────────────┘                                   │
│         │                                           │
│         ▼                                           │
│  ┌─── BANK 2 ───┐                                   │
│  │ upload_firmware(path)                            │
│  │ update_firmware(bank=2)                          │
│  │ reboot()                                         │
│  │ wait_for_reboot()                                │
│  │ connect()                                        │
│  │ verify: both banks now have same version         │
│  └──────────────┘                                   │
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

The UI displays these checklist items:

| Icon | Checklist Step | What It Shows |
|------|----------------|---------------|
| 🔒 | login | Green if connected |
| ⚙️ | config_upload | Green if config applied |
| 1 | firmware bank 1 | Green with version if known |
| 2 | firmware bank 2 | Green with version if known |

**Card displays:**
- Vendor name (from device_type)
- Model name (from `model_confirmed` or `device_model`)

**Modal displays (on tap):**
- Model
- MAC Address
- Serial Number
- IP Address
- Link Speed
- Firmware Bank 1 (with "active" indicator)
- Firmware Bank 2 (with "active" indicator)

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

## Adding a New Handler

1. Create `provisioner/handlers/{vendor}.py`
2. Inherit from `BaseHandler`
3. Implement all required methods
4. Add to `handler_manager.py` HANDLER_MAP
5. Add default credentials to `config.py`
6. Create config template directory: `configs/templates/{vendor}/`
7. Create firmware directory: `firmware/{vendor}/`
8. Test locally before deploying
