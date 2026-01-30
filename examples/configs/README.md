# Config Templates

This folder contains **example** config templates. Copy these to your provisioner's config repository on the Pi.

## Directory Structure

On the Pi, templates should be at:
```
/var/lib/provisioner/repo/configs/templates/
├── tachyon/
│   ├── default.json   # SM config (applied during auto-provisioning)
│   └── ap.json        # AP config (applied via "Configure as AP" button)
├── cambium/
│   ├── default.json   # SM config
│   └── ap.json        # AP config
```

## AP Config - Auto Field Injection

For AP configs, the system automatically injects values into known fields. You can use your normal config file and these fields will be overwritten:

### Cambium
| Field | Injected Value | Example |
|-------|----------------|---------|
| `wirelessInterfaceSSID` | ssid | `tw05-north` |
| `snmpSystemName` | hostname | `tw05-north` |
| `systemConfigDeviceName` | hostname | `tw05-north` |

### Tachyon
| Field | Injected Value | Example |
|-------|----------------|---------|
| `system.hostname` | hostname | `tw05-north` |
| `system.name` | hostname | `tw05-north` |
| `wireless.radios.wlan0.vaps[0].ssid` | ssid | `NORTH` |

## SSID Generation

SSIDs are generated differently per device type:

| Device | SSID Pattern | Example |
|--------|--------------|---------|
| Tachyon | Direction only (uppercase) | `NORTH` |
| Cambium | Tower + direction | `tw05-north` |

## Optional: Placeholder Syntax

You can also use `{{placeholder}}` syntax anywhere in your config for custom fields:

| Variable | Example | Description |
|----------|---------|-------------|
| `{{hostname}}` | `tw05-north` | Generated hostname |
| `{{systemname}}` | `tw05-north` | Same as hostname |
| `{{ssid}}` | `NORTH` or `tw05-north` | Device-specific SSID |
| `{{tower}}` | `5` | Raw tower number |
| `{{tower_padded}}` | `05` | Zero-padded tower number |
| `{{direction}}` | `north` | Lowercase direction |
| `{{direction_upper}}` | `NORTH` | Uppercase direction |

## Usage

1. Upload your normal AP config via Manage → Configs (select "AP" mode)
2. The system saves it as `ap.json` in the device type folder
3. When you click "Configure as AP" on a provisioned device, it:
   - Loads your AP config
   - Injects hostname/SSID into the known fields
   - Applies the config to the device
   - Reboots the device
