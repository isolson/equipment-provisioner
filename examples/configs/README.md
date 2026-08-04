# Configuration Templates

This folder contains example configuration templates. Copy them to the provisioner's configuration repository on the host.

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

## AP and PTP Mode Templates

The AP and PTP mode flow renders a small set of approved variables in the mode templates. The flow also injects values into known fields for Cambium and Tachyon devices. It does not render variables in standard provisioning templates.

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

## Mode Template Variables

Use these variables only in `ap.json`, `ptp-a.json`, and `ptp-b.json` files. `provisioner/mode_config.py` replaces them before it applies the configuration. Do not use them in `default.*` or other standard provisioning templates.

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
