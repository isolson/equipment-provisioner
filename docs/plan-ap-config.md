# AP Config Selection Feature - Implementation Plan

## Overview

After standard provisioning completes (which applies SM/subscriber config by default), allow the user to optionally convert a device to AP mode with custom naming.

## User Flow

1. Device detected → Auto-provisions with SM config (default behavior, unchanged)
2. Provisioning completes successfully
3. Port card shows "Configure as AP" button
4. User clicks button → Modal appears asking:
   - Tower number (1-99, displayed as tw01-tw99)
   - Direction: North / South / East / West (dropdown or buttons)
5. System generates naming:
   - Hostname: `tw{tower:02d}-{direction}` (e.g., "tw05-north")
   - Systemname: same as hostname
   - SSID (device-specific):
     - **Tachyon**: Just the direction uppercase → `NORTH`, `SOUTH`, `EAST`, `WEST`
     - **Cambium**: Tower + direction → `tw05-north`, `tw05-south`, etc.
6. AP config template is loaded, variables injected, and applied to device

## Config File Structure

```
configs/templates/
├── tachyon/
│   ├── default.json      # SM config (current default)
│   ├── sm.json           # Explicit SM config (optional alias)
│   └── ap.json           # AP config template with placeholders
├── cambium/
│   ├── default.json      # SM config
│   └── ap.json           # AP config template
```

## Template Variable Syntax

AP config files use `{{variable}}` placeholders:

```json
{
  "system": {
    "hostname": "{{hostname}}",
    "systemname": "{{systemname}}"
  },
  "wireless": {
    "ssid": "{{ssid}}"
  }
}
```

Available variables:
- `{{hostname}}` - e.g., "tw05-north"
- `{{systemname}}` - e.g., "tw05-north"
- `{{ssid}}` - device-specific (see below)
- `{{tower}}` - raw tower number, e.g., "5"
- `{{tower_padded}}` - zero-padded, e.g., "05"
- `{{direction}}` - lowercase, e.g., "north"
- `{{direction_upper}}` - uppercase, e.g., "NORTH"

### SSID Generation by Device Type

| Device Type | SSID Format | Example |
|-------------|-------------|---------|
| Tachyon     | `{{direction_upper}}` | `NORTH` |
| Cambium     | `tw{{tower_padded}}-{{direction}}` | `tw05-north` |

## API Design

### New Endpoint

```
POST /api/ports/{port_number}/apply-ap-config
```

**Request:**
```json
{
  "tower_number": 5,
  "direction": "north"
}
```

**Response:**
```json
{
  "success": true,
  "hostname": "tw05-north",
  "ssid": "NORTH",
  "device_type": "tachyon",
  "message": "AP configuration applied"
}
```

### Error Cases
- Device not connected/detected on port → 400
- No AP config template found → 404
- Device rejected config → 500 with device error

## Backend Components

### 1. Config Template Loader (new module: `provisioner/ap_config.py`)

```python
class APConfigManager:
    def get_ap_template(device_type: str, model: str = None) -> Path
    def render_template(template: dict, variables: dict) -> dict
    def generate_naming(tower: int, ap: int) -> dict
```

### 2. API Endpoint (in `provisioner/web/api.py`)

- Validates port has a provisioned device
- Loads AP template for device type
- Renders template with variables
- Gets handler for device type
- Connects to device and applies config
- Returns result

### 3. Handler Updates

Handlers already have `apply_config()` - no changes needed.
May need to add reconnect logic if device was idle.

## Frontend Components

### 1. Port Card Enhancement

After successful provisioning, show:
```
[Configure as AP]  [Re-provision]
```

### 2. AP Config Modal

```
┌─────────────────────────────────────┐
│  Configure as Access Point          │
├─────────────────────────────────────┤
│                                     │
│  Tower Number: [___] (1-99)         │
│                                     │
│  Direction:                         │
│    [North] [South] [East] [West]    │
│                                     │
│  Preview:                           │
│    Hostname: tw05-north             │
│    SSID: NORTH (Tachyon)            │
│                                     │
│  [Cancel]            [Apply Config] │
└─────────────────────────────────────┘
```

### 3. Progress/Result Display

Show spinner during config apply, then success/error message.

## Implementation Order

1. **Phase 1: Backend**
   - [ ] Create `ap_config.py` module with template loading/rendering
   - [ ] Add API endpoint `/api/ports/{port}/apply-ap-config`
   - [ ] Add reconnect logic for idle devices

2. **Phase 2: Config Templates**
   - [ ] Create example AP config template for Tachyon
   - [ ] Create example AP config template for Cambium
   - [ ] Document template variable syntax

3. **Phase 3: Frontend**
   - [ ] Add "Configure as AP" button to port card (post-provisioning)
   - [ ] Create AP config modal component
   - [ ] Wire up API call and result handling

4. **Phase 4: Testing**
   - [ ] Test with Tachyon device
   - [ ] Test with Cambium device
   - [ ] Test error cases (no template, device offline, invalid input)

## Decisions

1. **Tower Number Range**: Two digits (tw01-tw99)
2. **Reboot After Config**: Yes - trigger device reboot after AP config applied
3. **Config Persistence**: Yes - track AP assignments in database (same as SM provisioning)
4. **SM Mode Button**: Not needed - physical reconnection triggers SM re-provisioning
