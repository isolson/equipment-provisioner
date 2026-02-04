# Ubiquiti Wave Device Credentials Configuration

This document describes how to configure username, password, SNMP, and other credentials on Ubiquiti Wave devices.

## Overview

Wave devices use a REST API at `/api/v1.0/system/airos/configuration` for configuration management. This is different from traditional airOS devices which use SSH and text-based `system.cfg` files.

## Authentication

Wave devices authenticate via POST to `/api/v1.0/user/login` and return an `x-auth-token` header used for subsequent requests.

```
POST /api/v1.0/user/login
Content-Type: application/json

{"username": "ubnt", "password": "ubnt"}

Response Headers:
x-auth-token: <token>
```

## Configuration API

### Get Current Configuration
```
GET /api/v1.0/system/airos/configuration
x-auth-token: <token>
```

### Apply Configuration
```
PUT /api/v1.0/system/airos/configuration
x-auth-token: <token>
Content-Type: application/json

<configuration JSON>
```

## Password Configuration (HAR Verified)

Wave devices use a dedicated user endpoint for password changes. The password is sent in **cleartext** - the device handles hashing internally.

### API Endpoint
```
PUT /api/v1.0/system/users
x-auth-token: <token>
Content-Type: application/json

{
  "username": "ubnt",
  "displayName": "ubnt",
  "password": "newpassword",
  "readOnly": false
}
```

### Response on Success
```json
{
  "readOnly": false,
  "sshKeys": [],
  "username": "ubnt"
}
```

Note: The response does NOT include the password - it's stored internally as a hash.

### Key Points
- **Cleartext password** - No need to hash; device handles it
- **No reboot required** - Password takes effect immediately
- **Separate from config** - Users are managed via `/system/users`, not `/system/airos/configuration`

## SNMP Configuration (HAR Verified)

SNMP is configured via the `/services` endpoint using the `snmpAgent` field.

### API Endpoint
```
PUT /api/v1.0/services
x-auth-token: <token>
Content-Type: application/json
```

### snmpAgent Structure
```json
{
  "snmpAgent": {
    "enabled": true,
    "community": "mycommunity",
    "location": "Site Name",
    "contact": "admin@example.com"
  }
}
```

### Full Services Object
When updating SNMP, you must PUT the entire services object (GET first, modify snmpAgent, PUT back):

```json
{
  "snmpAgent": {
    "enabled": true,
    "community": "mycommunity",
    "location": "Site Name",
    "contact": "admin@example.com"
  },
  "sshServer": {
    "enabled": false,
    "sshPort": 22,
    "passwordAuthentication": true
  },
  "webServer": {
    "enabled": true,
    "httpPort": 80,
    "httpsPort": 443,
    "httpEnabled": true,
    "httpsEnabled": true,
    "sessionTimeout": 15
  },
  "ntpClient": {
    "enabled": true,
    "ntpServers": ["ntp.svc.ui.com"]
  },
  "discoveryResponder": {
    "enabled": true
  },
  "lldp": {
    "enabled": true
  }
}
```

## Implementation Status

### Implemented in ubiquiti.py
- [x] `connect()` - Authentication with x-auth-token
- [x] `get_info()` - Device info retrieval
- [x] `apply_config()` - Configuration PUT with verification
- [x] `upload_firmware()` - Firmware upload
- [x] `update_firmware()` - Firmware status polling
- [x] `reboot()` - Device reboot
- [x] `wait_for_reboot()` - Reboot verification
- [x] `set_password()` - Password change (NEW)
- [x] `configure_snmp()` - SNMP configuration (NEW)
- [x] `_get_config()` - Get current config helper (NEW)

### Not Implemented
- [ ] `backup_config()` - Config export (needs HAR analysis)

## HAR Analysis Required

To complete the implementation, HAR (HTTP Archive) analysis is needed to discover:

1. **Password change endpoint/structure:**
   - Is there a dedicated `/api/v1.0/user/password` endpoint?
   - What is the exact JSON structure for users in the config?
   - Is a reboot required after password change?

2. **SNMP configuration:**
   - What is the config key for SNMP settings?
   - What fields are available (community, v3 settings, trap hosts)?

3. **Other credentials:**
   - Are there separate APIs for SSH keys?
   - WiFi/SSID password configuration structure?

### How to Capture HAR

1. Open Wave device web UI in Chrome/Firefox
2. Open Developer Tools (F12) > Network tab
3. Perform the operation (change password, configure SNMP)
4. Right-click > Save all as HAR
5. Analyze the captured requests

## Implementation Plan for set_password()

```python
async def set_password(self, new_password: str, username: str = None) -> bool:
    """Change the device password.

    For Wave devices, this updates the user credentials via the
    configuration API.
    """
    if self._api_style != "wave":
        return False

    target_user = username or self.credentials.get("username", "ubnt")

    # Approach 1: Try dedicated user password endpoint (if exists)
    try:
        result = await self._api_post(
            "/api/v1.0/user/password",
            {
                "username": target_user,
                "currentPassword": self.credentials.get("password"),
                "newPassword": new_password,
            }
        )
        if result.get("error", 0) == 0:
            logger.info(f"Password changed for {target_user}")
            self.credentials["password"] = new_password
            return True
    except Exception:
        pass

    # Approach 2: Config-based password change
    try:
        # Get current config
        config = await self._get_config()

        # Generate password hash
        import crypt
        password_hash = crypt.crypt(new_password, crypt.mksalt(crypt.METHOD_SHA512))

        # Update user password in config
        if "users" in config:
            for user in config["users"]:
                if user.get("name") == target_user:
                    user["password"] = password_hash
                    break
        else:
            # Create users section
            config["users"] = [{"name": target_user, "password": password_hash}]

        # Apply config
        if await self.apply_config(config):
            logger.info(f"Password changed for {target_user} via config")
            self.credentials["password"] = new_password
            return True

    except Exception as e:
        logger.error(f"Failed to change password: {e}")

    return False
```

## Usage Examples

### Change Password
```python
from provisioner.handlers.ubiquiti import UbiquitiHandler

handler = UbiquitiHandler(
    ip="192.168.1.20",
    credentials={"username": "ubnt", "password": "ubnt"}
)

# Connect first
if await handler.connect():
    # Change password
    if await handler.set_password("new_secure_password"):
        print("Password changed successfully")
    else:
        print("Password change failed")
```

### Configure SNMP
```python
# After connecting...
if await handler.configure_snmp(
    community="mynetwork",
    location="Tower Site A",
    contact="admin@example.com",
    enabled=True
):
    print("SNMP configured successfully")
```

### Full Provisioning Flow with Credentials
```python
async def provision_wave_device(ip: str, old_password: str, new_password: str):
    handler = UbiquitiHandler(
        ip=ip,
        credentials={"username": "ubnt", "password": old_password}
    )

    try:
        # 1. Connect
        if not await handler.connect():
            return False, "Failed to connect"

        # 2. Get device info
        info = await handler.get_info()
        print(f"Device: {info.model}, FW: {info.firmware_version}")

        # 3. Change password from default
        if not await handler.set_password(new_password):
            return False, "Failed to change password"

        # 4. Configure SNMP
        if not await handler.configure_snmp(community="monitoring"):
            print("Warning: SNMP configuration failed")

        # 5. Apply other config (hostname, etc.)
        config = {
            "system": {"hostname": f"site-{info.serial_number}"},
        }
        if not await handler.apply_config(config):
            return False, "Failed to apply config"

        return True, "Provisioning complete"

    finally:
        await handler.disconnect()
```

## Testing

### Verify Password Change
After changing the password, verify by reconnecting:

```python
await handler.disconnect()
handler.credentials["password"] = new_password
if await handler.connect():
    print("Password verified - can login with new credentials")
```

### Verify SNMP Configuration
Use snmpwalk to verify SNMP is working:

```bash
snmpwalk -v2c -c mynetwork 192.168.1.20 sysDescr
```

## Troubleshooting

### Password Change Fails
1. Ensure you're connected and authenticated
2. Check if device uses different config structure (HAR analysis needed)
3. Try rebooting the device after password change

### SNMP Not Responding
1. Verify SNMP is enabled in the response
2. Check firewall settings on the device
3. Ensure correct community string

## Firmware Variants

Wave devices use platform-specific firmware. The provisioner maps device models to the correct firmware variant automatically.

### Firmware Mapping

| Model | Firmware | Board ID | File Pattern |
|-------|----------|----------|--------------|
| Wave-Pro | GMC | 75ba | `75ba-wave-*.bin` |
| Wave-AP | GMC | 75ba | `75ba-wave-*.bin` |
| Wave-AP-Micro | GMC | 75ba | `75ba-wave-*.bin` |
| Wave-Pico | GMC | 75ba | `75ba-wave-*.bin` |
| Wave-Nano | MGMP | 02da | `02da-wave-*.bin` |
| Wave-Micro | MGMP | 02da | `02da-wave-*.bin` |
| Wave-LR | MGMP | 02da | `02da-wave-*.bin` |

### Important Notes

- **Silent rejection**: The Wave API accepts firmware uploads but silently rejects wrong variants. After reboot, firmware banks will show the old version if wrong firmware was uploaded.
- **Dual banks**: Wave devices have two firmware banks. The provisioner updates both banks to ensure redundancy.
- **Verification**: Always check bank versions after firmware update to catch variant mismatches.

### Firmware Download Source

Firmware is available from Ubiquiti's API:
```
https://fw-download.ubnt.com/data/{PRODUCT}/{prefix}-wave-{version}-{uuid}.bin
```

Where PRODUCT is:
- `GMC` for GigaBeam Connect (Wave-Pro, Wave-AP, Wave-AP-Micro, Wave-Pico)
- `MGMP` for Mini GigaBeam Micro/Pico (Wave-Nano, Wave-Micro, Wave-LR)

## References

- [Password management on UBNT airOS (Unimus Forum)](https://forum.unimus.net/viewtopic.php?t=1372)
- [ISP Wireless - Guide to Security for airOS Devices (UISP Help)](https://help.uisp.com/hc/en-us/articles/22590879672471-ISP-Wireless-Guide-to-Security-for-airOS-Devices)
- [GitHub - euphdk/airos-config](https://github.com/euphdk/airos-config)
