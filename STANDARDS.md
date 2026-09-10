# Network Provisioner Development Standards

This document defines the technical standards and constraints that MUST be followed when developing or modifying this codebase. Review this document before making changes.

## 1. Network Interface Handling

### VLAN Isolation
- Each physical port maps to a dedicated VLAN interface (eth0.1991-eth0.1996 for ports 1-6)
- Devices on different ports MUST be completely isolated from each other
- Never assume traffic will route correctly based on IP alone

### Interface Binding
- **CRITICAL**: When making network connections to devices, you MUST bind to the specific interface, not just the local IP address
- Python's `socket.bind()` or aiohttp's `local_addr` parameter is NOT sufficient when multiple interfaces share the same subnet (e.g., 169.254.x.x link-local addresses)
- Use `SO_BINDTODEVICE` socket option or subprocess tools with `--interface` flag (e.g., `curl --interface eth0.1992`)
- Always pass the interface name through the handler chain - never lose track of which interface a device was discovered on

### Link-Local Addressing
- Devices use link-local addresses (169.254.x.x) which are interface-scoped
- The same IP (e.g., 169.254.1.1) may exist on multiple interfaces simultaneously
- Routing tables cannot distinguish between same-subnet destinations on different interfaces without explicit interface binding

## 2. Multi-Vendor Device Support

### Handler Architecture
- Each device vendor MUST have its own handler class in `provisioner/handlers/`
- All handlers MUST inherit from `BaseHandler` and implement the required interface
- Vendor-specific logic stays in vendor handlers - no vendor code in shared modules

### Handler Interface Contract
All handlers must implement:
```python
async def connect(self) -> bool
async def disconnect(self) -> None
async def get_info(self) -> DeviceInfo
async def backup_config(self) -> bytes
async def apply_config(self, config: Dict[str, Any]) -> bool
async def upload_firmware(self, firmware_path: str) -> bool
async def update_firmware(self, bank: Optional[int] = None) -> bool
async def reboot(self) -> bool
async def get_firmware_version(self) -> str
```

### Handler Behavior Properties
Handlers override properties to control the provisioning flow — do NOT add vendor branching to `base.py`. See `docs/HANDLER_DEVELOPMENT.md` for the full property reference. Key properties: `supports_dual_bank`, `update_triggers_reboot`, `verify_active_bank`, `fw2_skips_reboot`, `config_after_all_firmware`, `supports_password_change`.

### Device Detection
- Fingerprinting logic determines device type from HTTP responses, banners, and other protocol evidence.
- Never assume device type based on IP address alone
- Detection must work with devices in factory-default state

### Credentials
- Each vendor may have different credential formats and defaults
- Handlers receive credentials via constructor - never hardcode credentials

### Login Flow (Credential Priority)
The provisioner attempts authentication in this order:

1. **Default/Built-in Credentials** - The configured factory credentials for each device type
2. **User-Configured Credential** - A single credential per device type that users can set via the UI settings page
3. **Interactive Prompt** - If both above fail, the UI prompts the user to enter credentials manually

This flow ensures:
- Zero-touch provisioning works for factory-default devices
- Fleet-wide custom credentials can be pre-configured
- One-off devices with unique passwords can still be provisioned

Implementation notes:
- The handler should attempt credentials in order and stop on first success
- Failed login attempts should be logged but not block the flow
- Interactive prompt should timeout after reasonable period (60s)
- Never store user-entered credentials permanently without explicit consent

## 3. User Interface Standards

### Target Hardware
- Primary display: 7" touchscreen (800x480 or 1024x600)
- Touch input only - no keyboard/mouse assumed
- Outdoor/bright light viewing conditions

### Touch Target Sizing
- Minimum touch target: 44x44 CSS pixels (per Apple HIG)
- Recommended button size: 48x48 pixels or larger
- Spacing between touch targets: minimum 8px

### Button Styling
```css
/* Standard button */
.btn {
    min-height: 48px;
    min-width: 48px;
    padding: 12px 24px;
    font-size: 16px;
    border-radius: 8px;
}

/* Large action button */
.btn-lg {
    min-height: 64px;
    padding: 16px 32px;
    font-size: 18px;
}
```

### Layout Guidelines
- Use large, clear status indicators
- Prefer single-column layouts for main content
- Keep navigation simple - avoid deep hierarchies
- Use high contrast colors for readability
- Progress indicators must be clearly visible

### Theme
The kiosk uses a light, high-contrast operations-console theme for the outdoor
7-inch panel: page `#eef1f6`, white panels with `#cfd6e2` borders, dark ink
`#0f172a`, and one tone per status phase (idle `#94a3b8`, active `#0369a1`,
success `#15803d`, warning `#b45309`, error `#b91c1c`) on pale tints. Status is
never color alone; each tone pairs with an icon and a word. The
header shows the deployed git version and a live-updates dot. A stale banner
appears when no update arrived for three broadcast intervals; the page
reconnects forever with capped backoff.

### Port Card Design
Each port card (250px, 200px in portrait) has a left status rail and three zones:
- **Identity strip** — vendor pill in the registry color, model, port badge, link speed.
- **Status center** — 56px icon, uppercase headline, one-line detail, and a progress bar when a run or mode change is active. All of it comes from the server presentation state (`workflow_actions.presentation_for_port`), so the card can never disagree with the modal.
- **Footer strip** — mode chip (`SM VERIFIED`, `AP tw05-north`, `PTP-A`) or a hint.

Cards are built once and patched only when their state changes; no full re-render.

### Port Sheet
Tapping a card opens a full-height sheet with fixed regions and a fixed action bar:
- **Summary** — MAC, serial, IP, link, firmware, hostname and link id when deployed.
- **Notice** — one in-sheet panel for the current phase, failure, or confirmation. Native `alert()` and `confirm()` are not used.
- **Timeline** — the server-owned event log (`GET /api/ports/{n}/events`, WebSocket `port_event`). It survives page reloads and Chromium respawns. Verify failures show mismatch field names, never values.
- **Actions** — server-provided workflow actions only. Unqualified modes are listed with the reason (`PTP not qualified for ePMP 4518 on 5.11.1: no bench evidence`). Service actions (Netinstall) stay behind a collapsed section.
- **Action bar** — one contextual retry on failure, `Done` otherwise. Every touch target is at least 48px high with 12px gaps.

### Mode Change Flow
One flow for AP, PTP, and Restore SM: parameters, live preview from
`POST /api/ports/{n}/mode-preview` (current and target mode, the identity
fields that change, PTP side and peer, profile), an explicit confirm screen,
then progress from the mode job and the timeline. The preview never reserves
a PTP side; the apply reserves it once.

### Responsive Behavior
- UI must work at 800x480 minimum
- Test all views at target resolution before deployment
- Scrolling should be smooth and predictable

## 4. Security Requirements

### Credential Storage
- Never store credentials in code or version control
- Use the secrets management system (`/var/lib/provisioner/secrets/`)
- Credentials file permissions: 600 (owner read/write only)

### Network Security
- Provisioner operates on isolated management VLANs
- Device traffic never crosses VLAN boundaries
- No internet access required or expected from provisioner

### Input Validation
- Validate all user inputs before use
- Sanitize filenames and paths to prevent directory traversal
- Validate IP addresses and network parameters

### Firmware Handling
- Verify firmware checksums before upload
- Store firmware files with restricted permissions
- Log all firmware operations for audit trail

## 5. Code Organization

### Directory Structure
```
provisioner/
├── handlers/          # Vendor-specific device handlers
│   ├── base.py       # Base handler interface
│   ├── cambium.py    # Cambium device handler
│   ├── tarana.py     # Tarana device handler
│   └── tachyon.py    # Tachyon device handler
├── web/              # Web UI and API
│   ├── api.py        # REST API endpoints
│   └── templates/    # HTML templates
├── port_manager.py   # Port/VLAN management
├── device_db.py      # Device database
└── github_sync.py    # Config/firmware sync
```

### Naming Conventions
- Handlers: `{Vendor}Handler` (e.g., `TaranaHandler`)
- API endpoints use the `/api/{resource}/{action}` format.
- Config files: `{vendor}-{serial}.json`

### Error Handling
- Log all errors with sufficient context for debugging
- Include device IP, interface, and operation in error messages
- Never silently swallow exceptions
- Provide user-friendly error messages in UI

### Logging
- Use structured logging with consistent format
- Log levels: DEBUG for development, INFO for operations, ERROR for failures
- Include timestamp, component, and context in all log messages

## 6. Testing Requirements

### Before Deployment
- Test with actual hardware when possible
- Verify interface binding works correctly
- Test concurrent operations on multiple ports
- Verify UI at target screen resolution

### Device Testing Checklist
- [ ] Device detection works
- [ ] Login/authentication succeeds
- [ ] Device info retrieval works
- [ ] Config backup works
- [ ] Config apply works (if implemented)
- [ ] Firmware upload works
- [ ] Firmware activation works
- [ ] Device reboot and reconnection works

## 7. Cambium ePMP Handler Rules

> **Full API reference**: See `docs/cambium-config.md`

### Do NOT Guess Cambium Endpoints
- Cambium's web API is undocumented and varies by firmware version
- Every endpoint used in `cambium.py` MUST be documented in `docs/cambium-config.md` as CONFIRMED
- If you need a new endpoint, it must be verified on real hardware via browser dev tools first
- Do NOT write code that tries multiple endpoint paths hoping one works

### Config Apply Constraints
- **Full JSON config files** → use `config_import` (multipart upload with `skipIllegal=1`, poll for `applyFinished`)
- **Individual field changes** (SSID, hostname, AP naming) → use `set_param` (form-encoded, immediate)
- **`set_param` does NOT work** for full config dumps (~273+ keys) — returns `success: 0`
- **Do NOT use `set_param` for full config apply. Use `config_import` instead.**
- The device applies config asynchronously after `config_import` — must poll `get_param` with `applyStatusNeeded=true`

### SM vs AP Config
- **SM config** is used during provisioning (subscriber module default config)
- **AP config** (`ap.json`) is ONLY used post-provisioning for AP naming via `apply_ap_naming()`
- Template resolver excludes files starting with `ap` from the default fallback search
- Model aliases map device models to specific SM config templates (e.g., `ePMP 4518` → `f4518-sm-defaultconfig`)

### Config Template Format
- Templates use flat `device_props` key names (e.g., `wirelessInterfaceSSID`)
- The provisioner wraps flat keys into `{"device_props": {...}, "template_props": {"config_id": "0"}}` automatically
- Metadata keys (`_comment`, `_auto_injected_fields`) are stripped before sending
- Non-settable keys (tables, certificates, read-only hardware info) are filtered automatically

### When Modifying cambium.py
1. Read `docs/cambium-config.md` first
2. Check if the endpoint/behavior you need is marked CONFIRMED
3. If UNCONFIRMED, stop — ask the user to capture it from browser dev tools
4. After confirming new behavior, update `docs/cambium-config.md` before writing code
5. Test on real hardware — the provisioner has no Cambium simulator

## 8. Common Pitfalls (All Vendors)

### Avoid These Mistakes
1. **Assuming routing works**: Always explicitly bind to interface
2. **Hardcoding IPs**: Devices may have different IPs in different states
3. **Ignoring timeouts**: Network operations need appropriate timeouts
4. **Blocking the event loop**: Use async I/O for all network operations
5. **Losing interface context**: Always pass interface through the call chain
6. **Small touch targets**: Test button sizes on actual touchscreen
7. **Vendor-specific code in shared modules**: Keep vendor logic isolated
8. **Breaking the post-config link-loss pattern**: Devices using `config_after_all_firmware` go unreachable after config apply. The port manager's grace period preserves `last_result`/`checklist`, and the UI checks `last_result` before `link_up`. See `docs/HANDLER_DEVELOPMENT.md` "Post-Config Link Loss" for the full chain

---

*Last updated: 2026-04-09*
*Review this document when making architectural changes or adding new device support.*
