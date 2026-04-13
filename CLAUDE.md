# Network Provisioner - Claude Guidelines

## What This Is

A network equipment auto-provisioner running on an OrangePi at 192.168.10.120. It detects devices plugged into physical ports (VLAN-isolated), fingerprints them, and runs firmware updates + config apply via vendor-specific REST/SSH APIs. The UI is a touchscreen web app at port 8080.

## Architecture Rules

- **Handler properties control flow, not if/else in base.py.** The `provision()` method in `base.py` reads handler properties (`supports_dual_bank`, `config_after_all_firmware`, `fw2_skips_reboot`, etc.) to decide what to do. To change behavior for a device, override a property in the handler — do NOT add vendor-specific branching to `base.py`.
- **Properties can be conditional on model.** `self._device_info` is populated before properties are checked in `provision()`. A single handler can serve APs and switches with different behavior by checking the model in the property getter.
- **Vendor logic stays in vendor handlers.** No vendor-specific code in `base.py`, `port_manager.py`, `fingerprint.py`, or shared modules. The only vendor awareness in shared code is the `DeviceType` enum and `HANDLER_MAP`.
- **Config templates use deep merge, not placeholder substitution.** There is no `{{variable}}` engine. Templates are merged into the device's current config as-is. Do not add placeholder syntax to templates.
- **Two config/firmware paths exist.** Code deploys to `/opt/provisioner/` via `scripts/deploy.sh`. The active data repo is at `/var/lib/provisioner/repo/`. Config templates need to exist in the repo dir on the Pi to take effect. Deploy script syncs code but not the repo data dir.

## Provisioning Flow

Default order: Login -> Info -> FW1 -> Reboot -> Verify -> **Config -> Config Verify** -> FW2 -> Reboot -> Verify

When `config_after_all_firmware=True`: Login -> Info -> FW1 -> Reboot -> Verify -> FW2 -> Reboot -> Verify -> **Config (no verify)**

The default order is preferred for most devices. Only use `config_after_all_firmware` when config changes make the device unreachable (e.g., switching management VLAN/DHCP mode).

## Before Modifying

- Read `docs/HANDLER_DEVELOPMENT.md` for the handler property reference and provisioning flow
- Read `STANDARDS.md` for interface binding, VLAN isolation, and UI requirements
- Read `docs/cambium-config.md` before touching Cambium code — endpoints must be confirmed on hardware
- The Pi runs **Python 3.9** — do not use 3.10+ features (match/case, `X | Y` union types, `datetime.UTC`, `str.removeprefix`)
- Test on real hardware when possible. There is no simulator for most vendors.

## Adding New Vendors or Hardware

Follow the checklist in `docs/HANDLER_DEVELOPMENT.md` under "Adding a New Vendor" or "Adding a New Model to an Existing Vendor". The key touchpoints are:

1. `provisioner/handlers/{vendor}.py` — handler class
2. `provisioner/fingerprint.py` — device detection
3. `provisioner/port_manager.py` — boot-ping IPs (`DeviceLinkLocalIP`)
4. `provisioner/handler_manager.py` — `HANDLER_MAP`
5. `provisioner/firmware.py` — `MODEL_FIRMWARE_PATTERNS` + version regex
6. `provisioner/config_store.py` — `CONFIG_MODEL_ALIASES` (if needed)
7. `configs/templates/{vendor}/{model}.json` — config template

## Deployment

```bash
# Deploy code to Pi and restart service
./scripts/deploy.sh

# Config templates in the repo dir must be copied separately:
ssh orangepi@192.168.10.120
sudo -n cp /opt/provisioner/configs/templates/{vendor}/{file} /var/lib/provisioner/repo/configs/templates/{vendor}/{file}
```

## Common Mistakes to Avoid

- Adding vendor branching to `base.py` instead of using handler properties
- Using Python 3.10+ syntax (Pi runs 3.9)
- Forgetting to add new device IPs to the boot-ping list (causes 120s detection delay)
- Putting `{{placeholders}}` in config templates (no substitution engine exists)
- Only deploying code without copying templates to the repo dir on the Pi
- Making `config_after_all_firmware` globally true instead of conditional on model
- Checking `link_up` or `device_detected` before `last_result` in UI code — devices that change networks after config will have link down but should still show "COMPLETE"
- Clearing `last_result` or `checklist` in `_clear_port_state_on_disconnect()` without checking the grace period — the post-provisioning grace period (3 min) preserves these so the UI survives link loss
- Guessing Cambium API endpoints without hardware verification
