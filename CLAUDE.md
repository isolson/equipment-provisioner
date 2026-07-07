# Network Provisioner - Claude Guidelines

## What This Is

A network equipment auto-provisioner running on a Linux host (currently a Lenovo ThinkPad Yoga 11e at 192.168.10.50 — see `docs/HOST_SETUP.md`). It detects devices plugged into physical ports (VLAN-isolated), fingerprints them, and runs firmware updates + config apply via vendor-specific REST/SSH APIs. The UI is a touchscreen web app at port 8080.

## Architecture Rules

- **Handler properties control flow, not if/else in base.py.** The `provision()` method in `base.py` reads handler properties (`supports_dual_bank`, `config_after_all_firmware`, `fw2_skips_reboot`, etc.) to decide what to do. To change behavior for a device, override a property in the handler — do NOT add vendor-specific branching to `base.py`. The same applies *before* instantiation: `config_store.py` and `main.py` read class-level traits (`allows_prefixed_config_exports`, `allows_arbitrary_template_fallback`, `config_alias_prefix_matching`, `requires_model_preflight`) via `HandlerManager.handler_class_for()` instead of `if device_type == "..."` — see `docs/HANDLER_DEVELOPMENT.md`.
- **Properties can be conditional on model.** `self._device_info` is populated before properties are checked in `provision()`. A single handler can serve APs and switches with different behavior by checking the model in the property getter.
- **Vendor *behavior* stays in vendor handlers.** No provisioning logic in `base.py`, `port_manager.py`, or `fingerprint.py`; `base.py` must contain **zero** vendor brand strings (it currently has one stray `mikrotik` check at `base.py:395-403` — don't add more, and prefer a handler property when you touch it). Vendor *enumeration*, by contrast, is **not** confined to the enum + `HANDLER_MAP` as older notes claimed — it is currently spread across ~10 registries (handler map, credentials ×4, link-local IPs, fingerprint signatures, firmware patterns, firmware-source `SOURCE_MAP`, CLI/API/UI lists, and setup-tools `SUPPORTED_DEVICE_TYPES`). **Standard: never add a *new* source of truth that lists vendors — derive from an existing one.** See `AGENTS.md` for the full standard and `docs/ARCHITECTURE_ISOLATION_REVIEW.md` for the touchpoint map; we are consolidating toward a single `VendorSpec` registry (`docs/epic-vendor-isolation-refactor.md`).
- **Config templates use deep merge, not placeholder substitution.** There is no `{{variable}}` engine. Templates are merged into the device's current config as-is. Do not add placeholder syntax to templates. Exception: *full-export* templates (e.g. Tachyon `.tar`/exported JSON) are applied authoritatively (replace, not merge) — the vendor handler decides (`TachyonHandler._is_full_config_export`); the shared loader (`provisioner/config_templates.py`) stays vendor-neutral and rejects `{{placeholders}}`.
- **Two config/firmware paths exist.** Code deploys to `/opt/provisioner/` via `scripts/deploy.sh`. The active data repo is at `/var/lib/provisioner/repo/`. Config templates need to exist in the repo dir on the Pi to take effect. Deploy script syncs code but not the repo data dir.

## Provisioning Flow

Default order: Login -> Info -> FW1 -> Reboot -> Verify -> **Config -> Config Verify** -> FW2 -> Reboot -> Verify

When `config_after_all_firmware=True`: Login -> Info -> FW1 -> Reboot -> Verify -> FW2 -> Reboot -> Verify -> **Config (no verify)**

The default order is preferred for most devices. Only use `config_after_all_firmware` when config changes make the device unreachable (e.g., switching management VLAN/DHCP mode).

## Before Modifying

- Read `docs/HANDLER_DEVELOPMENT.md` for the handler property reference and provisioning flow
- Read `AGENTS.md` for the coding-architecture standards (vendor isolation, the single-registry direction, and the anti-patterns to avoid)
- Read `STANDARDS.md` for interface binding, VLAN isolation, and UI requirements
- Read `docs/ARCHITECTURE_ISOLATION_REVIEW.md` (current isolation state + exhaustive vendor-touchpoint map) and `docs/epic-vendor-isolation-refactor.md` (the remediation plan) before any cross-vendor refactor
- Read `docs/HOST_SETUP.md` before touching deploy scripts or systemd units — covers the SSH-agent gotcha, `/etc` vs `/opt` config split, and required `CAP_SETUID`/`CAP_SETGID` for the display wake path
- Read `docs/KIOSK_ARCHITECTURE.md` before touching `provisioner/display.py`, the openbox autostart, `restart-kiosk.sh`, or `auto-rotate.*` — covers the startx-based session, same-uid X access, and the native-DPMS-vs-JS-sleep split
- Read `docs/cambium-config.md` before touching Cambium code — endpoints must be confirmed on hardware
- Read `docs/mikrotik-netinstall.md` before touching MikroTik Netinstall / BOOTP auto-trigger code — covers the RouterOS 7.20+ quirks (device-mode, `-s` replacing default-config, admin first-login lockout) that took multiple iterations to discover
- The host runs **Python 3.9** — do not use 3.10+ features (match/case, `X | Y` union types, `datetime.UTC`, `str.removeprefix`)
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
8. `provisioner/handlers/__init__.py` — import + `__all__` *(miss this → ImportError at boot)*
9. `provisioner/config.py` — `CredentialsConfig` field, `DeviceIPsConfig`, firmware-source default, any `apply_config_<vendor>` flag
10. `provisioner/main.py` — credentials dict *(must move in lockstep with #9 or AttributeError at boot)*
11. `provisioner/cli.py` — handler dict + `choices`
12. `provisioner/web/api.py` — `VALID_DEVICE_TYPES` + `BUILTIN_CREDENTIALS`; `provisioner/web/templates/index.html` — vendor metadata map
13. `provisioner/firmware_sources/__init__.py` — import + `__all__` *(miss this → ImportError at boot)*
14. `provisioner/firmware_checker.py` — `SOURCE_MAP` + the source imports *(miss either → ImportError at boot)*
15. `provisioner/setup_tools.py` — `SUPPORTED_DEVICE_TYPES` + the per-vendor readiness / credential-hint / config-mode dicts (first-run setup UI)

⚠️ This list is long *because* vendor enumeration isn't yet consolidated. Miss an **S1** site (#4, #8, #9, #10, #13, #14) and the service crashes at boot; miss an **S2** site and the device is silently undetectable or shows dead/missing setup-UI entries. Run `grep -rin <vendor> provisioner/ configs/` before declaring done. The exhaustive table is in `docs/ARCHITECTURE_ISOLATION_REVIEW.md`.

## Deployment

```bash
# Deploy code to host and restart service. Defaults to serveradmin@192.168.10.50.
# Refuses to run from branches other than 'production' — use --allow-branch to
# hardware-test a feature branch. See docs/BRANCHING.md for the promotion flow.
./scripts/deploy.sh

# Config templates in the repo dir must be copied separately:
ssh -i ~/.ssh/id_conductor serveradmin@192.168.10.50
sudo -n cp /opt/provisioner/configs/templates/{vendor}/{file} /var/lib/provisioner/repo/configs/templates/{vendor}/{file}
```

`deploy.sh` auto-detects `~/.ssh/id_conductor` and skirts the 1Password-agent issue; manual `ssh` outside the script may still need `-i ~/.ssh/id_conductor -o IdentitiesOnly=yes` — see `docs/HOST_SETUP.md`. `config.yaml` lives at `/etc/provisioner/config.yaml` at runtime — `deploy.sh` does NOT update it; see the install snippet in HOST_SETUP.

## Secrets & Private Data

Minimize the chance of leaking credentials, keys, or other private data — especially into the chat transcript, which **cannot be scrubbed afterward**.

- **Never echo or print a secret value** — passwords, API keys, tokens, WPA2/PSK, RADIUS secrets, the MikroTik `bootstrap_password` / onboarding passphrase, etc. When you fetch a credential, extract only the field you need into a variable; don't dump the whole response. Confirm presence with a length or masked form, never the value.
- **Never pass a secret as a command-line argument** — it's visible in `ps`, shell history, and the transcript. Inject via environment variable or stdin/heredoc. For SSH prefer keys; otherwise `SSHPASS=… sshpass -e …`, never `sshpass -p <value>`.
- **When the user shares a password/key — or you fetch one — you may store it in a safe place and must not echo it again.** A "safe place" is a gitignored local file (e.g. `.context/*.env`, `chmod 600`) or your auto-memory — never a committed file, never the transcript. Reference it from there (source the env file) instead of re-typing the value.
- **If a secret does leak**, scrub what's reachable (background-task output files, `/tmp` renders, shell history) and tell the user exactly what leaked and where so they can decide on rotation. Don't rotate fleet-wide secrets (MikroTik bootstrap/onboarding) unilaterally — the onboarding PSK rotation means reflashing the whole fleet.

## Common Mistakes to Avoid

- Echoing/printing a secret value, or passing one as a CLI arg (`sshpass -p`, secrets in argv) instead of via env/stdin — see **Secrets & Private Data** above
- Adding vendor branching to `base.py` instead of using handler properties
- Adding a *new* place that enumerates vendors (another hardcoded list/dict or `if device_type == "..."`) instead of deriving from an existing registry — the vendor list already has ~10 copies; don't make it 11
- Using Python 3.10+ syntax (Pi runs 3.9)
- Forgetting to add new device IPs to the boot-ping list (causes 120s detection delay)
- Putting `{{placeholders}}` in config templates (no substitution engine exists)
- Only deploying code without copying templates to the repo dir on the Pi
- Making `config_after_all_firmware` globally true instead of conditional on model
- Checking `link_up` or `device_detected` before `last_result` in UI code — devices that change networks after config will have link down but should still show "COMPLETE"
- Clearing `last_result` or `checklist` in `_clear_port_state_on_disconnect()` without checking the grace period — the post-provisioning grace period (3 min) preserves these so the UI survives link loss
- Guessing Cambium API endpoints without hardware verification
- Gating `display.wake()` on `display.is_sleeping()` in the device-detect callbacks — native X DPMS can turn the screen off without flipping our `_sleeping` flag, so the screen will stay dark even when a device plugs in. `wake()` is idempotent; just call it.
- Adding `xset s off` / `xset -dpms` to the openbox autostart or `restart-kiosk.sh` — that's the old "always on" behavior; the kiosk now relies on native X DPMS for idle off
- Removing `CAP_SETUID`/`CAP_SETGID` from `provisioner-web.service` — they're required for the `sudo -u kiosk` shell in `display.py`. Without them, sudo silently fails (rc=1) and wake-on-connect falls back to backlight-only (which doesn't turn the panel back on).
