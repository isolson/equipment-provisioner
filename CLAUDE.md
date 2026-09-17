# Network Provisioner - Claude Guidelines

## What This Is

A network equipment auto-provisioner running on a Linux host (currently a Lenovo ThinkPad Yoga 11e at 192.168.10.50 — see `docs/HOST_SETUP.md`). It detects devices plugged into physical ports (VLAN-isolated), fingerprints them, and runs firmware updates + config apply via vendor-specific REST/SSH APIs. The UI is a touchscreen web app at port 8080.

## Architecture Rules

- **Handler properties control flow, not if/else in base.py.** The `provision()` method in `base.py` reads handler properties such as `supports_dual_bank`, `config_after_all_firmware`, and `fw2_skips_reboot`. To change behavior for a device, override a property in the handler. Do not add vendor-specific branching to `base.py`. The same rule applies before instantiation: `config_store.py` and `main.py` read class-level traits through `HandlerManager.handler_class_for()` instead of `if device_type == "..."`. See `docs/HANDLER_DEVELOPMENT.md`.
- **Properties can be conditional on model.** `self._device_info` is populated before properties are checked in `provision()`. A single handler can serve APs and switches with different behavior by checking the model in the property getter.
- **Vendor *behavior* stays in vendor handlers.** No provisioning logic in `base.py`, `port_manager.py`, or `fingerprint.py`; `base.py` must contain **zero** vendor brand strings (true since Story 1 / #122 replaced the last stray `mikrotik` branch with the `firmware_lookup_key()` handler override — keep it at zero). Vendor *enumeration* is consolidated into the `VendorSpec` registry (`provisioner/vendor_registry.py`, Story 6 / #76): one `register(VendorSpec(...))` per vendor, from which the handler map, firmware `SOURCE_MAP`, firmware patterns, credentials, IPs, UI metadata, and the CLI/API/setup lists all derive. Fingerprint signatures/probes are the remaining hand-kept vendor knowledge (Story 7 / #77). **Standard: never add a *new* source of truth that lists vendors — derive from the registry.** See `AGENTS.md` for the full standard and `docs/ARCHITECTURE_ISOLATION_REVIEW.md` for the touchpoint map (`docs/epic-vendor-isolation-refactor.md` is the epic).
- **Config templates use deep merge, with an explicit mode-template exception.** Standard provisioning templates are merged into the device's current config as-is (shared merge semantics live in `provisioner/config_merge.py`). They do not support `{{variable}}` substitution. AP and PTP mode-change templates are rendered by `provisioner/mode_config.py`; limit placeholders to those templates. Full-export templates are classified by the handler's `is_full_config_export()` hook. Tachyon exports remain non-composable resolver inputs, but current 30x firmware requires a complete current-schema document at the POST boundary, so `TachyonHandler` completes the export from the live config before applying the export values. Do not generalize that vendor-specific compatibility behavior into shared flow.
- **Template lookup goes through the config resolver.** `main.py` resolves templates via `provisioner/config_resolver.py` (R1 / #114), not by calling `store.get_config_template()` directly. With no role selected the resolver is a byte-identical passthrough of the plain lookup; with a role it composes site-role overlays from `configs/templates/{vendor}/roles/{role}/`, gated by the `supports_config_overlays` handler trait (off fleet-wide until bench-verified). See `docs/HANDLER_DEVELOPMENT.md` → "Site-Role Config Overlays".
- **Two config/firmware paths exist.** Code deploys to `/opt/provisioner/` via `scripts/deploy.sh`. The active data repo is at `/var/lib/provisioner/repo/`. Config templates need to exist in the repo dir on the Pi to take effect. Deploy script syncs code but not the repo data dir.

## Provisioning Flow

Default order: Login -> Info -> FW1 -> Reboot -> Verify -> **Config -> Config Verify -> Secrets** -> FW2 -> Reboot -> Verify

Config verify compares the field ownership contract's expectation set
(`provisioner/field_ownership.py`). Secrets are written by `apply_secrets()`
from the host credentials, never by a template.

Provisioning North Star: start every supported radio with the verified SM
baseline. Elevate to AP or PTP only through an explicit post-provision mode
workflow with its approved profile. A model's AP capture is evidence for that
role; it must not change the standard SM default or cross-apply to another
model in the same firmware family. See `docs/PROVISIONING_NORTH_STAR.md`.

When `config_after_all_firmware=True`: Login -> Info -> FW1 -> Reboot -> Verify -> FW2 -> Reboot -> Verify -> **Config (no verify)**

The default order is preferred for most devices. Only use `config_after_all_firmware` when config changes make the device unreachable (e.g., switching management VLAN/DHCP mode).

## Before Modifying

- Read `docs/HANDLER_DEVELOPMENT.md` for the handler property reference and provisioning flow
- Read `AGENTS.md` for the coding-architecture standards (vendor isolation, the single-registry direction, and the anti-patterns to avoid)
- Read `STANDARDS.md` for interface binding, VLAN isolation, and UI requirements
- Read `docs/ARCHITECTURE_ISOLATION_REVIEW.md` (current isolation state + exhaustive vendor-touchpoint map) and `docs/epic-vendor-isolation-refactor.md` (the remediation plan) before any cross-vendor refactor
- Read `docs/HOST_SETUP.md` before touching deploy scripts or systemd units — it covers the SSH-agent issue, the `/etc` versus `/opt` config split, and the required `CAP_SETUID`/`CAP_SETGID` capabilities for the display wake path
- Read `docs/KIOSK_ARCHITECTURE.md` before touching `provisioner/display.py`, the openbox autostart, `restart-kiosk.sh`, or `auto-rotate.*` — covers the startx-based session, same-uid X access, and the native-DPMS-vs-JS-sleep split
- Read `docs/cambium-config.md` before touching Cambium code — endpoints must be confirmed on hardware
- Read `docs/PROVISIONING_NORTH_STAR.md` for field ownership (one owner per
  field) and qualification (evidence decides which modes are offered). A
  template or handler value must trace to a fixture under `bench-evidence/`.
- Read `docs/EVIDENCE_RUNBOOK.md` to capture evidence and
  `docs/EVIDENCE_CONTRIBUTING.md` to turn it into an issue and PR;
  `bench-evidence/INVENTORY.md` lists what is missing per record.
- Read `docs/BENCH_EVIDENCE.md` before hardware-related handler changes. Each
  capture has a `capture-summary.md` next to it (repo record and bench host);
  read it before inferring an endpoint. Raw HARs live only on the host under
  `/var/lib/provisioner/bench-evidence/`. Check
  the exact model and firmware evidence before inferring an API endpoint or
  configuration shape. Keep raw HAR files and device backups outside git;
  record redacted facts and regression tests in the repository.
- Read `docs/mikrotik-netinstall.md` before touching MikroTik Netinstall / BOOTP auto-trigger code — covers the RouterOS 7.20+ quirks (device-mode, `-s` replacing default-config, admin first-login lockout) that took multiple iterations to discover
- The host runs **Python 3.9** — do not use 3.10+ features (match/case, `X | Y` union types, `datetime.UTC`, `str.removeprefix`)
- Test on real hardware when possible. There is no simulator for most vendors.

## Adding New Vendors or Hardware

Follow the checklist in `docs/HANDLER_DEVELOPMENT.md` under "Adding a New Vendor" or "Adding a New Model to an Existing Vendor". Since the VendorSpec registry landed (Story 6 / #76), the touchpoints are:

1. `provisioner/handlers/{vendor}.py` — handler class
2. `provisioner/firmware_sources/{vendor}.py` — firmware source class (only if the vendor has an auto-fetch source; Tarana doesn't)
3. `provisioner/fingerprint.py` — `DeviceType` enum member + detection signatures/probes (detection is the one area not yet in the registry — Story 7 / #77)
4. `provisioner/vendor_registry.py` — **one `register(VendorSpec(...))` call**, in `DeviceType` declaration order: handler class, firmware source class + checker defaults, factory credentials, link-local IPs, model→firmware patterns, UI name/color. Everything else derives: `HANDLER_MAP`, `SOURCE_MAP`, `MODEL_FIRMWARE_PATTERNS`, the IP/boot-ping/`DeviceIPsConfig` views, `_default_credentials()`/`_default_firmware_sources()`, `BUILTIN_CREDENTIALS`, kiosk vendor cards, and the CLI/API/setup device-type lists.
5. `configs/templates/{vendor}/{model}.json` — config template (+ `CONFIG_MODEL_ALIASES` in `config_store.py` if the API-reported model name differs)

Do **not** re-list the vendor anywhere else: `handlers/__init__.py` and `firmware_sources/__init__.py` deliberately no longer import vendor modules (the old ImportError-at-boot class), `main.py`/`cli.py`/`web/api.py`/`setup_tools.py` derive their lists, and per-vendor hint dicts (`setup_tools.py`, `mode_config.py`, `config_store.py`) are `.get()`-tolerant of a missing vendor. `tests/test_vendor_registry.py` fails CI on spec↔enum↔view drift; `tests/test_vendor_golden.py` locks the current values — update both in the same commit as an intentional vendor change. Run `grep -rin <vendor> provisioner/ configs/` before declaring done. Single-vendor builds: set `PROVISIONER_VENDORS=<vendor>` in the service environment.

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

- **Never echo or print a secret value** — passwords, API keys, tokens, WPA2/PSK values, RADIUS secrets, and MikroTik bootstrap or onboarding passphrases. When you fetch a credential, extract only the required field into a variable. Do not dump the whole response. Confirm presence with a length or masked form, never the value.
- **Never pass a secret as a command-line argument** — it's visible in `ps`, shell history, and the transcript. Inject via environment variable or stdin/heredoc. For SSH prefer keys; otherwise `SSHPASS=… sshpass -e …`, never `sshpass -p <value>`.
- **When the user shares a password/key — or you fetch one — you may store it in a safe place and must not echo it again.** A "safe place" is a gitignored local file (e.g. `.context/*.env`, `chmod 600`) or your auto-memory — never a committed file, never the transcript. Reference it from there (source the env file) instead of re-typing the value.
- **If a secret does leak**, scrub what's reachable (background-task output files, `/tmp` renders, shell history) and tell the user exactly what leaked and where so they can decide on rotation. Don't rotate fleet-wide secrets (MikroTik bootstrap/onboarding) unilaterally — the onboarding PSK rotation means reflashing the whole fleet.

## Common Mistakes to Avoid

- Echoing/printing a secret value, or passing one as a CLI arg (`sshpass -p`, secrets in argv) instead of via env/stdin — see **Secrets & Private Data** above
- Adding vendor branching to `base.py` instead of using handler properties
- Adding a *new* place that enumerates vendors (another hardcoded list/dict or `if device_type == "..."`) instead of deriving from an existing registry — the vendor list peaked at ~10 copies and Phase 1 of the isolation epic just collapsed several; don't add one back
- Using Python 3.10+ syntax (Pi runs 3.9)
- Forgetting to add new device IPs to the vendor-IP registry (`provisioner/vendor_ips.py` — the boot-ping list derives from it; a missing IP causes 120s detection delay)
- Putting `{{placeholders}}` in config templates (no substitution engine exists)
- Only deploying code without copying templates to the repo dir on the Pi
- Making `config_after_all_firmware` globally true instead of conditional on model
- Checking `link_up` or `device_detected` before `last_result` in UI code — devices that change networks after config will have link down but should still show "COMPLETE"
- Clearing `last_result` or `checklist` in `_clear_port_state_on_disconnect()` without checking the grace period — the post-provisioning grace period (3 min) preserves these so the UI survives link loss
- Guessing Cambium API endpoints without hardware verification
- Gating `display.wake()` on `display.is_sleeping()` in the device-detect callbacks — native X DPMS can turn the screen off without flipping our `_sleeping` flag, so the screen will stay dark even when a device plugs in. `wake()` is idempotent; just call it.
- Adding `xset s off` / `xset -dpms` to the openbox autostart or `restart-kiosk.sh` — that's the old "always on" behavior; the kiosk now relies on native X DPMS for idle off
- Removing `CAP_SETUID`/`CAP_SETGID` from `provisioner-web.service` — they're required for the `sudo -u kiosk` shell in `display.py`. Without them, sudo silently fails (rc=1) and wake-on-connect falls back to backlight-only (which doesn't turn the panel back on).
