# Network Provisioner

Use this file for all agent instructions; `CLAUDE.md` is a symlink to it.
The provisioner detects VLAN-isolated devices and applies firmware and config through vendor handlers.
The Lenovo ThinkPad Yoga 11e host serves a touchscreen web UI on port 8080.

## Agent rules

These rules match `AGENT_LOOP_REPO_RULES` in `dev-host/config/network-provisioner-loop.env`. They apply to loop and worker agents.
Follow `AGENTS.md` and its `CLAUDE.md` symlink. Your scope is source code, redacted fixtures, docs, and local tests. Keep local pytest and CI green and code compatible with Python 3.11.

### Must not touch

- Do not change `/etc/provisioner/config.yaml` or systemd units.
- Do not access live provisioning hardware or call live device APIs.

### Must not do

- Do not run `scripts/deploy.sh`. Deploys and real-hardware tests are operator work.
- Loop agents do not run SSH commands. An interactive agent may SSH to the provisioner host only when the operator asks for it in that session. Read the current state first, and read it back after each change.
- Never merge a PR or cancel a CI run.
- Never echo, log, commit, or pass as a command-line argument a secret: device passwords, `MIKROTIK_ZTP_API_KEY`, the bootstrap password or onboarding passphrase, RADIUS secrets, keys, tokens, or PSKs. Inject via environment or stdin. Extract only the field needed from a credential response; confirm presence by length or mask.
- Store a shared or fetched secret only in a gitignored `.context/*.env` file with mode `600`. Never store secrets in memory or the transcript. If one leaks, scrub reachable artifacts (task outputs, `/tmp`, history) and report what leaked and where without repeating its value. Never rotate fleet-wide MikroTik bootstrap or onboarding secrets.
- Never put a secret or a device default in a template. Never write a device default. Never take a config value from chat, a screenshot, or a single field export, or guess a device API endpoint. Every template or handler value must trace to a committed, redacted bench-evidence fixture. Keep raw HAR files and device backups out of git; the secure host location is
  `/var/lib/provisioner/bench-evidence/`.

### Stop and label agent:needs-human if

- The issue needs real hardware, new bench evidence, a deploy, host access, or a change to a protected file above. The operator tests on real hardware when possible.

State any required host config change in the PR.

## Commands

Install CI dependencies with `pip install -e ".[dev,web,snmp]"`. CI tests Python 3.11 and 3.13.

```bash
pytest
python scripts/check_docs.py
python scripts/check_templates.py
python scripts/check_bench_evidence.py --all --repo-only
```

Safety CI also runs these checks with the versions pinned in `.github/workflows/safety.yml`:

```bash
gitleaks git --log-opts="<base>..<head>" --redact --no-banner --exit-code 1 .
actionlint -color
zizmor --min-severity high .github/workflows/
pip-audit --requirement requirements.txt --progress-spinner off
```

## Architecture

A device plugged into a VLAN-isolated port is detected by `port_manager`, classified by `fingerprint`, routed by `handler_manager` (`HANDLER_MAP`), and provisioned by `base.py`'s property-driven `provision()` flow calling into a vendor handler. The system has **two layers with very different isolation quality**:

- **Behavior layer (well isolated, keep it that way):** each vendor's logic lives entirely in `handlers/{vendor}.py` (+ `firmware_sources/{vendor}.py` + `configs/templates/{vendor}/`). No handler imports another. The provisioning *order* is decided by handler **properties**, never by `if vendor ==` in the engine.
- **Registration layer:** `provisioner/vendor_registry.py` owns vendor metadata in `VendorSpec` entries. Handler/firmware maps, defaults, IPs and UI/API/CLI lists derive from it. `DeviceType` remains explicit and is checked against the registry. Detection signatures and probes remain shared code.

The provisioning north star is separate from vendor enumeration: every
supported radio starts with the verified SM baseline, then may be explicitly
elevated to AP or PTP with a role-specific profile. A model's AP capture is
process evidence for that role, not a canonical template. It must not become
the default config for another model in the same firmware family. See
`docs/PROVISIONING_NORTH_STAR.md`.

## Standards (must-follow)

### 1. Vendor *behavior* belongs in handlers; flow is property-driven
`self._device_info` is populated before properties are checked in `provision()`. Change device behavior by overriding a handler **property** (`supports_dual_bank`, `config_after_all_firmware`, `update_triggers_reboot`, `verify_active_bank`, `fw2_skips_reboot`, `supports_password_change`, …). Properties may be conditional on `self._device_info.model`. **Never** add vendor branching to
`base.py`, `port_manager.py`, or `fingerprint`'s flow. `base.py` must contain **zero** vendor brand strings. Use the `firmware_lookup_key()` handler override for vendor-specific lookup keys.

Before instantiation, `config_store.py` and `main.py` read class-level traits through `HandlerManager.handler_class_for()` instead of branching on device type.

### 2. Derive vendor enumeration from VendorSpec
`provisioner/vendor_registry.py` is the registration source. Do not add a vendor
list, sibling handler import, or parallel credential/IP/firmware registry.
`DeviceType` is an intentional explicit enum; consistency tests enforce its
agreement with specs. Register specs in `DeviceType` declaration order. Put new device IPs in the spec address entry; missing IPs delay detection by 120 seconds. Detection signatures/probes are the remaining shared
vendor knowledge and require ordering/behavior tests.

Do not remove a vendor handler or firmware source without updating all derived consumers and detection support.

### 3. Add vendors and models through their actual registration and resolver paths
Follow `docs/HANDLER_DEVELOPMENT.md`. A vendor needs its handler, optional
firmware source, reviewed templates/evidence, a `DeviceType` member, one
`VendorSpec` entry and detection support. Derived views need no manual entries.
A model uses its existing vendor's firmware patterns and registered
`ConfigFamilySpec`; test `ConfigStore` resolution before assuming an arbitrary
model directory will be used. Keep conditional model behavior in its handler.
Update `tests/test_vendor_registry.py` and `tests/test_vendor_golden.py` in the same commit as an intentional vendor change. Run `rg -ni <vendor> provisioner/ configs/` before declaring done. Cover existing siblings as well as the new model. Finish with registry/golden,
detection, handler and full-suite checks plus the static/evidence gates.
Record actual hardware qualification separately. Adding a model never automatically validates its family.

### 4. Config templates: deep-merge, with an explicit mode-template exception
Standard provisioning templates are deep-merged into the device's live config as-is (shared semantics in `provisioner/config_merge.py`). They do not support `{{variable}}` substitution. The AP and PTP mode-change templates are an explicit exception: `provisioner/mode_config.py` renders their allowlisted variables before it applies them. Do not use placeholders in standard provisioning
templates or in unrelated documentation. Registered model families take precedence; legacy aliasing lives in `config_store.py` `CONFIG_MODEL_ALIASES`. Template lookup runs through the vendor-neutral resolver seam (`provisioner/config_resolver.py`), which can compose site-role overlays from `configs/templates/{vendor}/roles/{role}/`; see `docs/HANDLER_DEVELOPMENT.md` → "Site-Role Config
Overlays". Role overlays must never contain identity fields.

Full-export templates are classified by the handler's `is_full_config_export()` hook. Tachyon exports remain non-composable resolver inputs, but current 30x firmware requires a complete current-schema document at the POST boundary, so `TachyonHandler` completes the export from the live config before applying the export values. Do not generalize that vendor-specific compatibility behavior
into shared flow.

`main.py` uses the resolver, not `store.get_config_template()` directly. With no role, resolution is a byte-identical passthrough. Role composition is gated by `supports_config_overlays` (off fleet-wide until bench-verified).

Required model network settings belong in the sanitized model baseline and its
workflow checks. Do not make a technician remember a required setting or enter
it as an optional site value. Keep customer, tower, IP, and credential values
outside the baseline.

### 5. Python 3.11 floor
The ThinkPad Yoga host runs Python 3.13 (Debian 13). The supported floor is 3.11: no PEP 695 `type`/generic syntax, no `itertools.batched`, no `typing.override`. CI runs the tests on 3.11 and 3.13; there is no transpile step.

### 6. Respect the two-path deploy and config migration
Code deploys to `/opt/provisioner/`; data lives in `/var/lib/provisioner/repo/`; runtime config is `/etc/provisioner/config.yaml`. The operator runs `scripts/deploy.sh`; it syncs **code only** — not templates in the repo dir, not `config.yaml`. Pydantic uses default `extra=ignore` (no `extra="forbid"`), so schema changes are migration-safe: stale vendor keys in an existing `config.yaml`
parse harmlessly and defaults backfill. Templates must exist in the data repo on the ThinkPad Yoga to take effect. See `docs/HOST_SETUP.md` for the LAN IP, key path, and operator deploy/SSH commands. Production deploys use the `production` branch; see `docs/BRANCHING.md`.

### 7. Preserve the documented exceptions
These are intentional and must survive any refactor:

- **Evolution Digital** is deliberately *absent* from `HANDLER_MAP` and dispatched from `main.py` (passive cross-port flow). Keep the side-door.
- **MikroTik** netinstall/ZTP/BOOTP and the `MIKROTIK_OUIS` / ED-OUI gating are legitimately vendor-specific (they gate destructive operations). Do not "generalize" them away.
- **Fingerprint probe ordering and confidence weights** are load-bearing (e.g. MikroTik `:8728` short-circuits first). Preserve order when refactoring detection.

### 8. Testing expectations
There is **no hardware simulator** for most vendors, so:

- Pure-enumeration / registry changes are fully unit-testable → they must be covered, and CI (`.github/workflows/test.yml`) must stay green.
- Detection / handler-behavior changes carry real risk → lean on existing fixtures (`test_fingerprint.py`, `test_mikrotik_*detection*`, `test_handler_properties.py`, `test_provision_flow.py`) and assert **identical** outcomes.
- Keep `test_vendor_registry.py` and `test_vendor_golden.py` green; they guard derived views, add/remove behavior, imports and ordering.

For hardware API, firmware, configuration, and verification changes, follow
`docs/BENCH_EVIDENCE.md`. Check the exact model and firmware evidence before you infer an endpoint or payload. Commit only redacted structure fixtures and confirmed facts.

### 9. Field ownership and evidence decide values

Every config field has one owner (`fleet_policy`, `role`, `secret`,
`device_default`, `mode_action`); see `docs/PROVISIONING_NORTH_STAR.md`. A
handler declares one `FIELD_OWNERSHIP` table. `scripts/check_templates.py`
refuses a template that carries a secret, a device default, a site identity,
or an unclassified field. Values must trace to a `values` path in the committed fixture; a change starts with a new fixture. A post-provision mode is offered only after both transition
directions are recorded in a bench manifest (`provisioner/qualification.py`).
Before changing a device endpoint or request shape, read the capture summary next to
the HAR (`bench-evidence/<vendor>/<model>/<firmware>/capture-summary.md`) and
cite it.

### 10. Write GitHub text and code comments plainly

Every contributor, human or agent, follows these writing rules for the text
below. Use plain words. Put the bottom line first. Cut filler and AI tells.
An agent that starts a worker puts this rule in the worker's prompt.

Claude agents load the `ai-copywriter` skill before they write this text.
Other agents do not need that skill. They apply the rules in this section
directly.

The rule covers:

- issue and PR titles and bodies;
- PR comments, issue comments, and review-thread replies;
- commit messages, because GitHub shows them;
- sign-off packets and bot status comments;
- code comments and docstrings in new or changed code.

It does not require a rewrite of existing comments.

## Provisioning flow and UI rules

Default order: Login -> Info -> FW1 -> Reboot -> Verify -> **Config -> Config Verify -> Secrets** -> FW2 -> Reboot -> Verify

Config verify compares the field ownership contract's expectation set (`provisioner/field_ownership.py`). Secrets are written by `apply_secrets()` from the host credentials, never by a template.

When `config_after_all_firmware=True`: Login -> Info -> FW1 -> Reboot -> Verify -> FW2 -> Reboot -> Verify -> **Config (no verify)**

Only use `config_after_all_firmware` when config changes make the device unreachable (for example, management VLAN/DHCP changes). Make it conditional on model when models differ.

- Check `last_result` before `link_up` or `device_detected` in UI code, so link loss after config still shows "COMPLETE".
- Do not clear `last_result` or `checklist` in `_clear_port_state_on_disconnect()` without checking the 3-minute post-provisioning grace period.
- Call `display.wake()` in device-detect callbacks without gating on `display.is_sleeping()`. Native X DPMS can turn the screen off without changing `_sleeping`; `wake()` is idempotent.
- Do not add `xset s off` or `xset -dpms` to the openbox autostart. The kiosk relies on native X DPMS for idle off.
- Operator changes to `systemd/provisioner-web.service` must preserve `CAP_SETUID`/`CAP_SETGID` for `sudo -u kiosk` in `provisioner/display.py`; otherwise wake-on-connect falls back to backlight-only.

## Read before changing

- Handlers, models, and vendors: `docs/HANDLER_DEVELOPMENT.md`. Single-vendor builds use `PROVISIONER_VENDORS=<vendor>` in the service environment (operator only).
- Cross-vendor refactors: `docs/ARCHITECTURE_ISOLATION_REVIEW.md` and `docs/epic-vendor-isolation-refactor.md`.
- UI: load `.claude/skills/frontend-design/SKILL.md` for `provisioner/web/templates/` work; `STANDARDS.md` section 3 takes precedence. Read `STANDARDS.md` for interface binding and VLAN isolation too.
- Host/deploy/systemd (operator only): `docs/HOST_SETUP.md`; display, openbox autostart, and `image/auto-rotate.py` / `image/auto-rotate.service`: `docs/KIOSK_ARCHITECTURE.md`.
- Evidence: start with `docs/EVIDENCE_HANDOFF.md`, then `docs/BENCH_EVIDENCE.md`. The operator uses `docs/EVIDENCE_RUNBOOK.md` for captures; use `docs/EVIDENCE_CONTRIBUTING.md` for issues/PRs and `bench-evidence/INVENTORY.md` for missing records. Read `docs/cambium-config.md` for Cambium (operator confirms endpoints on hardware) and `docs/mikrotik-netinstall.md` before Netinstall/BOOTP
  changes (RouterOS 7.20+ device-mode, `-s`, and admin first-login quirks).
