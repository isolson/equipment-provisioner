# Coding Architecture Standards

This file is the **tool-agnostic** statement of how this codebase is structured and the standards any contributor (human or agent) must follow. It is the canonical reference for *architecture & coding expectations*.

- For **host/deploy/kiosk operational details** and Claude-specific workflow, see `CLAUDE.md` (which points here for these standards).
- For the **current isolation state** and the exhaustive vendor-touchpoint map, see `docs/ARCHITECTURE_ISOLATION_REVIEW.md`.
- For the **remediation plan** (consolidating the registries), see `docs/epic-vendor-isolation-refactor.md`.
- For the **handler property reference**, see `docs/HANDLER_DEVELOPMENT.md`; for interface binding / VLAN / UI, see `STANDARDS.md`.

---

## The architecture in one paragraph

A device plugged into a VLAN-isolated port is detected by `port_manager`, classified by `fingerprint`, routed by `handler_manager` (`HANDLER_MAP`), and provisioned by `base.py`'s property-driven `provision()` flow calling into a vendor handler. The system has **two layers with very different isolation quality**:

- **Behavior layer (well isolated, keep it that way):** each vendor's logic lives entirely in `handlers/{vendor}.py` (+ `firmware_sources/{vendor}.py` + `configs/templates/{vendor}/`). No handler imports another. The provisioning *order* is decided by handler **properties**, never by `if vendor ==` in the engine.
- **Registration layer (currently leaky, being consolidated):** the list of which vendors exist is duplicated across ~10 registries. There is not yet a single add/remove point.

The standards below exist to protect the first and shrink the second.

---

## Standards (must-follow)

### 1. Vendor *behavior* belongs in handlers; flow is property-driven
Change device behavior by overriding a handler **property** (`supports_dual_bank`, `config_after_all_firmware`, `update_triggers_reboot`, `verify_active_bank`, `fw2_skips_reboot`, `supports_password_change`, …). Properties may be conditional on `self._device_info.model`. **Never** add vendor branching to `base.py`, `port_manager.py`, or `fingerprint`'s flow. `base.py` must contain **zero** vendor brand strings (today it has exactly one stray `mikrotik` check at `base.py:395-403` — that is debt, not a pattern to copy; replace it with a property when you touch it).

### 2. Never add a *new* source of truth for vendor enumeration
The vendor list already exists in: `DeviceType` enum, `HANDLER_MAP`, `handlers/__init__.py`, `cli.py`, `web/api.py` `VALID_DEVICE_TYPES` + `BUILTIN_CREDENTIALS`, `index.html` vendor map, `config.py` (`CredentialsConfig`, `DeviceIPsConfig`, firmware sources, feature flags), `port_manager.py` `DeviceLinkLocalIP`, `firmware_checker.py` `SOURCE_MAP` (+ `firmware_sources/__init__.py` imports), and `setup_tools.py` `SUPPORTED_DEVICE_TYPES` (+ its readiness/hint/mode dicts). Credentials alone have **four** copies. When you need "the list of vendors," **derive it from an existing registry** (prefer `HANDLER_MAP`/`DeviceType`) — do not hardcode a new list, dict, or `if device_type == "..."`. The target end-state is a single `VendorSpec` registry (see the epic); move toward it, never away.

### 3. Adding/removing a vendor is a checklist, not a guess
Until the registry is consolidated, adding or removing a vendor means editing **all** of the sites in `CLAUDE.md` → "Adding New Vendors or Hardware" (12 touchpoints). Failure modes differ:
- **S1 / crash at boot** if you miss handler imports (`handler_manager.py`, `handlers/__init__.py`) or the `config.py ↔ main.py` credentials pair.
- **S2 / silently undetectable device or dead code** if you miss a fingerprint signature, IP entry, firmware pattern, or UI/CLI/API list.

Always finish with `grep -rin <vendor> provisioner/ configs/` and a green test suite.

### 4. Config templates: deep-merge, no placeholders
Templates are merged into the device's live config as-is. There is **no** `{{variable}}` substitution engine — don't add one. Model aliasing lives in `config_store.py` `CONFIG_MODEL_ALIASES`.

### 5. Python 3.9 target
No `match`/`case`, no `X | Y` unions (use `Optional[...]` / `Dict[...]`), no `str.removeprefix`, no `datetime.UTC`. CI runs on 3.9; there is no transpile step.

### 6. Respect the two-path deploy and config migration
Code deploys to `/opt/provisioner/`; data lives in `/var/lib/provisioner/repo/`; runtime config is `/etc/provisioner/config.yaml`. `scripts/deploy.sh` syncs **code only** — not templates in the repo dir, not `config.yaml`. Pydantic uses default `extra=ignore` (no `extra="forbid"`), so schema changes are migration-safe: stale vendor keys in an existing `config.yaml` parse harmlessly and defaults backfill. Still, note any required host config change in your PR.

### 7. Preserve the documented exceptions
These are intentional and must survive any refactor:
- **Evolution Digital** is deliberately *absent* from `HANDLER_MAP` and dispatched from `main.py` (passive cross-port flow). Keep the side-door.
- **MikroTik** netinstall/ZTP/BOOTP and the `MIKROTIK_OUIS` / ED-OUI gating are legitimately vendor-specific (they gate destructive operations). Do not "generalize" them away.
- **Fingerprint probe ordering and confidence weights** are load-bearing (e.g. MikroTik `:8728` short-circuits first). Preserve order when refactoring detection.

### 8. Testing expectations
There is **no hardware simulator** for most vendors, so:
- Pure-enumeration / registry changes are fully unit-testable → they must be covered, and CI (`.github/workflows/test.yml`) must stay green.
- Detection / handler-behavior changes carry real risk → lean on existing fixtures (`test_fingerprint.py`, `test_mikrotik_*detection*`, `test_handler_properties.py`, `test_provision_flow.py`) and assert **identical** outcomes.
- New registries should ship with a consistency test that fails if the duplicated vendor lists drift apart (see epic Story 0).

### 9. Never leak secrets or private data
Credentials, keys, tokens, and PSKs (device passwords, `MIKROTIK_ZTP_API_KEY`, the fleet `bootstrap_password` / onboarding passphrase, RADIUS secrets) must never be echoed, logged, or passed as CLI arguments — they land in `ps`, shell history, and the **un-scrubbable** chat transcript. Inject via env (`SSHPASS=… sshpass -e`) or stdin; extract only the field you need from a credential response; confirm presence by length/mask, not value. A secret the user shares — or that you fetch — may be stored in a **gitignored** local file (`.context/*.env`, `chmod 600`) or auto-memory and referenced from there, never re-printed and never committed. If something leaks, scrub reachable artifacts (task outputs, `/tmp`, history) and report exactly what and where; never rotate fleet-wide MikroTik bootstrap/onboarding secrets unilaterally (the onboarding PSK means a whole-fleet reflash).

---

## Anti-patterns (do not do)

- Vendor branching in `base.py` / shared modules instead of a handler property.
- Introducing a 9th place that enumerates vendors instead of deriving from an existing registry.
- `{{placeholder}}` syntax in config templates.
- Python 3.10+ syntax.
- Removing a vendor by deleting its handler or firmware-source file but leaving its import / `SOURCE_MAP` / credentials / fingerprint / `SUPPORTED_DEVICE_TYPES` entries (S1 crash or S2 silent breakage).
- Generalizing the Evolution Digital side-door or MikroTik netinstall/OUI gating.
- Reordering fingerprint probes or changing confidence weights without fixture-backed verification.
- Echoing/logging a secret value or passing one as a CLI argument instead of via env/stdin; writing a secret to a committed file instead of a gitignored `.context/*.env`.

---

## Definition of a clean vendor change

A vendor addition or removal is "done" when: the 12-point checklist is fully applied (or, post-consolidation, the single `VendorSpec` registry edited), `grep -rin <vendor>` shows no stragglers outside intended locations, the registry-consistency test passes, and the full suite is green on the Python 3.9 target.
