# Coding Architecture Standards

This file is the **tool-agnostic** statement of how this codebase is structured and the standards any contributor (human or agent) must follow. It is the canonical reference for *architecture & coding expectations*.

- For **host/deploy/kiosk operational details** and Claude-specific workflow, see `CLAUDE.md` (which points here for these standards).
- For the **current isolation state** and the exhaustive vendor-touchpoint map, see `docs/ARCHITECTURE_ISOLATION_REVIEW.md`.
- For the **refactor status and remaining work**, see `docs/epic-vendor-isolation-refactor.md`.
- For the **handler property reference**, see `docs/HANDLER_DEVELOPMENT.md`; for interface binding / VLAN / UI, see `STANDARDS.md`.
- For **UI work** (the pages in `provisioner/web/templates/`), load the `frontend-design` skill in `.claude/skills/frontend-design/`. It covers general design craft. The UI standards in `STANDARDS.md` §3 take precedence over it.

---

## The architecture in one paragraph

A device plugged into a VLAN-isolated port is detected by `port_manager`, classified by `fingerprint`, routed by `handler_manager` (`HANDLER_MAP`), and provisioned by `base.py`'s property-driven `provision()` flow calling into a vendor handler. The system has **two layers with very different isolation quality**:

- **Behavior layer (well isolated, keep it that way):** each vendor's logic lives entirely in `handlers/{vendor}.py` (+ `firmware_sources/{vendor}.py` + `configs/templates/{vendor}/`). No handler imports another. The provisioning *order* is decided by handler **properties**, never by `if vendor ==` in the engine.
- **Registration layer:** `provisioner/vendor_registry.py` owns vendor metadata in `VendorSpec` entries. Handler/firmware maps, defaults, IPs and UI/API/CLI lists derive from it. `DeviceType` remains explicit and is checked against the registry. Detection signatures and probes remain shared code.

The standards below preserve this isolation and its regression coverage.

The provisioning north star is separate from vendor enumeration: every
supported radio starts with the verified SM baseline, then may be explicitly
elevated to AP or PTP with a role-specific profile. A model's AP capture is
process evidence for that role, not a canonical template. It must not become
the default config for another model in the same firmware family. See
`docs/PROVISIONING_NORTH_STAR.md`.

---

## Standards (must-follow)

### 1. Vendor *behavior* belongs in handlers; flow is property-driven
Change device behavior by overriding a handler **property** (`supports_dual_bank`, `config_after_all_firmware`, `update_triggers_reboot`, `verify_active_bank`, `fw2_skips_reboot`, `supports_password_change`, …). Properties may be conditional on `self._device_info.model`. **Never** add vendor branching to `base.py`, `port_manager.py`, or `fingerprint`'s flow. `base.py` must contain **zero** vendor brand strings — and does, since Story 1 / #122 replaced the last stray `mikrotik` branch with the `firmware_lookup_key()` handler override. Keep it at zero.

### 2. Derive vendor enumeration from VendorSpec
`provisioner/vendor_registry.py` is the registration source. Do not add a vendor
list, sibling handler import, or parallel credential/IP/firmware registry.
`DeviceType` is an intentional explicit enum; consistency tests enforce its
agreement with specs. Detection signatures/probes are the remaining shared
vendor knowledge and require ordering/behavior tests.

### 3. Add vendors and models through their actual registration and resolver paths
Follow `docs/HANDLER_DEVELOPMENT.md`. A vendor needs its handler, optional
firmware source, reviewed templates/evidence, a `DeviceType` member, one
`VendorSpec` entry and detection support. Derived views need no manual entries.
A model uses its existing vendor's firmware patterns and registered
`ConfigFamilySpec`; test `ConfigStore` resolution before assuming an arbitrary
model directory will be used. Keep conditional model behavior in its handler.
Cover existing siblings as well as the new model. Finish with registry/golden,
detection, handler and full-suite checks plus the static/evidence gates.

### 4. Config templates: deep-merge, with an explicit mode-template exception
Standard provisioning templates are deep-merged into the device's live config as-is (shared semantics in `provisioner/config_merge.py`). They do not support `{{variable}}` substitution. The AP and PTP mode-change templates are an explicit exception: `provisioner/mode_config.py` renders their allowlisted variables before it applies them. Do not use placeholders in standard provisioning templates or in unrelated documentation. Registered model families take precedence; legacy aliasing lives in `config_store.py` `CONFIG_MODEL_ALIASES`. Template lookup runs through the vendor-neutral resolver seam (`provisioner/config_resolver.py` — R1 / #114), which can compose site-role overlays from `configs/templates/{vendor}/roles/{role}/`; see `docs/HANDLER_DEVELOPMENT.md` → "Site-Role Config Overlays". Role overlays must never contain secrets or identity fields.

Required model network settings belong in the sanitized model baseline and its
workflow checks. Do not make a technician remember a required setting or enter
it as an optional site value. Keep customer, tower, IP, and credential values
outside the baseline.

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
- Keep `test_vendor_registry.py` and `test_vendor_golden.py` green; they guard derived views, add/remove behavior, imports and ordering.

For hardware API, firmware, configuration, and verification changes, follow
`docs/BENCH_EVIDENCE.md`. Check the exact model and firmware evidence before
you infer an endpoint or payload. Keep raw HAR files and device backups in the
secure bench evidence directory, and commit only redacted structure fixtures
and confirmed facts.

### 9. Never leak secrets or private data
Credentials, keys, tokens, and PSKs (device passwords, `MIKROTIK_ZTP_API_KEY`, the fleet `bootstrap_password` / onboarding passphrase, RADIUS secrets) must never be echoed, logged, or passed as CLI arguments — they land in `ps`, shell history, and the **un-scrubbable** chat transcript. Inject via env (`SSHPASS=… sshpass -e`) or stdin; extract only the field you need from a credential response; confirm presence by length/mask, not value. A secret the user shares — or that you fetch — may be stored in a **gitignored** local file (`.context/*.env`, `chmod 600`) or auto-memory and referenced from there, never re-printed and never committed. If something leaks, scrub reachable artifacts (task outputs, `/tmp`, history) and report exactly what and where; never rotate fleet-wide MikroTik bootstrap/onboarding secrets unilaterally (the onboarding PSK means a whole-fleet reflash).

---

### 10. Field ownership and evidence decide values

Every config field has one owner (`fleet_policy`, `role`, `secret`,
`device_default`, `mode_action`); see `docs/PROVISIONING_NORTH_STAR.md`. A
handler declares one `FIELD_OWNERSHIP` table. `scripts/check_templates.py`
refuses a template that carries a secret, a device default, a site identity,
or an unclassified field. Every value in a template or handler table must
trace to a `values` path in a redacted bench fixture; a change starts with a
new fixture. A post-provision mode is offered only after both transition
directions are recorded in a bench manifest (`provisioner/qualification.py`).
Never write a device default. Never put a secret in a template. Before
changing a device endpoint or request shape, read the capture summary next to
the HAR (`bench-evidence/<vendor>/<model>/<firmware>/capture-summary.md`) and
cite it.

## Anti-patterns (do not do)

- Taking a config value from a chat, a screenshot, or a single field export instead of a committed fixture; or writing a field the contract classifies as a device default

- Vendor branching in `base.py` / shared modules instead of a handler property.
- Introducing another place that enumerates vendors instead of deriving from an existing registry.
- `{{placeholder}}` syntax in config templates.
- Python 3.10+ syntax.
- Removing a vendor by deleting its handler or firmware-source file but leaving its import / `SOURCE_MAP` / credentials / fingerprint / setup-tools per-vendor dict entries (S1 crash or S2 silent breakage).
- Generalizing the Evolution Digital side-door or MikroTik netinstall/OUI gating.
- Reordering fingerprint probes or changing confidence weights without fixture-backed verification.
- Echoing/logging a secret value or passing one as a CLI argument instead of via env/stdin; writing a secret to a committed file instead of a gitignored `.context/*.env`.

---

## Definition of a clean vendor change

The spec and enum agree, derived consumers update without manual vendor lists,
resolver and detection tests cover the new hardware and existing siblings, and
the full suite plus docs/Python 3.9/template/evidence gates pass. Record actual
hardware qualification separately. Adding a model never automatically validates
its family or authorizes copying captured secrets into a template.
