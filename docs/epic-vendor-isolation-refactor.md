# Epic: Vendor Isolation Refactor

> Status: Proposed · Owner: TBD · Source audit: `docs/ARCHITECTURE_ISOLATION_REVIEW.md`

## Goal

Make the provisioner *additively pluggable*, not just *subtractively modular*: adding or removing a vendor should be a small, single-place change instead of a 12–14 file hunt across 6–8 duplicated registries. Do this **without touching any vendor's provisioning behavior** and without regressing the production touchscreen kiosk.

## Problem (recap of the audit)

- **Behavior is well isolated (A-grade):** each vendor lives entirely in `handlers/{vendor}.py` (+ `firmware_sources/{vendor}.py` + `configs/templates/{vendor}/`). No handler imports another. The property-driven `provision()` flow holds.
- **Registration is leaky (C-grade):** the vendor list is duplicated across **6–8 independent sources of truth** with no single add/remove point. CLAUDE.md's claim — *"only the `DeviceType` enum and `HANDLER_MAP`"* — is inaccurate.
- The dominant failure mode of any vendor change is **omission**: forget an S1 site (handler import, `config.py↔main.py` credentials) and the service **crashes at boot**; forget an S2 site and you get **dead code or a silently-undetectable device**.

### The duplicated sources of truth (what this epic collapses)

| Concern | Current copies | Target |
|---|---|---|
| Vendor → handler | `HANDLER_MAP` (`handler_manager.py:24`), `cli.py:383`, `VALID_DEVICE_TYPES` (`api.py:1156`), `index.html:347` | 1 (derive from `HANDLER_MAP`/`DeviceType`) |
| Credentials | `CredentialsConfig` (`config.py:114`), `main.py:109` dict, handler `DEFAULT_CREDENTIALS`, `BUILTIN_CREDENTIALS` (`api.py:2086`) | 1 table (mirror `FirmwareSourceConfig`) |
| Link-local IPs | `DeviceLinkLocalIP` (`port_manager.py:112`) + inline copy (`:982`) + `DeviceIPsConfig` (`config.py:47`) | 1 registry |
| Detection knowledge | `HTTP_SIGNATURES` + per-vendor probes + `_extract_device_details` (`fingerprint.py`) | per-vendor contribution |
| Vendor-in-engine leak | `if self.device_type == "mikrotik"` (`base.py:395-403`) | handler property |

## Success criteria

1. Adding/removing a vendor touches **≤ 2 hand-edited locations** plus the vendor's own files.
2. A CI test fails if the registries ever drift out of sync.
3. The one engine-level rule violation (`base.py` MikroTik branch) is gone.
4. Zero behavioral change to provisioning, fingerprint *accuracy*, or the kiosk UI (existing tests stay green).
5. Reducing to a single-vendor build (Direction B) becomes a config/registry toggle, not a code carve.

## Non-goals (explicit scope guards)

- **Not** generalizing genuinely vendor-specific machinery: MikroTik netinstall/ZTP/BOOTP/OUI gating and the Evolution Digital passive cross-port flow stay as **documented exceptions**.
- **Not** removing any vendor in this epic — once Story 6 lands, removal becomes trivial and is a separate task.
- **No** changes to handler provisioning logic or the `provision()` property contract itself.

---

## Cross-cutting considerations (the "other considerations" check)

These constrain *how* every story is executed:

1. **Two-path deploy / config migration.** `scripts/deploy.sh` syncs code to `/opt/provisioner/` but **does not** touch `/etc/provisioner/config.yaml` or the `/var/lib/provisioner/repo/` data dir. Any schema change (Stories 3–4) ships safely *because* pydantic uses default `extra=ignore` (no `extra="forbid"` exists) — stale vendor keys in an old `config.yaml` parse harmlessly and defaults fill the rest. Still, each schema story must include a one-line host note. Config templates must already exist in the repo data dir to take effect.
2. **Python 3.9 only.** No `match`/`case`, no `X | Y` unions (use `Optional[...]`/`Dict[...]`), no `str.removeprefix`, no `datetime.UTC`. New registry code must follow this.
3. **No hardware simulator for most vendors.** Pure-enumeration refactors (Stories 0–5) are fully unit-testable and low-risk. Detection refactoring (Story 7) carries *behavioral* risk and must lean on existing detection tests (`test_fingerprint.py`, `test_mikrotik_detection_ui.py`, `test_mikrotik_edge_case_detection.py`) and preserve probe **ordering** (MikroTik :8728 short-circuit first, then Tachyon/Wave API probes, then HTTP/SSH/SNMP).
4. **CI is the safety net.** `.github/workflows/test.yml` runs the suite. Story 0 adds the registry-consistency test that becomes the regression guard for all later stories.
5. **Simple mode (no-switch ThinkPad).** `SimpleModeConfig` runs the *same* fingerprint + `DeviceLinkLocalIP.ALL` path on a single base interface (plus a subnet ARP-sweep). Stories 4 and 7 must preserve simple-mode detection, not just multi-port.
6. **Evolution Digital side-door.** ED is intentionally absent from `HANDLER_MAP` and dispatched from `main.py:438`/`:757`. Every registry change must keep this path intact (it needs cross-port access).
7. **Firmware sources already prove the pattern.** `Dict[str, FirmwareSourceConfig]` (`config.py:193`, `_default_firmware_sources()`) is the table-driven model to copy for credentials — don't reinvent.
8. **Kiosk UI is production.** Story 5 changes how `index.html` gets its vendor list; it must not break the live touchscreen. There's already a `/default-credentials` endpoint enumerating types — extend that pattern rather than add a parallel one.
9. **Tests assert the vendor set.** `test_handler_manager.py`, `test_config.py`, `test_fingerprint.py` encode the current list and will need updates as registries consolidate — expected, and formalized by Story 0.

---

## Stories

Each story is independently shippable as its own PR. Effort: S ≈ <½ day, M ≈ 1–2 days, L ≈ 3–5 days. Risk reflects behavioral blast radius given the no-simulator constraint.

### Story 0 — Registry-consistency contract test (foundation) · S · risk: none
**Why:** lock the current effective vendor set before changing anything, and expose drift.
**Scope:** add `tests/test_vendor_registry.py` asserting the *same* vendor set across `DeviceType` (minus `UNKNOWN`/`EVOLUTION_DIGITAL`), `HANDLER_MAP`, `cli.py` handler dict, `VALID_DEVICE_TYPES`, `CredentialsConfig` fields, `BUILTIN_CREDENTIALS`, `DeviceLinkLocalIP.ALL`, and (via a parsed-constant or rendered-endpoint check) the `index.html` vendor map. Document ED + Mock as known exceptions.
**Acceptance:** test passes today; deliberately breaking any one registry makes it fail. **Do this first** — it is the guard for Stories 2–7.

### Story 1 — Remove the MikroTik branch from the engine (S1 fix) · S · risk: low
**Why:** the only true architecture-rule violation; vendor name inside `base.py`.
**Scope:** replace `base.py:395-403` `firmware_lookup_key()` MikroTik branch with a handler property (e.g. `firmware_lookup_key(device_info) -> Optional[str]`, default `model`; `MikrotikHandler` returns `hardware_version`). 
**Acceptance:** no vendor string remains in `base.py`; `test_handler_properties.py` covers the override; MikroTik firmware lookup unchanged. Independent of all other stories.

### Story 2 — One source of truth for the handler registry · M · risk: low
**Why:** collapse 4 copies of the vendor→handler list (`HANDLER_MAP`, `cli`, `VALID_DEVICE_TYPES`, UI).
**Scope:** make `cli.py` and `VALID_DEVICE_TYPES` *derive* from `HANDLER_MAP`/`DeviceType` (add a helper like `provisionable_device_types()`), preserving the ED exception explicitly. 
**Acceptance:** deleting an entry from `HANDLER_MAP` propagates everywhere; Story 0 test still green; `test_handler_manager.py` updated.

### Story 3 — Table-drive credentials (kill the crash-coupling) · M · risk: low-med
**Why:** removes the `config.py ↔ main.py` AttributeError-on-omission (S1) and collapses 4 credential sources to 1.
**Scope:** convert `CredentialsConfig` typed fields → `Dict[str, DeviceCredentials]` keyed by device-type (mirror `FirmwareSourceConfig`), with per-vendor defaults supplied by a defaults factory. Reconcile `main.py:109` dict, `BUILTIN_CREDENTIALS` (`api.py:2086`), and handler `DEFAULT_CREDENTIALS` to read from this one table. 
**Migration note:** `extra=ignore` means existing `config.yaml` `credentials.<vendor>` blocks keep working; defaults backfill. Add host note in PR.
**Acceptance:** `test_config.py` covers the dict form; removing a vendor no longer requires editing `main.py`; credential UI (`/default-credentials`) unchanged.

### Story 4 — Centralize the IP / boot-ping registry · S · risk: low
**Why:** `DeviceLinkLocalIP` is duplicated (`port_manager.py:112` vs inline `:982`) and overlaps `DeviceIPsConfig` (`config.py:47`).
**Scope:** single structure for vendor→link-local IP(s); the inline list at `:982` and `DeviceIPsConfig` defaults derive from it; config still overrides. Preserve MikroTik fallbacks and simple-mode behavior.
**Acceptance:** one place defines IPs; `test_port_manager.py` green; simple-mode + multi-port both probe the same set.

### Story 5 — Frontend derives vendor metadata from the API · M · risk: med (UI)
**Why:** `index.html:347` is a hardcoded frontend copy of the vendor list.
**Scope:** extend/return vendor metadata (name, color, icon, default user) from a backend endpoint derived from the registry; `index.html` fetches it instead of hardcoding. Keep the two genuinely *behavioral* UI branches (`canApplyMode` cambium/tachyon `:966`; Tachyon SSID-uppercase `:1307`) but data-drive the list/labels.
**Acceptance:** kiosk renders identically; `test_web_pages.py`/`test_mikrotik_detection_ui.py` green; adding a vendor needs no JS edit.

### Story 6 — Vendor descriptor / plugin registry (capstone) · L · risk: med
**Why:** the end state — one place per vendor; makes add/remove and single-vendor builds a one-line change.
**Scope:** introduce `VendorSpec` (handler class, default creds, link-local IPs, firmware filename patterns, config-template dir, fingerprint signatures+probe ref, UI metadata) and a registry where each vendor registers once. Derive `DeviceType`, `HANDLER_MAP`, `MODEL_FIRMWARE_PATTERNS`, IP registry, and credential defaults from it. Gate behind Stories 2–4 proving the sub-patterns.
**Acceptance:** adding a vendor = add `handlers/x.py` + `firmware_sources/x.py` + templates + one `register(VendorSpec(...))`. Story 0 test green. A `VENDORS` allowlist makes Direction-B (single-vendor) a config toggle.

### Story 7 — Modularize fingerprint detection (optional, highest effort) · L · risk: med-high
**Why:** the largest leak by volume; today it's central switch/elif over `DeviceType`.
**Scope:** move each vendor's HTTP signatures, dedicated probe, and `_extract_device_details` branch into that vendor's spec/contribution; the fingerprinter iterates contributions in a defined order. **Must preserve probe ordering and confidence weights exactly.**
**Acceptance:** `test_fingerprint.py` + all `test_mikrotik_*detection*` green with byte-identical detection outcomes on fixtures; simple-mode detection preserved. Ship only if Stories 2–6 land and the win justifies the behavioral risk.

---

## Recommended sequence

```
Story 0 (guard) ──┬─> Story 1 (S1 quick win, parallel)
                  ├─> Story 2 ─> Story 5 (UI)
                  ├─> Story 3 ─┐
                  └─> Story 4 ─┴─> Story 6 (capstone) ─> Story 7 (stretch)
```

- **Phase 1 (low-risk, high-value):** 0, 1, 2, 3, 4 — pure enumeration consolidation, fully unit-tested, no behavioral risk. This alone gets you from "12–14 file edit" to "~2 places + vendor files" and kills both S1 issues.
- **Phase 2 (UI):** 5 — independent, needs kiosk verification.
- **Phase 3 (stretch):** 6 then 7 — the true plugin model and detection modularization; do only if the maintenance math justifies the effort and behavioral risk.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Forgetting a registry mid-refactor reintroduces drift | Story 0 consistency test is the gate for every later PR |
| Detection accuracy regression (Story 7) — no simulator | Preserve probe order/weights; assert byte-identical outcomes on existing fixtures; ship last |
| Host `config.yaml` mismatch after schema change | `extra=ignore` makes it safe; include host reconciliation note per PR; remember deploy.sh skips config + repo data dir |
| Kiosk UI breakage (Story 5) | Verify on the touchscreen path; keep behavioral branches; reuse existing `/default-credentials` endpoint pattern |
| Python 3.10+ syntax slips in | 3.9 reviewer check; CI runs on the 3.9 target |
| ED side-door or MikroTik netinstall accidentally "generalized" | Explicit non-goals; keep as documented exceptions; covered by `test_evolution_digital.py`, `test_bootp_auto_trigger.py`, `test_netinstall_packages.py` |

## Definition of done (epic)

- Stories 0–4 merged, CI green on the 3.9 target.
- A vendor can be added or removed by editing ≤ 2 shared locations + its own files, enforced by the Story 0 test.
- `base.py` contains no vendor brand strings.
- (If Phase 3 taken) `register(VendorSpec(...))` is the single add point and a `VENDORS` allowlist yields a single-vendor build.
