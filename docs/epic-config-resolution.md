# Epic: Config Resolution & Provisioning Profiles

> Status: Proposed · Tracking: issue #112 · Stories: #113–#120 · Prerequisite: epic #69 Phase 1 (`docs/epic-vendor-isolation-refactor.md`)

## Goal

The provisioner today answers "where does this device's config come from?" with "the one static template for this model." This epic replaces that with a **config resolver** choosing composable layers — **base template → site-role overlay → replacement overlay** — layered by a shared merge utility the resolver introduces (**R0 correction, review-verified:** the repo has no central template deep-merge today — the only one is internal to the Tachyon handler; Cambium merges device-side), adding:

1. **Roles:** some equipment configures for tower sites, some for business/home (also subsumes the planned infra-ZTP routing split).
2. **Replacement flows:** a new AP inherits its predecessor's SSID/key; a new PTP radio inherits its side's identity (static IP/subnet, DHCP vs OSPF) — all vendors where applicable.
3. **An operator UI that never requires spelling a vendor name:** plug in → auto-detected → three big buttons (New Home/Business · New Tower · Replacement).

**Explicitly not a rewrite.** The provisioning engine, handlers, fingerprinting, and kiosk stack stay. The audit (`docs/ARCHITECTURE_ISOLATION_REVIEW.md`) shows the engine is vendor-neutral and behaviorally sound; the recurring cross-vendor breakage comes from registry duplication, which epic #69 is eliminating. This epic adds one new layer *upstream* of handlers; handlers apply whatever config they're given, unchanged.

## R0 design corrections (2026-08-21 — PR #123 reviewed & verified against code)

The R0 design (`docs/design-config-resolution.md`, PR #123) contradicted four assumptions in this epic; all were **confirmed by adversarial review** with file:line evidence:

1. **No shared deep-merge exists** — only `TachyonHandler._deep_merge`; the resolver composes layers itself and materializes one job-scoped config file (also because `provision()` silently ignores `config_path` when inline `config` is present, `base.py:726-732`).
2. **Tachyon replacement is snapshot-as-base** (raw export replaces the template), not a field overlay — full-export semantics.
3. **Zero OSPF-shaped fields exist in the repo** — PTP "DHCP vs OSPF" identity mapping is entirely bench territory (H7); the schema only reserves `routing.{mode, area}`.
4. **Ubiquiti replacement is double-gated** — AirOS has no config-apply path at all; Wave apply defaults off (`apply_config_ubiquiti: False`).

R0 also defines hardware follow-ups H1–H10 and open decisions D1–D9 (see the doc); stories must defer to those instead of re-deciding.

## Design principles

- **No engine changes.** Resolver sits above `provision()`; the property contract is untouched.
- **Vendor-isolation rules apply** (`AGENTS.md`): the resolver never enumerates vendors; per-vendor knowledge lives in handler traits / templates / (future) VendorSpec.
- **Backward compatible by construction:** no role + no replacement selected ⇒ byte-identical to today's resolution (regression-tested in R1).
- **Snapshots are the fleet memory:** every unit crossing the bench can leave a snapshot behind (R3/R4), so replacement coverage grows organically; fleet-data import (R7) is the later fallback for dead predecessors.
- **Secrets discipline:** PSKs/keys live in the data dir only, field-level redaction map defined in R0, masked in UI/logs/API lists.

## Stories

| Story | Issue | Size | Depends on | Hardware-gated? |
|---|---|---|---|---|
| R0 — Design: resolver contract + snapshot schema | #113 | M | — (start now) | no (flags only) |
| R1 — Site-role overlays (tower vs home/business) | #114 | M | R0; prefer after #71–#74 | no |
| R2 — Kiosk operator flow (job type + picker) | #115 | M | R0, R1, R3; coord. #75 | **yes — touchscreen** |
| R3 — Snapshot store | #116 | M | R0 | no |
| R4 — Snapshot capture via handler trait | #117 | M/L | R0, R3; generalizes #44/#45/#46 | **yes — per vendor** |
| R5 — AP replacement (SSID/key) | #118 | M/L | R0, R1, R3, R4 | **yes — per vendor** |
| R6 — PTP A/B replacement (link identity) | #119 | L | R5 | **yes — per vendor** |
| R7 — Fleet-data import fallback (netbox) | #120 | L | external decisions | n/a (blocked) |

Sequencing: **R0 now** (parallel with epic #69 Phase 1) → R1 + R3 in parallel → R4 → R2 → R5 → R6. R7 when unblocked.

## Hardware / vendor / external follow-ups (decisions the repo cannot make — do NOT guess in PRs)

1. **Cambium:** any endpoint not already used by the handler must be hardware-confirmed (`docs/cambium-config.md` standing rule) — affects R4/R5/R6.
2. **Tachyon:** full-export (replace-not-merge) semantics vs overlay composition — R0 decides on paper, bench confirms.
3. **Ubiquiti:** AirMax vs Wave API split (`_api_style`); Wave-Nano is the historical edge case — R4 capture + R5/R6 apply need bench passes on both styles.
4. **MikroTik:** `.rsc`/netinstall config model doesn't fit JSON deep-merge snapshots; interacts with the planned infra-ZTP split → descoped from R4; needs a product decision (route by model or ask operator).
5. **Tarana:** config ≈ `operator_id` only — confirm replacement is a no-op and descope.
6. **PTP identity field maps per vendor** (which config keys encode static IP/prefix/OSPF params) — R0 mines templates/handlers; unresolved rows go to bench verification.
7. **Kiosk changes (R2, #75):** physical touchscreen walk-through before production (`deploy.sh --allow-branch` bench flow, `docs/BRANCHING.md`).
8. **Snapshot secrets policy sign-off** (product decision): storing customer PSKs on the bench host — retention, access, masking rules (R0 proposes, owner approves).
9. **R7 fleet source:** authoritative system for SSID/keys + PTP IP plans, read-only API access, bench-host connectivity policy.

## Definition of done

- R0–R5 merged and CI-green (3.9); no-selection path byte-identical to pre-epic behavior; kiosk flow verified on the touchscreen; per-vendor replacement paths individually bench-verified before production enablement; zero regressions in epic #69's `test_vendor_registry.py` contract.
