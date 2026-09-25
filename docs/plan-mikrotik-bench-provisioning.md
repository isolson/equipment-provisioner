# Plan: MikroTik Bench Provisioning (Business Routers + Site Infra)

> Status: Proposed · Companion docs: `docs/mikrotik-netinstall.md` (the existing
> customer-gateway pipeline — **unchanged by this plan**), `docs/design-config-resolution.md`
> (resolver seam, roles, snapshot schema), `docs/epic-config-resolution.md` (R2 kiosk
> job-intent picker, R7 fleet-data source — this plan unblocks R7's "netbox?" cell),
> `AGENTS.md` (vendor-isolation standards).
>
> This is a planning document. It changes no production code. §2 is the
> **assumptions register** — every question the requester did not answer is
> resolved there with a default and a rationale; veto by editing the row, not by
> re-deciding in a PR.

## 0. Decisions already made (requester, 2026-08-29)

These are fixed inputs. Do not re-litigate them in stories.

| # | Decision |
|---|---|
| D1 | Goal: plug-and-play in the field. Bench flashes + configures; **success = deployment-ready** (unbox at site, cable it, done). |
| D2 | Provisioner generates configs itself, and must work **without internet**. Ops validation is a **tie-in**, not a dependency: when ops is reachable it validates; when not, a tech may **bypass** and continue. |
| D3 | Cached data is the offline solution (not "refuse when offline"). |
| D4 | **Live device config is canonical; NetBox must match what's live.** NetBox is the fleet record; the provisioner writes what it actually applied. |
| D5 | Provisioner is standalone (direct L2 connectivity to the device) — nothing in this plan may require a cloud-side step to *apply* config. |
| D6 | In scope: **business routers** (businesses/prosumers with UniFi APs): hEX S, hEX PoE, PowerBox Pro, RB4011, RB5009, L009, etc. Normally factory-new with per-unit default login credentials (RouterOS 7 sticker password). |
| D7 | In scope: **site router = RB5009**, **site switch = netPower 16P**. |
| D8 | Out of scope: core routers; customer MikroTik WiFi gateways (existing `docs/mikrotik-netinstall.md` pipeline stays as-is); UniFi APs (TBD, not this plan); Cisco business switches (not MikroTik). |
| D9 | **#1 North Star: never break existing vendors.** No re-testing of unrelated vendors for a MikroTik change. |
| D10 | UI: the tech sees options **on the port card of the port the device is on**; anyone touching the screen may operate it (no login). Auto-detect as smart as possible; selection narrows **broad device class → specific (site number)**. |
| D11 | Config generation happens **after** confirmation; **Back** is allowed at every step; the confirmation is a **summary with no assumptions** (every value the config will contain is shown). |
| D12 | A device that arrives in **Netinstall (BOOTP)** may have destructive actions (reflash) applied automatically; the final confirmation of the *selected options* is still required before the generated config is applied. |
| D13 | Netinstall is how we **skip credentials** on factory-new units. |
| D14 | Print a label: identity, class, WAN MAC as configured, plus serial/model. |

## 1. What exists today (and what this plan reuses)

| Existing piece | Reused how |
|---|---|
| Per-port BOOTP listener → `main._on_port_device_in_bootp` → `api._run_netinstall` (`docs/mikrotik-netinstall.md`) | The BOOTP detection, transient `10.255.x.11/24` address, `netinstall-cli` invocation, OUI gating, cooldown/idempotency, planned-reboot watchdog suppression, and the post-flash SSH/serial read are reused verbatim. Only the *choice of first-boot script* and the *post-flash continuation* become intent-driven. |
| `MikrotikHandler.netinstall(...)` (`-s` configure script, `-sm` mode script) | Called with a **bench-staging** script for the new classes instead of the wifi-api served Configure script. |
| `MikrotikHandler.apply_config_file()` (`sftp` + `/import`) | The generated `.rsc` is applied through this existing path; no new device-side transport. |
| `MikrotikHandler.get_info()` → `board-name`, `architecture-name`, serial, MAC | Feeds model→class auto-detect and the label. |
| `mode_config.py` `{{placeholder}}` rendering — the one sanctioned placeholder path (`CLAUDE.md`) | **Extended, not bypassed**: the new generator is a second explicitly-sanctioned renderer (Jinja2 is already a dependency, `requirements.txt`) that lives in a MikroTik-only module. Standard deep-merge templates stay placeholder-free. |
| `workflow_actions.workflow_for_port()` + `HandlerManager.operator_capabilities_for()` | The kiosk renders server-owned actions per port. The job-intent picker is delivered as **new actions / `required_action` values** through this contract — the docstring already reserves `mode_selection_required` for "the forthcoming job-intent selector". |
| `config_resolver.py` roles (`configs/templates/{vendor}/roles/{role}/`), `ProvisionRequest.role` | The class chosen on screen is passed as the job's `role`; MikroTik is the first vendor to turn `supports_config_overlays`-style behaviour on — but via its own `.rsc` profile tree (see §3.3), because `.rsc` cannot be deep-merged (`design-config-resolution.md` hardware follow-up #4). |
| `equipment_registry.py` (generic webhook + MikroTik ZTP register) | A third client is added beside them: `netbox.py`. The ZTP client is untouched. |
| Label printing (`_mikrotik_netinstall_label_payload`, `index.html` Brady Web-Bluetooth flow, `labels.html` templates `tw##rtr`, `tw##sw##`) | Same print path; a new payload `type` carries identity/class/WAN MAC. |
| `db.py` `provisioning_jobs`/`device_inventory` | Job record gains the intent + generated-config hash + NetBox sync status (additive columns). |

## 1b. Upstream sources of truth in `sixtyops/treehouse-architecture` (found 2026-08-29)

The architecture repo already answers most of what §2 originally had to assume. **The provisioner consumes these; it does not re-author them.**

| Need | Upstream artifact | How the provisioner uses it |
|---|---|---|
| Business-router config | `docs/operations/business-router-canonical.rsc` + `business-router-provisioning-contract.md` (names **`network-provisioner`** as an executor) + `business-router-sites.yaml` (the declaration) + `business-router-standard.md` | Render `canonical + declaration → <slug>-rtr01.rsc` exactly per the contract's Render / Preflight / Apply / Verify obligations. Identity `subscriber-<slug>-rtr01` is the import-completed sentinel (last block). |
| Site-router / site-switch config | `netbox/generate_config.py` (standalone mode needs no NetBox: `--site tw15 --neighbors tw04,tw16`; `--switch-model`), `netbox/templates/routeros/site-router.rsc.j2` + `includes/`, `netbox/templates/routeros-switch/site-switch.rsc.j2`, `docs/operations/infrastructure-switch-standard.md` | Same renderer, same templates. Site switch = transparent bridge + VLAN 12 DHCP client, identity `th.tw##.sw##`. |
| Deterministic IP plan | `netbox/lib/ip_math.py` (`/20` per new-format site, mgmt VLAN 12 at offset +4, loopback `100.127.16.<N>`, transit `/29` + VLAN `3[owner][seq]`, VLAN 77 local access) — documented in `architecture/06-netbox-ipam.md`, `19-site-standards.md` | Imported, never copied. **Offline site-infra rendering is fully possible** — this retires the old A16 "type the IP by hand". |
| Per-device secrets | `netbox/lib/secret_kdf.py` (HMAC-KDF from `CONFIG_KDF_SEED`, per slot + purpose, rotation = version bump); RADIUS via CIDR client model (no per-device RADIUS secret); local break-glass user; 1Password vault entry per site (`"{site name} switch"` convention in `business-switch/generate.py`) | See A13. |
| UniFi conventions | Business-router standard: UniFi is **L2 only**; controller `172.233.208.174` (`wifi.treehouse.mn`) via DHCP option 43 + inform `dstnat 8080→8089`; VLANs 10 Internal (native) / 20 IoT / 40 Guest / 70 OpenRoam; UniFi-side config via `unifi/` scripts (separate, not bench) | See A15. |
| State model | `architecture/50-infra-ztp.md`: running device = **truth**, git intent = desired, NetBox = "right about now", written only by pipelines | Matches D4 exactly. The bench is one such pipeline: it writes NetBox after read-back verification. |
| Model port profiles | `generate_config.py` `SWITCH_MODELS` (CRS310, CRS326, hEX S, PowerBox Pro/hEX PoE); business contract has profiles for hEX S / hEX PoE only and **explicitly rejects** RB4011 and plain hEX | RB5009, L009, RB4011, netPower 16P profiles **do not exist yet** — see B0. |

**Upstream doc conflicts the requester must settle (not the provisioner's call):**

1. **Business-router addressing:** `architecture/49-business-customer.md` + `48-business-switch.md` say each business site gets `10.{idx}.0.0/16` (idx from `business-switch/sites.yaml`) with the upstream MikroTik serving `10.{idx}.{vlan}.50–250`; `docs/operations/business-router-standard.md` + canonical `.rsc` say every site is an identical `192.168.10/20/40/70` NAT island. The provisioning contract implements the latter. **Default: follow the contract (192.168 NAT island)** because it is the machine-consumable spec and has bench-tested configs; flag `10.{idx}` as a pending migration decision.
2. **Business-router identity:** `subscriber-<slug>-rtr01` (contract/canonical) vs `th.{site}.rtr01` (49). **Default: contract.**
3. **Business-router NetBox record:** the contract says "no NetBox record" (customer-premise NAT island); 49 says NetBox entries for every managed device; the requester says NetBox must match live (D4). **Default: D4 wins — create the record**, tagged `business-router`, no IPAM derivation.
4. **Site naming variance:** `tw15-rtr01` (slot / generate_config) vs `th.tw15.rtr01` (19-site-standards) vs `th.tw20.sw01` (switch standard) vs `tw##rtr` (provisioner `labels.html`). **Default: whatever the upstream template emits for identity; the label prints the same string.**

## 2. Assumptions register (unanswered questions → defaults)

Each row: **A#** · the question · the default this plan adopts · why. Change a row here before, not during, implementation.

### Device classes and auto-detect

| # | Question | Default | Why |
|---|---|---|---|
| A1 | What are the selectable device classes? | Exactly three: **Site Router**, **Site Switch**, **Business Router**. Customer Gateway remains the fourth, implicit option only where the existing pipeline is enabled (see A9). | D6/D7 name exactly these; classes map 1:1 onto label conventions already in `labels.html` (`tw##rtr`, `tw##sw##`). |
| A2 | How is class auto-detected? | By `board-name` after flash: `netPower 16P` → Site Switch (only choice); `RB5009*` → ambiguous → show **Site Router** and **Business Router**; every other in-scope board → Business Router (preselected), Site Router/Switch hidden. Unknown board → all three shown, none preselected, warning banner. The map is a class-level dict on `MikrotikHandler` (`BENCH_CLASS_BY_BOARD`), not in the engine or the UI. | D10 "as smart as possible"; the board name is the only reliable signal, and it is only known after flash (a BOOTP frame carries no model). |
| A3 | What does "specific" mean per class? | Site Router: **site number 1–99**, site format (`new`/`old`, defaulted from the cached NetBox site record), and **neighbor site numbers** (the PTP links — `generate_config.py --neighbors`). Site Switch: **site number + switch unit** (`sw01`…). Business Router: pick a **`slug` from `business-router-sites.yaml`** (the upstream declaration); a slug not yet declared cannot be provisioned — the tech sees "declare it in treehouse-architecture first" (or, online, a NetBox tenant with no declaration shows the same message). | The upstream contract makes the declaration the only input surface; the bench must not invent one. Neighbors are required because transit VLANs/`/29`s derive from them. |
| A4 | Site router/switch identity | Whatever `site-router.rsc.j2` / `site-switch.rsc.j2` emit (`tw##-rtr01` slot name / `th.tw##.sw##`); the provisioner never composes identities itself. `labels.html`'s `tw##rtr` pattern is updated to match. | Upstream conflict #4 in §1b; one string, printed as-is. |
| A5 | Business router identity | `subscriber-<slug>-rtr01` — the contract's import-completed sentinel. | Fixed by `business-router-provisioning-contract.md`; not a provisioner decision. |

### Netinstall vs. credentialed path

| # | Question | Default | Why |
|---|---|---|---|
| A6 | Primary bench path? | **Netinstall.** The credentialed path (device plugged in booted, sticker password typed into the existing credentials prompt) is supported as a secondary path through the same job picker, because the generated `.rsc` is applied via the existing `apply_config_file()` either way. | D13. Supporting the second path is nearly free and covers re-work of a unit that is not factory-new. |
| A7 | When does the reflash start? | **Immediately on BOOTP** (as today), with an intent-neutral **bench-staging** first-boot script (`-s`) and the same `-sm` advanced-mode script. The tech picks class/site *while* the flash runs (~2–4 min). | D12 allows automatic destructive action; overlapping flash with data entry is the biggest UX win; and the model is only knowable after flash (A2). |
| A8 | What is in the bench-staging script? | Minimal: identity `bench-staged-<serial>`; bridge of all ether/sfp ports with `192.168.88.1/24` (the address the handler already expects); a `bench` user with a **per-flash random password** injected by the provisioner (never `admin/admin`); ssh only; no phone-home, no DHCP client, no wifi. It is the RouterOS *reset default* until the final config replaces it (see A18). | Lets the provisioner log in with credentials it generated (D13) and read the board name. |
| A9 | Coexistence with the existing customer-gateway pipeline on the same bench? | New config key `device_settings.mikrotik.netinstall_intent`: `gateway` (**default — byte-identical to today's behaviour**) or `bench`. In `bench` mode BOOTP runs the A7 flow. A per-port override is **not** in v1. | D9: the default must not change any existing behaviour. Customer gateways are out of scope (D8), so a bench that does both is not a v1 requirement. |
| A10 | Cooldown/idempotency for the bench flow? | Reuse `REPROVISION_COOLDOWN` and the `last_bootp_fired_mac` gate unchanged. A tech who wants to re-do a unit within 30 min uses the existing manual **Service actions → MikroTik recovery (Netinstall)** button. | No new state machine. |

### Config generation

| # | Question | Default | Why |
|---|---|---|---|
| A11 | Template format and engine | **Upstream templates, rendered in-process.** A sparse, read-only mirror of `sixtyops/treehouse-architecture` (`netbox/lib/`, `netbox/templates/`, `netbox/generate_config.py`, `docs/operations/business-router-*`) lives at `/var/lib/provisioner/repo/upstream/treehouse-architecture/`, refreshed by the existing data-repo sync when online, **pinned SHA recorded on every job**. `provisioner/mikrotik_profiles.py` imports `ip_math`/`secret_kdf` from the mirror and drives `generate_config.py`'s standalone mode for site classes, and implements the business contract's render step against `business-router-canonical.rsc` + the `business-router-sites.yaml` declaration. The **only** provisioner-owned templates are `_staging.rsc.j2` (A8) and per-model **port profiles** missing upstream (RB5009, L009, RB4011, netPower 16P) — and those are contributed upstream, not kept here long-term. Every render is followed by the contract's offline `.rsc` lint. | Prevents a second config generator drifting from the fleet standard; the upstream contract explicitly names `network-provisioner` as an executor of *its* render. Jinja2 already a dependency; the mirror is Python-3.9-safe (`ip_math.py` is plain f-strings). |
| A12 | Where do generated files go? | `/var/lib/provisioner/run/generated/mikrotik/<job-id>.rsc`, mode 0600, kept (not deleted) so the exact applied config is auditable and re-printable; a SHA-256 of it is stored on the job and sent to NetBox (D4). | D4 needs an auditable "what is live". Same directory convention as `RESOLVED_CONFIG_DIR`. |
| A13 | Secrets on the final config | Three kinds, following upstream: (1) **KDF-derived** secrets (SNMP community; extendable to the local break-glass user) via `secret_kdf.derive(seed, slot, purpose)` with `CONFIG_KDF_SEED` in `/etc/provisioner/provisioner.env` — deterministic, so nothing needs to be *stored* per device, and it works offline; (2) **RADIUS** for site infra via the CIDR client model — no per-device secret; (3) for anything genuinely per-unit and random (business-router local admin if the canonical config keeps one), a **1Password item per device** (`"{site name} router"`, matching the switch convention) written via `op` CLI service account when online, held in the encrypted outbox (A19) when offline. **Never on screen, never on the label.** The NetBox secrets plugin is *not* adopted in v1 — 1Password is already the team's store and `generate.py` already targets it. | `50-infra-ztp.md` security contract + `business-switch/generate.py` precedent; `CLAUDE.md` secrets policy. |
| A14 | WAN configuration | As the upstream templates define: Business Router `ether1-wan` DHCP client (label prints its MAC — D14); Site Router per `site-router.rsc.j2` (transit VLAN `/29`s, OSPF, VLAN 77 local access); Site Switch transparent bridge + VLAN 12 DHCP client (no static mgmt). The provisioner adds nothing. | Fixed upstream. |
| A15 | LAN/VLAN plan for business routers with UniFi APs | Canonical: VLAN 10 Internal (native, mgmt) `192.168.10.0/24`, 20 IoT, 40 Guest `/22`, 70 OpenRoam `/23`; option 43 → UniFi controller `172.233.208.174` + inform `dstnat 8080→8089`; AP trunks `ether4/5` forced PoE. UniFi-controller-side setup stays in the `unifi/` scripts / SOP §C, out of the bench. | Fixed upstream (`business-router-standard.md`). Conflict #1 (§1b) noted. |
| A16 | Site IP plan (routers/switches) | **Deterministic from `ip_math.py`** — mgmt gateway, loopback, transit `/29`s and VLANs are all computed from site number + neighbors; **offline rendering is complete** with no manual IP entry. NetBox (when reachable) is only used for the A17 conflict checks and the write-back. | `19-site-standards.md`: "every IP and VLAN at a site is computable from the site number." |

### Ops validation, NetBox, offline

| # | Question | Default | Why |
|---|---|---|---|
| A17 | What is "ops"? | **NetBox** (D4) for automated checks — site exists with the expected `site_format`, slot identity not occupied by a *different* serial (swap = rebind, per `50-infra-ztp`), serial not active at another site, declared neighbors exist. Plus a **declaration freshness** check: the upstream mirror SHA is compared to `origin/main` when online; a stale mirror is a validation failure (bypassable). A human-approval gate is **not** in v1. | D2 asks for validation with bypass, and D4 names NetBox. A human-in-the-loop would block the field (D1). |
| A18 | Bypass semantics | If NetBox is unreachable **or** validation fails, the summary screen shows the failure reason and a **"Bypass ops validation"** button requiring a second tap (confirm). The job records `validation: bypassed` + reason; the NetBox write is queued (A19) tagged `bench-bypassed` so ops can review. No bypass code/PIN in v1. | Anyone touching the screen may operate it (D10), so a PIN adds nothing. |
| A19 | Offline write path | An **outbox** (`/var/lib/provisioner/run/netbox-outbox/*.json`, one file per job) drained by a background task whenever NetBox becomes reachable; writes are idempotent by serial. The kiosk shows a small "N records pending sync" badge. | D3 cached solution; D4 requires the record to eventually land. |
| A20 | Offline read cache | Sites, tenants, mgmt prefixes, device roles, and the device list (serial→site/identity) are cached to `/var/lib/provisioner/run/netbox-cache.json` on every successful contact and on a 15-minute refresh. The summary shows the cache age when offline. | Lets auto-complete (site number → site name, tenant slug list) and A17 checks run offline where possible. |
| A21 | NetBox write contract | On success: create/update `dcim/devices` by serial (`device_type` from board name, `role` from class, `site`/`tenant`, `name` = identity, `serial`, `status: active`, `comments` = bench job id), interfaces for WAN/LAN with MACs, primary IP where applicable, custom fields `bench_config_sha256`, `bench_config_class`, `bench_upstream_sha` (mirror commit the config was rendered from), `bench_provisioned_at`. Device-type/role objects and the custom fields must pre-exist — reuse `netbox/populate.py` / `populate_extras.py` upstream rather than a new seeding script. Business routers get a record (§1b conflict #3) with no IPAM objects. | "NetBox should match what's live" (D4): write exactly what was applied, after it was verified applied; `50-infra-ztp`: NetBox is written only by pipelines. |
| A22 | NetBox auth | `device_settings.mikrotik.netbox_url` + `netbox_token` (`${NETBOX_TOKEN}` env expansion like `ztp_api_key`), token with write scope limited to dcim/ipam. | Existing config.py pattern. |

### UI and labels

| # | Question | Default | Why |
|---|---|---|---|
| A23 | Step order on the port card | 1 **Class** (auto-preselected per A2, big buttons) → 2 **Specifics** (site/unit or tenant slug; IP fields only when required by A16) → 3 **Summary & confirm** (every rendered value; validation status; Bypass if needed) → 4 progress checklist → 5 **Done + Print label**. Back on every step; cancelling before step 3 leaves the device bench-staged (safe). | D10, D11. |
| A24 | Label content | Identity (large), class, site/tenant, WAN MAC (as configured), serial, board, bench date. No credentials. | D14 + A13. |
| A25 | Touchscreen verification | Required before production (`deploy.sh --allow-branch`), same rule as epic-config-resolution follow-up #7. | Kiosk changes are hardware-gated in this repo. |

## 3. Design

### 3.1 Flow (bench intent, Netinstall path)

```
BOOTP frame (OUI-gated, cooldown-gated)             ── unchanged
  └─ netinstall_intent == "gateway"  → existing _run_netinstall (unchanged)
  └─ netinstall_intent == "bench"    → _run_bench_netinstall
        1. flash: netinstall-cli -sm <mode.rsc> -s <bench-staging.rsc>   (A7/A8)
        2. wait boot → SSH as `bench` (generated pw) → get_info()
        3. port state: bench_stage = "awaiting_intent", board/serial/MAC known
        4. workflow_for_port → required_action = "choose_bench_class"
           (kiosk shows Class → Specifics → Summary on that port card)
        5. POST /api/mikrotik/bench/{port}/validate  → NetBox checks or offline verdict
        6. POST /api/mikrotik/bench/{port}/apply  {spec, bypass: bool}
              a. render profile → generated .rsc (A11/A12)
              b. apply_config_file() → /import                (existing)
              c. reboot → wait → SSH with *final* admin creds → verify
                 (identity, WAN iface, mgmt IP reachable from the port VLAN,
                  no `bench` user left, reset-default replaced — A18 note)
              d. NetBox write or outbox                         (A19/A21)
              e. label payload → kiosk print                    (A24)
        7. last_result = complete; grace period preserves the card (existing)
```

Credentialed path: the standard detection flow finds a booted MikroTik, `login` succeeds (typed sticker password), `get_info()` runs, and the same step 3–7 continues. The only difference is that `provision()` is short-circuited by a new handler trait `bench_intent_required` (class-level, MikroTik-only) — evaluated in `main._provision_port_device` **through `handler_class_for()`**, never as `if device_type == "mikrotik"`.

### 3.2 Vendor-isolation compliance (D9)

- **Zero changes to `base.py`, `port_manager.py`, `fingerprint.py` flow, or any other vendor.** `main.py` gains one trait read (`bench_intent_required`) via `HandlerManager`, defaulting to `False` for every existing handler — the same pattern as `requires_model_preflight`.
- New modules: `provisioner/mikrotik_profiles.py` (renderer + `BenchJobSpec`), `provisioner/netbox.py` (client + cache + outbox), `provisioner/handlers/mikrotik.py` additions (board→class map, staging script builder, `bench_intent_required`, verification helpers). New API routes live in a `web/api_mikrotik_bench.py` router, included from `api.py`.
- Registry: no new vendor enumeration. The kiosk learns about bench actions through `workflow_for_port()` output only.
- Config: `netinstall_intent` defaults to `gateway`; **with default config the diff is dormant** — a regression test asserts the BOOTP callback resolves to the existing `_run_netinstall` and `workflow_for_port()` output is unchanged for every non-MikroTik `SpyHandler` fixture.
- Tests: `tests/test_mikrotik_bench_flow.py` (stubbed handler + stubbed NetBox session, offline/online/bypass matrix), `tests/test_mikrotik_profiles.py` (every profile renders for every in-scope board with `StrictUndefined`; rendered output contains no `{{`, no `bench` user, and no literal secret), `tests/test_netbox_outbox.py`. CI stays Python 3.9.

### 3.3 Templates

```
/var/lib/provisioner/repo/
├── configs/templates/mikrotik/profiles/
│   └── _staging.rsc.j2                       # A8 — the ONLY provisioner-owned .rsc template
└── upstream/treehouse-architecture/          # sparse read-only mirror, SHA-pinned per job (A11)
    ├── netbox/lib/ip_math.py, secret_kdf.py
    ├── netbox/generate_config.py             # site-router / site-switch standalone render
    ├── netbox/templates/routeros/…, routeros-switch/…
    └── docs/operations/business-router-canonical.rsc, business-router-sites.yaml
```

Class → upstream render path: Site Router → `generate_config.py --site tw## --neighbors …` (router template); Site Switch → `--site tw## --switch-model <slug>`; Business Router → contract render (`canonical + declaration`). `get_info().model` (board name) maps to the upstream model slug on `MikrotikHandler` (`BENCH_MODEL_SLUG_BY_BOARD`) — a board with no upstream profile is refused before any reset, per the contract's Preflight rule. Mirror refresh rides the existing data-repo sync (`CLAUDE.md` deployment note); board slugs missing upstream are the B0 upstream PRs.

### 3.4 Data

- `provisioning_jobs` (additive columns): `bench_class`, `bench_identity`, `generated_config_sha256`, `validation_status` (`ok|bypassed|skipped`), `netbox_sync` (`synced|pending|failed`).
- `PortState` (additive): `bench_stage`, `bench_board`, `bench_spec_draft` (for Back navigation), `bench_validation`.
- Secrets: generated passwords only in memory + outbox (0600) until synced, then scrubbed from the outbox file.

## 4. Stories

| Story | Size | Depends on | Hardware-gated |
|---|---|---|---|
| B0 — Upstream mirror + renderer (`mikrotik_profiles.py` driving upstream `generate_config.py` / business contract render; `_staging.rsc.j2`; contract lint; SHA pinning) **+ upstream PRs to `treehouse-architecture` adding port profiles for RB5009, L009, RB4011 (router) and netPower 16P (switch)** | L | — | no (render only) |
| B1 — Bench-staging Netinstall path + `netinstall_intent` flag + dormant-by-default regression test | M | B0 | **yes** — RB5009 + hEX S on the bench |
| B2 — Job-intent picker on the port card (workflow contract + kiosk steps, Back, summary) | M | B1 | **yes** — touchscreen |
| B3 — Apply + verify + final-creds handoff (credentialed path included) | M | B0, B1 | **yes** — all in-scope boards |
| B4 — NetBox client: read cache, validation checks, write, outbox + sync badge | L | — (parallel with B1) | no |
| B5 — Label payload + print | S | B2, B3 | yes — printer |
| B6 — 1Password `op` service-account writer (A13) + upstream `populate_extras.py` additions for the bench custom fields + docs (`docs/mikrotik-bench.md`, HANDLER_DEVELOPMENT trait entry, HOST_SETUP config keys: `CONFIG_KDF_SEED`, `NETBOX_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`) | M | B4 | no |

Sequence: **B0 + B4 now (parallel)** → B1 → B2 + B3 → B5 → B6. Each hardware-gated story ships with a verification report per `docs/epic-contribution-readiness.md`.

## 5. Definition of done

- Factory-new RB5009 / netPower 16P / hEX S each: reset-button → BOOTP → tech taps ≤ 3 screens → confirm → label prints → unit boots at a site with the intended identity, WAN, and mgmt reachability, **with the bench offline** (bypass path) and **online** (NetBox record matches the live config, including `bench_config_sha256`).
- Default config (`netinstall_intent: gateway`) produces zero behaviour change: existing MikroTik contract tests, vendor registry/golden tests, and every other vendor's test suite pass untouched; no test outside `tests/test_mikrotik_*` / `tests/test_netbox_*` is modified.
- `grep -rn bench provisioner/base.py provisioner/port_manager.py` is empty.

## 6. Open questions parked for the requester (non-blocking; defaults in §2 apply until answered)

Resolved on 2026-08-29 by `treehouse-architecture`: identity (A5), offline IP plan (A16), UniFi conventions (A15), and the secrets *mechanism* (A13: KDF + RADIUS + 1Password; NetBox secrets plugin deferred). Still open:

1. §1b conflict #1 — business-router addressing: `192.168` NAT island (contract, default) vs `10.{idx}.0.0/16` (49/48). Affects whether the canonical `.rsc` or the business-switch scheme is the target.
2. §1b conflict #3 — whether business routers get a NetBox record (default: yes, per D4).
3. A13 — confirm 1Password over the NetBox secrets plugin for the (few) truly random per-unit secrets, and whether a service-account token may live on the bench host.
4. A3 — whether a business slug may be *declared from the bench* (writing `business-router-sites.yaml` upstream via PR) or must always be pre-declared by ops. Default: pre-declared.
