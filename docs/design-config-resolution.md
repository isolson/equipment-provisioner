# Design: Config Resolver Contract + Snapshot Schema

> Status: R0 deliverable · Tracking: issue #113 (part of epic #112) · Companion docs:
> `docs/epic-config-resolution.md` (epic; ships in PR #121 — link dangles until it merges),
> `docs/ARCHITECTURE_ISOLATION_REVIEW.md`
> (vendor-touchpoint map), `docs/epic-vendor-isolation-refactor.md` (epic #69),
> `docs/HANDLER_DEVELOPMENT.md` (handler properties and class traits).
>
> **This is a design document. It changes no production code.** Downstream stories
> R1–R6 implement it. Anything the repo cannot answer is flagged in §6.7
> ("Hardware follow-ups") and §7 ("Open decisions") — per the epic's rule, none of
> those cells are guessed.

## Scope and non-goals

The resolver answers one question — *"which ordered config layers apply to this
device for this job?"* — upstream of the provisioning engine. It replaces exactly
one call site (`main.py:599`). It does not change:

- `BaseHandler.provision()` or any handler `apply_config` / `apply_config_file`
- `ConfigStore.get_config_template()` lookup order, `CONFIG_MODEL_ALIASES`, or the
  class-level handler traits that gate them
- the `apply_config_{vendor}` feature-flag gate in `main.py`
- mode templates (`mode_config.py`) and their `{{placeholder}}` rendering — still
  the **only** sanctioned placeholder path
- the Tarana inline-settings injection and the MAC-based device-override second
  pass (both noted below as future layer candidates, untouched in this epic's v1)

---

## 1. The resolver seam

### 1.1 Where config selection happens today (call-path trace)

Two entry paths converge on one selection point:

**Auto-provision (device plugged in):**

```
port_manager link/boot-ping detect
  → main.Provisioner (device-detected callback, main.py:342)
  → _run_port_provisioning(port, device_type, ip)          main.py:348
  → _provision_port_device(..., provision_request=None)    main.py:405
```

**Manual / retry (UI):**

```
POST /api/provision  (ProvisionRequest)                    web/api.py:268
  → background task _run_provisioning                      web/api.py:882
  → _provision_port_device(..., provision_request=req)     web/api.py:915
```

**Inside `_provision_port_device` (main.py):**

| Step | Location | What happens |
|---|---|---|
| Evolution Digital side-door | `main.py:438` | passive flow dispatched *before* any config lookup — never reaches the seam (keep) |
| Re-fingerprint | `main.py:527` | `identify_device()` refreshes `fingerprint.model` |
| Model preflight | `main.py:556` | if `handler_class.requires_model_preflight` and no model: read-only `login_and_get_info()` fills `fingerprint.model` — **the resolver runs after this**, so model-specific resolution has the best model string available |
| **THE SEAM** | `main.py:599` | `config_path = store.get_config_template(device_type, fingerprint.model)` — the single static-template lookup this design replaces |
| Feature-flag gate | `main.py:606` | `apply_config_{device_type}` flag can null out `config_path` (stays outside the resolver, unchanged) |
| Tarana settings injection | `main.py:615` | builds an inline `override` dict (`operator_id`) — a known S2 orchestrator leak; unchanged in v1, absorbed later (see §7) |
| Provision call | `main.py:671` | `handler_manager.provision_device(config=override, config_path=..., ...)` |
| Device-override second pass | `main.py:699` | after success, `store.get_device_override(mac)` may trigger a second provision pass with inline config (feature-flagged; unchanged) |

**Inside the engine (`handlers/base.py`):**

- Default order: config phase at `base.py:720-768` (Config → Config Verify → FW2).
- `config_after_all_firmware` order: deferred config at `base.py:898-944`
  (config last, verify reported `UNVERIFIED`).
- **Precedence quirk to preserve:** when both are passed, inline `config` wins and
  `config_path` is ignored (`base.py:727-732` and `916-921`). Today this is how
  Tarana works (inline settings, no template file).

**Inside the handlers (what "apply the config" means per vendor):**

| Vendor | File apply path | Semantics |
|---|---|---|
| Tachyon | `tachyon.py:1281` `apply_config_file` | `.tar` export or full-export-shaped JSON (`_is_full_config_export`, `tachyon.py:1025`) → applied **authoritatively (replace)**; partial JSON → GET live config, `_deep_merge(current, template)` (`tachyon.py:1271`), POST result |
| Cambium | `cambium.py:1280` `apply_config_file` | JSON → `config_import` multipart upload + `applyFinished` poll; `.tar` → LuCI flashops restore; inline dict → `set_param` (small key sets only). All endpoints CONFIRMED in `docs/cambium-config.md` |
| MikroTik | `mikrotik.py:263` `apply_config_file` | SFTP `.rsc` + `/import` over SSH. Inline dict `apply_config` is **rejected by design** (`mikrotik.py:254`) |
| Ubiquiti | `ubiquiti.py:973` `apply_config` | **Wave only** (`_api_style == "wave"`): PUT full config JSON + fail-closed read-back. AirOS: no config apply exists. Feature flag `apply_config_ubiquiti` defaults **False** |
| Tarana | `tarana.py:1293` `apply_config` | `operator_id` → gNMI `/radios/global/config/operator-id`. Nothing else |

Two corrections to the epic's shorthand that this trace surfaced:

1. **"The existing deep-merge machinery" is per-handler, not central.** The only
   template→device deep merge in the tree is `TachyonHandler._deep_merge`.
   Cambium applies device-side (`config_import` with `skipIllegal=1`, which skips
   keys the device cannot set; whether a partial JSON leaves unlisted keys
   untouched is not established in-repo); Wave PUTs a
   config JSON whose merge-vs-replace semantics are not established in-repo;
   MikroTik and Tarana have no JSON merge at all. Layer composition therefore
   cannot be "handled by the existing merge" — the resolver must compose layers
   itself, *before* the handler is invoked (§1.3), using the same algorithm.
2. **Config templates for several vendors do not exist in the repo.** Only
   `configs/templates/{cambium,tachyon}/` exist (plus two root-level MikroTik
   `.rsc` files for the provisioner's own switch). Ubiquiti/Tarana/MikroTik have
   no per-device template today; the live data repo on the host
   (`/var/lib/provisioner/repo/`) is the operative template store.

### 1.2 The `ConfigResolver` contract

New module `provisioner/config_resolver.py`. All snippets are Python 3.9.

```python
"""Vendor-neutral config resolution.

The resolver decides WHICH ordered layers apply. It never enumerates
vendors: per-vendor knowledge is consulted exclusively through class-level
handler traits via HandlerManager.handler_class_for(device_type), the same
mechanism config_store.py already uses.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class JobContext:
    """Operator selections attached to one provisioning job.

    The default (both fields None) is the backward-compatible no-op:
    resolution is byte-identical to today's single-template lookup.
    """
    role: Optional[str] = None                    # opaque string, e.g. "tower"
    replacement_snapshot_id: Optional[str] = None # snapshot store key (R3)


@dataclass
class ConfigLayer:
    kind: str                          # "base" | "role-overlay" | "replacement-overlay"
    path: Optional[Path] = None        # file-backed layer (base templates)
    data: Optional[Dict[str, Any]] = None  # inline layer (generated overlays)
    source: str = ""                   # provenance for logs/UI ("template tns-100.json",
                                       # "role tower", "snapshot <id>") — never secret values


@dataclass
class ResolvedConfig:
    layers: List[ConfigLayer] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)  # operator-visible resolution notes

    def as_provision_args(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Collapse layers into the (config, config_path) pair provision() takes.

        Single file-backed base layer -> (None, str(path))  [pass-through, byte-identical]
        Multi-layer -> (None, str(materialized_path))       [composed artifact, §1.3]
        """
        raise NotImplementedError  # R1


class ConfigResolver:
    def __init__(self, store, handler_manager):
        self._store = store              # ConfigStore
        self._handler_manager = handler_manager

    def resolve(self, device_type: str, model: Optional[str],
                context: Optional[JobContext] = None) -> ResolvedConfig:
        ctx = context or JobContext()
        resolved = ResolvedConfig()

        # Layer 1: the base template — DELEGATED to today's lookup, unchanged.
        base = self._store.get_config_template(device_type, model)
        if base is not None:
            resolved.layers.append(ConfigLayer(kind="base", path=base,
                                               source=base.name))

        if ctx.role is None and ctx.replacement_snapshot_id is None:
            return resolved   # fast path: exactly today's behavior

        # Layers 2-3: overlays (R1 role lookup, R5/R6 snapshot-derived) ...
        raise NotImplementedError  # R1/R5
```

The seam change in `main.py` is one line-shaped edit:

```python
# Today (main.py:599):
config_path = store.get_config_template(device_type, fingerprint.model)

# After R1:
resolved = self.config_resolver.resolve(device_type, fingerprint.model, job_context)
override_cfg, config_path = resolved.as_provision_args()
```

Everything after the seam (feature-flag gate, Tarana injection, firmware lookup,
`provision_device(...)`) is untouched. The inline-config-wins quirk is preserved:
the resolver's composed output travels as `config_path`, so the Tarana inline
`override` continues to take precedence exactly as today.

**Vendor-isolation compliance.** The resolver:

- contains zero vendor strings and zero `if device_type == ...` branches;
- reads per-vendor behavior only through class traits
  (`HandlerManager.handler_class_for`), the pattern blessed in
  `docs/HANDLER_DEVELOPMENT.md` → "Class-Level Traits";
- treats `role` as an opaque string — the set of roles is derived from the
  template tree on disk (§2.3) plus UI configuration, never a hardcoded enum;
- adds **no new vendor registry**. New per-vendor knowledge introduced by this
  epic lives as handler class traits (below) or template/snapshot files.

**New handler class traits** (declared here; implemented in the noted story;
defaults on `BaseHandler` chosen so that *nothing changes until a handler opts
in*):

| Trait | Default | Story | Meaning |
|---|---|---|---|
| `supports_config_overlays` | `False` | R1 | resolver may compose role/replacement overlays for this vendor. `False` ⇒ overlays are refused with an operator-visible note (base-only resolution). Enabled per vendor only after bench verification |
| `supports_config_snapshot` | `False` | R4 | handler implements `capture_config_snapshot()` (§3.4) |
| `is_full_config_export(config)` | `False` (staticmethod) | R1 | promotion of `TachyonHandler._is_full_config_export` to a class-level hook so the resolver can detect replace-not-merge templates *before instantiation* (§2.4). Tachyon overrides with its existing key-set heuristic. Deliberately method-shaped while the other traits are plain class attributes: the answer depends on the *loaded config's content* (key sets), not on the vendor alone, so it cannot be a constant — same callable-before-instantiation property as the attribute traits, consulted via `handler_class_for` |
| `snapshot_identity_paths` | `{}` | R4/R5 | identity field → vendor-native config path map (the §6 tables, expressed in code where they are hardware-confirmed). Used to *generate* replacement overlays and to extract identity blocks at capture time |

### 1.3 Composing layers into what the engine already accepts

Handlers and `provision()` do not change, so multi-layer output must collapse to
the existing `(config, config_path)` interface:

- **Fast path (no overlays):** one file-backed base layer → pass the `Path`
  through as `config_path`, exactly the string produced today. No file is read,
  parsed, or re-serialized — byte identity is structural, not best-effort.
- **Composed path (overlays present):** the resolver loads the base via the
  existing `provisioner/config_templates.load_config_template()` (which already
  handles `.tar` exports and **rejects `{{placeholders}}`** — that guard now
  covers overlays too), folds the overlay layers in order with a shared
  vendor-neutral merge (§2.2), and materializes the result as a job-scoped JSON
  artifact under the data dir (proposed: `/var/lib/provisioner/run/resolved/`,
  mode `0600`, deleted after the job). That artifact path is handed to the
  handler as `config_path`. From the handler's point of view nothing changed: it
  receives one config file, same as today.
- **Non-JSON bases (`.rsc`):** composition is impossible; `supports_config_overlays`
  stays `False` for MikroTik (also descoped by the epic, follow-up #4).

Why materialize a file instead of passing an inline dict: inline `config`
suppresses `config_path` in `provision()` and, for Cambium, routes to `set_param`
(small-key-set apply) instead of `config_import` (full apply) — silently changing
apply semantics. Materializing keeps every vendor on its current file-apply path.
One assumption made explicit rather than inherited: for Cambium this holds only
when interface binding is active — without `self.interface`,
`apply_config_file` json-loads and falls through to `apply_config` → `set_param`
(`cambium.py:1293-1299`). The provisioner always binds a VLAN interface in
practice (STANDARDS.md §1); the resolver contract assumes it.
Note for R1: the composed artifact for a Tachyon `.tar` base is a *JSON* file,
which `apply_config_file` still treats as authoritative because the full-export
key-set heuristic (`_is_full_config_export`) fires on the composed content.

---

## 2. Layer precedence

### 2.1 Order

```
base template  →  role overlay  →  replacement overlay
(lowest)                              (highest, later wins)
```

- **Base**: exactly today's `get_config_template()` result (model → alias →
  default → trait-gated fallback → legacy).
- **Role overlay**: site-role deltas (tower vs home/business), file-backed (§2.3).
- **Replacement overlay**: identity fields inherited from a predecessor's
  snapshot — *generated* from the snapshot's identity block via the handler's
  `snapshot_identity_paths` trait, never hand-authored (§2.5). Highest precedence
  because a replacement's identity (SSID/PSK, static IP, PTP side) must win over
  any role default.

### 2.2 Merge semantics (one shared rule)

Composition uses the same algorithm the tree already trusts —
`TachyonHandler._deep_merge` (`tachyon.py:1271`), promoted in R1 to a shared,
vendor-semantics-free utility (proposed `provisioner/config_merge.py`):

- dict ∧ dict → recursive merge, later layer wins per key;
- **everything else (lists, scalars, `null`) → later layer replaces wholesale.**

The list rule is a real hazard and the design acknowledges it explicitly: e.g.
Tachyon's SSID lives at `wireless.radios.wlan0.vaps[0].ssid` — a naive overlay of
`{"wireless": {"radios": {"wlan0": {"vaps": [{"ssid": "x"}]}}}}` would replace the
whole `vaps` list and drop the base's security/profile settings. This is exactly
why `mode_config.py` uses path *injection* (`INJECT_FIELDS`,
`_set_nested_value` with `vaps[0].ssid`-style paths) rather than dict merge.
Rules that follow from this:

1. **Hand-authored role overlays** (R1) must contain complete list values when
   they touch a list. Overlay review checklist item, enforced by R1 tests on the
   shipped overlays.
2. **Role overlays must never contain secrets — and therefore must not touch
   identity fields.** Corollary of rule 1 that must be explicit: for Tachyon the
   passphrase lives inside `vaps[0]`, so a role overlay carrying a "complete"
   vap list element would embed a PSK in a git-committed file under
   `configs/templates/`. Forbidden. Secrets may only ever appear in snapshots
   and job-scoped data-dir artifacts (§4), never anywhere under
   `configs/templates/**`. Identity fields (SSID/PSK, static IP, PTP side)
   belong exclusively to the generated replacement layer (rule 3 below); role
   overlays are for site-role settings (services, VLAN plans, SNMP toggles,
   routing posture). R1 adds a lint test that shipped overlays contain no
   sensitive-shaped keys (reusing the `_is_sensitive_path` name heuristic as a
   guard, not as the correctness mechanism).
3. **Generated replacement overlays** (R5/R6) do not use dict merge for
   list-embedded fields at all: they are applied by path injection into the
   composed dict, reusing `mode_config.py`'s existing path grammar
   (`a.b[0].c`). The per-vendor paths come from `snapshot_identity_paths`, so
   the injection code is vendor-neutral.

### 2.3 Role overlay file layout

Reuse the existing lookup machinery instead of inventing a convention:

```
configs/templates/{vendor}/roles/{role}/{model|alias|default}.{json,...}
```

- Searched with the same `_find_named_template` chain (model → alias → default)
  and the same class traits (`allows_prefixed_config_exports`,
  `config_alias_prefix_matching`) as the base lookup. **No** arbitrary-file
  fallback for overlays (an accidental overlay is worse than none).
- The available role set is *derived* — `roles/*` directories present across the
  template tree — so adding a role is a data change, not a code change, and no
  module grows a role enum.
- Missing overlay for an explicitly selected role: proposed behavior is
  **soft-proceed** — resolve base-only, record an operator-visible note
  ("no `tower` overlay for cambium/epmp-4518") in `ResolvedConfig.notes`,
  surfaced in the job log. Roles will roll out vendor-by-vendor; a hard error
  would block provisioning of not-yet-covered vendors. Product may prefer
  fail-hard — open decision §7 (D3).

### 2.4 Interaction with full-export templates (replace-not-merge)

Tachyon `.tar` exports and full-export-shaped JSON are applied authoritatively
(replace). Composition-wise, two distinct cases:

- **Role overlays on a full-export base:** *forbidden in v1.* A full export is an
  interlocked complete config; a partial delta can produce combinations the
  device never validated together (the epic's follow-up #2). Mechanically: if
  the resolved base is a `.tar`/`.tar.gz`, or `handler_class.is_full_config_export(loaded)`
  is true for a JSON base, and a role overlay would apply, the resolver refuses
  the overlay, resolves base-only, and records a note. On paper, composition is
  actually well-defined (merge into the export dict, replace-apply the result) —
  bench may relax this later; until then the conservative rule holds.
- **Replacement on a full-export vendor:** modeled as **snapshot-as-base**, not
  as an overlay. The predecessor's snapshot `raw` export *becomes* the base
  layer (replacing the template), because for a replace-not-merge vendor the
  predecessor's full export *is* the correct authoritative config for the
  successor — modulo per-unit fields (MAC-bound values, mismatched-model
  exports), which is a bench question (§6.7 row H2).

### 2.5 Interaction with mode templates

Mode config (`mode_config.py`, `POST /ports/{n}/apply-mode`, `web/api.py:2510`)
stays a separate post-provisioning path, out of the resolver's scope:

- It remains the **only** placeholder-rendering path. Base templates and role
  overlays go through `load_config_template()`, which rejects `{{...}}`.
- Time-ordering defines effective precedence: mode config is applied *after*
  provisioning, so its field injections (SSID/hostname) overwrite whatever the
  resolver composed. That is correct today and stays correct.
- R6 (PTP replacement) will *reuse* the mode machinery's naming/side model
  rather than duplicate it: a snapshot's `ptp_role` + `ptp_link_id` (§3) map
  onto `generate_ptp_naming` inputs. Design detail deferred to R6.
- Noted for the VendorSpec effort (epic #69), not this epic:
  `mode_config.py`'s `INJECT_FIELDS`/`AP_SSID_PATTERNS` dicts and the
  `("cambium", "tachyon")` gate at `web/api.py:2546` are pre-existing vendor
  enumerations. `snapshot_identity_paths` (a handler trait) intentionally
  supersedes the *mechanism* so these can migrate into handler traits later; this
  epic must not add a new copy of that knowledge, and does not.

### 2.6 Existing implicit layers, unchanged

For completeness, the layers that already exist today and keep their current
positions relative to the resolver's output:

| Existing mechanism | Position | v1 treatment |
|---|---|---|
| `apply_config_{vendor}` feature flags | gate after resolution (`main.py:606`) | unchanged — can null the whole config |
| Tarana inline settings (`main.py:615`) | inline `config` beats `config_path` in `provision()` | unchanged; future candidate for a "vendor-settings layer" |
| MAC device overrides (`store.get_device_override`) | separate second provision pass (`main.py:699`) | unchanged; future candidate for a fourth layer |
| Mode templates | applied after provisioning | unchanged (§2.5) |

---

## 3. Snapshot schema

### 3.1 Purpose and versioning

A snapshot is one unit's captured identity + native config, stored by the
snapshot store (R3) and consumed by replacement resolution (R5/R6). JSON, one
document per capture.

- `schema_version` (integer, starts at `1`) governs the snapshot document
  structure only — not the vendor-native `raw` payload.
- Readers must ignore unknown fields (forward compatibility) and must refuse
  documents with `schema_version` greater than they support.
- Any change that alters the meaning of an existing field bumps the version;
  adding optional fields does not.

### 3.2 Document schema

All identity fields are optional (`null` when unknown/not applicable) because
capture coverage grows vendor-by-vendor; `schema_version`, `id`, `vendor`,
`model`, `captured_at`, and `source` are required (the store synthesizes `id`
on write if the capturing handler did not). Example (all values fake; `psk` shown
only because this example *is* the at-rest file in the protected data dir —
every API/UI/log surface redacts it per §3.3/§4):

```json
{
  "schema_version": 1,
  "id": "tachyon-SN0000000-20260821T140322Z",
  "vendor": "tachyon",
  "model": "TNA-303L-65",
  "serial_number": "SN0000000",
  "mac_address": "AA:BB:CC:00:11:22",
  "hostname": "tw05-north",
  "firmware_at_capture": "1.12.3",
  "captured_at": "2026-08-21T14:03:22Z",
  "source": "bench-capture",
  "identity": {
    "wireless": {
      "ssid": "NORTH",
      "psk": "fake-example-psk-not-real",
      "security_mode": null
    },
    "mgmt_ip": {
      "mode": "dhcp",
      "address": null,
      "prefix": null,
      "gateway": null,
      "vlan": 12
    },
    "routing": {
      "mode": "none",
      "area": null
    },
    "ptp_role": "none",
    "ptp_link_id": null
  },
  "raw": {
    "format": "tachyon-export-json",
    "encoding": "json",
    "content": { "...": "full vendor-native export, verbatim" }
  }
}
```

Field notes:

- `id` — filesystem-safe, unique: `{vendor}-{serial|mac}-{UTC timestamp}`.
  Exact key layout of the store is R3's decision; the `id` contract (unique,
  opaque to the resolver, safe in logs) is fixed here.
- `captured_at` — UTC ISO-8601 with `Z`. Python 3.9:
  `datetime.now(timezone.utc)` (no `datetime.UTC`).
- `source` — `"bench-capture"` or `"import"` (R7 fleet import).
- `identity.wireless` — AP/SM service identity. `security_mode` is a
  vendor-normalized hint (e.g. `"wpa2-psk"`); allowed values fixed in R4 per
  vendor as bench confirms them.
- `identity.mgmt_ip` — `mode` is `"dhcp"` or `"static"`; `address`/`prefix`/
  `gateway` required when `static`. `vlan` (optional int) covers the management
  VLAN, which the repo shows is part of link identity for Tachyon
  (`network.zones.wan.management.vlan`).
- `identity.routing` — `mode` is `"none"` or `"ospf"`; `area` plus any further
  OSPF params are **deliberately not enumerated** here: the repo contains zero
  OSPF-shaped fields for any vendor (verified: no match for `ospf` anywhere in
  `provisioner/`, `configs/`, `docs/`), so the sub-schema beyond
  `{mode, area}` is a hardware follow-up (§6.7 row H7). Reserved, not guessed.
- `identity.ptp_role` — `"a"`, `"b"`, or `"none"`; `ptp_link_id` uses the
  existing canonical form from `mode_config.make_ptp_link_id` (`"tw05-tw12"`).
- `raw` — the vendor-native export, verbatim. `format` is a handler-provided
  string (e.g. `tachyon-export-json`, `cambium-device-props`,
  `wave-config-json`); `encoding` is `"json"` or `"base64"` (binary exports,
  e.g. a `.tar`). `raw` is the authoritative payload for snapshot-as-base
  replacement (§2.4); `identity` is the normalized view for UI display and
  overlay generation.

### 3.3 Field-level redaction map

Fixed by the schema (vendor-neutral — no per-vendor secret lists needed at this
level):

| Path | Class | List/get API responses | UI | Logs |
|---|---|---|---|---|
| `identity.wireless.psk` | **secret** | omitted; replaced by `psk_present: true/false` (+ length) | masked (`••• · 24 chars`) | never |
| `raw.content` | **secret-bearing (whole blob)** | omitted from list *and* get responses; readable only server-side at apply time | never rendered | never |
| `identity.wireless.ssid` | public | yes | yes | yes |
| `identity.mgmt_ip.*`, `identity.routing.*`, `identity.ptp_*` | public | yes | yes | yes |
| **any `identity.*` field not explicitly listed above** | **secret until classified** | omitted | masked | never |
| document metadata (`id`, `vendor`, `model`, `serial_number`, `mac_address`, `hostname`, `firmware_at_capture`, `captured_at`, `source`) | public | yes | yes | yes |

The identity block is **default-secret**: a new identity field added by an R4
vendor capture is redacted everywhere until a schema revision explicitly
classifies it public. Capture coverage grows vendor-by-vendor, and default-open
would silently expose each new field; this row settles that argument once
instead of in every R4 vendor review.

Rationale for whole-blob treatment of `raw`: vendor exports carry admin password
hashes, SNMP communities, RADIUS material, and keys in vendor-specific places
that cannot be reliably enumerated across firmware versions. The precedent is
`TachyonHandler._is_sensitive_path` (`password`, `passphrase`, `private_key`,
`public_key`, `community`) — useful for *diff display* later, but redaction
correctness must not depend on per-vendor completeness. Device **admin
passwords are excluded from `identity` by policy** — they are credential-store
material (`data/credentials.json` flow), not snapshot material.

### 3.4 Capture surface (R4 contract, defined here)

```python
class BaseHandler:
    supports_config_snapshot = False   # class trait

    async def capture_config_snapshot(self) -> Optional[Dict[str, Any]]:
        """Return a schema_version-1 snapshot dict, or None if unavailable.

        Implementations populate identity via snapshot_identity_paths and
        attach the vendor-native export as raw. Called only when
        supports_config_snapshot is True and the device is connected.
        """
        return None
```

Read-back plumbing that already exists and R4 will build on: Tachyon
`backup_config` / `_get_config_curl`; Cambium `get_param act=config_regular`
(CONFIRMED in `docs/cambium-config.md`); Ubiquiti Wave GET configuration
(used by the fail-closed verify path). Prior art: PRs #48/#49/#50 (issues
#44/#45/#46) prototype per-vendor "snapshot to template" buttons; R4 replaces
those with this single trait. MikroTik's `backup_config` uses
`/export hide-sensitive` — by definition it cannot carry PSKs, one more reason
MikroTik stays descoped (epic follow-up #4).

---

## 4. Secrets policy for snapshots

Aligned with CLAUDE.md "Secrets & Private Data" and AGENTS.md §9. Rules,
enforceable in R3/R4 code review:

1. **At rest:** snapshots live only under the data dir — proposed
   `/var/lib/provisioner/snapshots/` — directory `0700`, files `0600`, owned by
   the service user. Never in git (repo `configs/` and the data repo's template
   tree are for templates, not snapshots), never synced by `deploy.sh` (which
   touches `/opt/provisioner/` code only). The inverse also holds: nothing
   under `configs/templates/**` — base templates *or* role overlays — may ever
   contain a secret (§2.2 rule 2); secrets exist only in snapshots and
   job-scoped resolved artifacts inside the data dir.
2. **API:** list and get endpoints return metadata + redacted identity per the
   §3.3 map — `psk` and `raw.content` never leave the server. The full document
   is read server-side only, at resolve/apply time. (Precedent: the credentials
   endpoint at `web/api.py:864` already returns `has_password: true` instead of
   values.)
3. **UI:** the replacement picker shows SSID, hostname, model, capture date, and
   a `PSK stored` badge. No reveal affordance in v1 (product may add an
   authenticated reveal later — open decision D6).
4. **Logs and job records:** log snapshot `id` and public identity fields only.
   The composed config artifact (§1.3) contains secrets when a replacement
   overlay injected a PSK — it gets the same `0600` + delete-after-job handling,
   and its *contents* are never logged (today's engine logs key counts and
   paths, not payloads — keep it that way).
5. **Bench host exposure:** the provisioner's web UI has no authentication and
   the host sits on the bench network. Storing customer PSKs there is a real
   policy decision, not a technical one — **product sign-off required** (epic
   follow-up #8), including retention (proposal: keep the latest N snapshots per
   serial, prune on capture; N and any max-age set by product — D5).
6. **Development discipline:** never echo snapshot contents in debugging or
   transcripts; use lengths/masks. Template examples in docs and tests use
   obvious fakes only.

---

## 5. Job context model

### 5.1 Model

`JobContext` (§1.2): `role: Optional[str]`, `replacement_snapshot_id:
Optional[str]`. Both `None` by default. The two are independent (a replacement
can also carry a role for non-identity settings); precedence when both apply is
fixed by §2.1.

### 5.2 Request shape (API → main loop → resolver)

Extend the existing `ProvisionRequest` (`web/api.py:54`) with flat optional
fields, matching its current style (`operator_id` precedent):

```python
class ProvisionRequest(BaseModel):
    port_number: int
    custom_password: Optional[str] = None
    custom_username: Optional[str] = None
    skip_firmware: bool = False
    skip_config: bool = False
    config_override: Optional[Dict[str, Any]] = None
    operator_id: Optional[int] = None
    # New (R1/R5) — absent in old clients, so requests are wire-compatible:
    role: Optional[str] = None
    replacement_snapshot_id: Optional[str] = None
```

Flow: `POST /api/provision` → `_run_provisioning` → `_provision_port_device`
builds `JobContext(role=req.role, replacement_snapshot_id=req.replacement_snapshot_id)`
→ `config_resolver.resolve(device_type, fingerprint.model, job_context)`.

Pre-existing observation, for the record: `ProvisionRequest.config_override`
(`web/api.py:61`) is a dead field — accepted by the model, consumed nowhere.
This design does not repurpose it (its name invites confusion with both the
resolver's overlays and the MAC device-override pass); removal or reuse is left
to R1's discretion.

**Auto-provision path** (`_run_port_provisioning`, no request object) constructs
`JobContext()` — the empty default. R2's kiosk flow will let the operator park a
pending selection on a port *before* provisioning starts (the three-button
screen); that pending selection lives in port state (like today's
`_credential_overrides` port-keyed dict) and is consumed into the `JobContext`
when the job launches. Whether auto-provision should *pause* awaiting a
selection instead of running the default job is R2's UX decision (D4) — the
resolver contract is indifferent.

The snapshot picker never asks the operator for a vendor: candidates are
filtered by the *detected* `device_type` (+ model-family via the existing alias
traits), preserving the epic's "never spell a vendor name" rule.

### 5.3 Backward compatibility (hard requirement) and the R1 regression tests

**Contract:** `resolve(device_type, model, JobContext())` returns exactly one
file-backed layer whose `Path` is `store.get_config_template(device_type,
model)`'s return value (or zero layers when that returns `None`), and
`as_provision_args()` passes that path through untouched. No file is opened, no
artifact is materialized, no trait consulted that could alter the result. This
makes byte-identity structural: the engine receives the identical
`(config, config_path)` pair it receives today.

R1 regression tests (this section is R1's test plan, agreed now so R1 needs no
further design):

1. **Delegation equivalence (parametrized golden test):** re-run every case in
   `tests/test_config_store.py` (Tachyon fallback gating, timestamped exports,
   alias prefix matching, Cambium legacy fallback, default/no-model cases —
   9 cases today) through `resolve(dt, model, JobContext())` and assert the
   returned layer path `==` the direct `get_config_template` result, including
   the `None` cases.
2. **Pass-through byte test:** over a fixture template tree, assert
   `as_provision_args()` returns `(None, str(path))` with the identical string
   `main.py` builds today; assert via a spy (patch `open` /
   `load_config_template`) that the template file was never *read*, and via
   mtime that it was never *rewritten* (mtime cannot detect reads).
3. **Seam test:** extend `tests/test_provision_flow.py` so a full mocked
   provision run with empty context hands the handler the same `config_path`
   as a pre-refactor control run, for a `config_after_all_firmware` vendor and
   a default-order vendor.
4. **No-new-enumeration test:** assert `provisioner/config_resolver.py` contains
   no vendor names (same grep-based guard style as epic #69's
   `test_vendor_registry.py`).

---

## 6. Per-vendor identity-field mapping

Everything below is mined from handlers, templates, and confirmed API docs in
this repo. **Empty/unknown cells are not guessed** — they appear in §6.7.
"Config path" means the key path inside the vendor's native config document.

### 6.1 Cambium (ePMP) — flat `device_props` keys

| Identity field | Config path | Evidence |
|---|---|---|
| hostname | `snmpSystemName` **and** `systemConfigDeviceName` (set together) | `mode_config.INJECT_FIELDS`, `cambium.py:2949` |
| SSID | `wirelessInterfaceSSID` | templates, `cambium.py:1501`, `docs/cambium-config.md` |
| PSK (secret) | `wirelessInterfaceEncryptionKey` | `cambium.py:439`, `cambium.py:1502` |
| admin password (secret; excluded from snapshots) | `admin_password` | `cambium.py:437` |
| mgmt IP mode | `networkInterfaceIPMethod` — present in read-back but listed read-only for `set_param` ("DHCP-assigned, not settable directly", `cambium.py:1497`) | read side usable for capture; write side → H4 |
| static IP / prefix / gateway | no *verified* keys. The only candidates in-repo are in `CambiumHandler.set_management_ip` (`cambium.py:2818-2836`), which builds nested `network.management.{ipMode,ip,netmask,gateway}` — **dead code** (zero call sites) whose nested shape does not match the flat `device_props` model the current apply path uses | → H4 |
| routing / OSPF | **not in repo** | → H7 |
| PTP master/slave mode keys | **not in repo** (mode templates set SSID/hostname only) | → H6 |
| capture (read-back) | `get_param act=config_regular` → full `device_props` | CONFIRMED, `docs/cambium-config.md` |
| apply | full: `config_import`; small sets: `set_param` | CONFIRMED; per STANDARDS.md §7, **any new endpoint must be hardware-confirmed first** |

### 6.2 Tachyon (TNA / TNS) — nested JSON export

| Identity field | Config path | Evidence |
|---|---|---|
| hostname | `system.hostname`, `system.name` (set together) | `INJECT_FIELDS`, templates |
| SSID (AP-side vap) | `wireless.radios.wlan0.vaps[0].ssid` | `INJECT_FIELDS`, `tachyon.py:1048` |
| SSID (station profiles) | `wireless.radios.wlan0.vaps[0].sta_profiles.profiles[].ssid` | `tachyon.py:1154` |
| PSK (secret) | exact key **not in repo** (sensitive-path filter matches `*password*`/`*passphrase*`, implying such keys exist under `vaps`/profiles, but the concrete path is unverified) | → H3 |
| user passwords (secret; often pre-hashed `$1$`/`$6$`) | `system.users[].password` | `tachyon.py:233-269` |
| mgmt IP mode | `network.zones.wan.mode` (`"dhcp"` seen in `tns-100.json`) | template |
| static address/prefix/gateway keys | **not in repo** (no static-mode example) | → H5 |
| mgmt VLAN | `network.zones.wan.management.vlan` (+ `vlans[]` list) | `tns-100.json`; note open PR #110 (`mgmt_vlan_enabled` synthesis bug) touches this area |
| routing | `network.routes[]` exists (empty in template); OSPF absent | → H7 |
| full-export detection | key sets `{ethernet,network,version}` / `{network,wireless,system,version}` | `tachyon.py:1025` |
| capture | `GET` config API (`backup_config`, `_get_config_curl`) | exists today |

### 6.3 Ubiquiti — Wave vs AirOS (`_api_style`)

| Identity field | Wave config path | AirOS |
|---|---|---|
| hostname | `system.hostname` | **no config-apply path exists at all** (`ubiquiti.py:979` warns and returns False); whole column → H8 |
| SSID | `wireless.interfaces[0].ssid` | → H8 |
| PSK (secret) | **not in repo** | → H8 |
| mgmt IP / routing | **not in repo** | → H8 |
| apply semantics | PUT full config + fail-closed read-back; whether PUT merges or replaces is **not established in-repo** | → H8 |
| capture | Wave GET configuration exists (verify path) | → H8 for AirOS |

Also: `apply_config_ubiquiti` defaults `False` — Ubiquiti config apply is off in
production today, so every Ubiquiti row is bench-gated twice (endpoint + flag).
Wave-Nano is the epic's named edge case (follow-up #3).

### 6.4 Tarana

Config surface is exactly `operator_id` → gNMI
`/radios/global/config/operator-id` (`tarana.py:1293`). No SSID/PSK/IP identity
exists in the provisioner's view. Expected outcome: replacement is a no-op and
Tarana is descoped from R5/R6 — needs one bench/product confirmation (H9).
`supports_config_overlays` stays `False`.

### 6.5 MikroTik

`.rsc` imperative scripts over SSH; inline dict apply rejected by design; JSON
deep-merge/snapshot model does not fit; `/export hide-sensitive` strips secrets.
Descoped from R4+ per epic follow-up #4; the route-by-model-vs-ask-operator
question for the infra-ZTP split is a product decision (D7). The *role* concept
itself (R1) may still apply to MikroTik later by selecting between `.rsc`
templates — single-file selection, no composition — explicitly out of v1 scope.

### 6.6 Evolution Digital

Passive flow, no login, no config — dispatched before the seam (`main.py:438`).
Out of scope by construction; the resolver is never invoked for it.

### 6.7 Hardware follow-ups (do NOT implement from this table — verify first)

| # | Vendor | Question the repo cannot answer | Blocks | Owner |
|---|---|---|---|---|
| H1 | Cambium | Which captured `device_props` keys are safe to write back on a *different* unit (config_import of a captured config vs factory template)? Any per-unit keys beyond the known read-only lists? | R4, R5 | bench (per `docs/cambium-config.md` standing rule) |
| H2 | Tachyon | Snapshot-as-base for replacement: does a full export from unit A apply cleanly to unit B (same model / sibling model)? Any MAC/serial-bound fields to strip? Overlay-onto-export composition validity | R5, R6 | bench (epic follow-up #2) |
| H3 | Tachyon | Exact PSK/passphrase key path under `vaps[]` / `sta_profiles` (and `security_mode` vocabulary) | R4, R5 | bench |
| H4 | Cambium | Static-IP field set (address/mask/gateway keys) and whether IP mode is settable via `config_import` even though `set_param` treats `networkInterfaceIPMethod` as read-only. The only in-repo candidates are in the dead, never-called `set_management_ip` helper (`cambium.py:2818-2836`, nested `network.management.*` shape that does not match the flat `device_props` apply path) — dismissed as evidence, cited so later implementers know it was considered | R6 | bench |
| H5 | Tachyon | Static-mode `network.zones.wan` field set (address/prefix/gateway) — repo only shows `"mode": "dhcp"` | R6 | bench |
| H6 | Cambium + Tachyon | PTP radio-role keys (master/slave / mode fields) — repo PTP mode templates only set SSID/hostname | R6 | bench |
| H7 | all PTP vendors | OSPF parameter shape — **zero** OSPF-shaped fields exist anywhere in the repo; `identity.routing` beyond `{mode, area}` is reserved, not designed | R6 | bench + product (confirm OSPF is actually in scope per vendor) |
| H8 | Ubiquiti | Wave PUT merge-vs-replace semantics; Wave PSK/mgmt-IP paths; capture + apply on **AirOS** (no apply path exists today); Wave-Nano pass | R4, R5, R6 | bench (epic follow-up #3) |
| H9 | Tarana | Confirm replacement is a no-op (`operator_id` only) → formally descope | R5 | bench + product (epic follow-up #5) |
| H10 | Tachyon | TNS switches use `config_after_all_firmware` (device leaves the provisioning network after config) — confirm capture-before-config ordering suffices for switch snapshots | R4 | bench |

---

## 7. Open decisions

| # | Decision | Proposal on the table | Owner |
|---|---|---|---|
| D1 | Role vocabulary and display names (`tower`, `home` — is "business" a distinct role or merged with home, per the epic's three-button UI?) | two roles: `tower`, `home` (home/business merged); resolver treats them as opaque strings either way | product |
| D2 | Overlay-on-full-export: keep the v1 refusal or allow merge-into-export after bench validation | v1: refuse + note (§2.4) | repo (v1 rule) → bench (relaxation) |
| D3 | Missing role overlay for an explicitly selected role: soft-proceed with a visible note vs fail the job | soft-proceed (§2.3) | product |
| D4 | Kiosk auto-provision vs wait-for-selection: does plugging in start the default job immediately, or park until the operator picks one of the three buttons? | R2 decides; resolver supports both | product (with R2/#75) |
| D5 | Snapshot retention & pruning (N per serial, max age) and access policy for customer PSKs on the bench host | latest N per serial, prune on capture; N set at sign-off | product (epic follow-up #8) |
| D6 | UI "reveal PSK" affordance (vs mask-only) on an unauthenticated kiosk | v1: mask-only, no reveal | product |
| D7 | MikroTik: route infra-ZTP by model or ask the operator (interacts with the planned infra-ZTP split) | out of this epic; blocks any future MikroTik role support | product (epic follow-up #4) |
| D8 | R7 fleet-data source of truth (netbox?), API access, bench-host connectivity policy | blocked externally | product / external (epic follow-up #9) |
| D9 | Promote `_deep_merge` + full-export heuristic to shared util / class hook exactly as specified in §2.2/§1.2, or fold into epic #69's VendorSpec if #76 lands first | as specified; re-home under VendorSpec when it exists | repo (R1) |

Acceptance per issue #113: with this document merged, R1 (role overlays +
regression suite, §5.3) and R3 (snapshot store, §3) can start without further
design meetings; every hardware-gated cell is enumerated in §6.7 with an owner.
