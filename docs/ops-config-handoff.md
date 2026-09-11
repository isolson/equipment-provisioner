# Ops configuration handoff for the bench provisioner

Use Ops as the owner of infrastructure intent, hardware profiles, rendering,
and network policy. The provisioner detects the physical unit, requests the
selected configuration, applies it through its vendor handler, and verifies
live state. Do not copy Ops address calculations or hardware tables here.

Status: source review and proposed API extension, 2026-09-10. No production
API deployment or live generated-config application was performed.

## Existing authority

- [MikroTik provisioning contract](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/docs/operations/mikrotik-provisioning-contract.md): trusted source commit, exact validated hardware profile, two preflights, full import, readback and credential-bearing file removal.
- [Infrastructure lifecycle](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/architecture/50-infra-ztp.md): git intent owns desired state; NetBox is current-known inventory. Serial-bound spare states differ from authenticated site-slot claims.
- [Hardware profiles](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/netbox/mikrotik_models.yaml): reuse this table through Ops; do not infer ports from model marketing names.
- [Business router standard](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/docs/operations/business-router-standard.md) and [business switch standard](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/architecture/48-business-switch.md): business policy includes VLANs 10/20/40/70. The switch document currently targets Cisco; the requested MikroTik implementation needs an explicit profile.

## Existing API and gaps

The reviewed [router](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/treehouse-ops/api/app/routers/provisioning.py),
[schemas](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/treehouse-ops/api/app/schemas/provisioning.py), and
[service](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/treehouse-ops/api/app/services/provisioner.py) implement:

| Route | Current source behavior |
| --- | --- |
| `POST /provisioning/configs/generate` | Synchronous generation from `device_name` and optional `template_name` |
| `GET /provisioning/configs` | List generation records; name filters are substring matches |
| `GET /provisioning/configs/{config_id}` | Return detail, including full config text |
| `GET /provisioning/configs/{config_id}/download` | Download the stored render |

These routes require an API key. The service uses NetBox context, stores the
full render in its database and output directory, and dispatches site-router,
distribution-switch and radio context builders. This is not yet the full
intent-driven bench contract. The request lacks physical identity, installed
firmware, requested lifecycle state, hardware-profile revision and trusted
source binding. The reviewed generation path does not invoke the contract's
lint/preflight or implement single-use artifact delivery and a verification
receipt. Route existence in source does not establish live deployment readiness.

Do not poll the config list for the newest matching name and apply it. Bind a
job to an exact device and immutable render ID. Poll job status only; fetching
a configuration must not itself reset, enroll or configure a device.

## Proposed extension (not implemented endpoints)

Extend the Ops contract with an executor job resource under
`/provisioning/executor-jobs`. Reuse its renderer and hardware resolver.

1. **Request:** POST an idempotency key, observed serial/board/architecture/
   interface inventory, RouterOS version, selected role and lifecycle state,
   and optional declared slot. Include the executor's allowlisted source SHA.
   Ops authenticates the executor and requires operator authorization for a
   slot-bound claim. Refuse an incompatible or unvalidated board before render.
2. **Poll:** GET the returned job ID. Return `pending`, `ready`, `failed`,
   `expired` or `complete`, with bounded retry guidance. Status contains no
   configuration or secrets. A retry with the same key and input returns the
   same job; different input with the same key is a conflict.
3. **Ready manifest:** bind serial, exact hardware profile and revision, role,
   state, slot/declaration revision, source SHA, supported firmware, render
   SHA-256, lint result, apply method and a versioned verification checklist.
   Reject stale identity, changed firmware, expired artifacts or unknown schema.
4. **Artifact:** deliver the complete render through an authenticated,
   short-lived, single-use mechanism. Record its digest and delivery audit.
   Keep credentials out of polling responses, URLs, logs and retained evidence.
   A lost delivery requires an explicit reissue; do not blindly replay a token.
5. **Execution and receipt:** recheck the physical unit before reset/import.
   Apply the contract's reset/upload/import sequence through the handler.
   Report each readback check plus artifact-removal verification, source and
   render digests. Ops updates current-known inventory only from verified
   results. Failed or interrupted execution never claims completion. Retain
   only the digest and contract-redacted evidence after the job.

## Hardware and qualification blockers

- Ops maps the alias `hEX S` to RB760iGS. Our unit is E60iUGS ARM. Add an exact
  E60iUGS profile and disambiguate the alias before any Ops-generated import.
- RB960PGS / hEX PoE has a validated physical-port profile and business-router
  defaults upstream. That is not evidence that all three requested roles pass
  this provisioner's end-to-end workflow.
- Both RB5009 profiles are marked `bench_validated: false` upstream. Complete
  that validation and the requested role mappings in Ops, then capture each
  supported transition on the bench.
- The initial hEX S buttons verified simple routing/bridging only. The
  subsequent [business bench profiles](business-wired-profiles.md) implement
  business VLAN policy and advanced local management, but do not implement
  the full Ops reset, KDF, claim or infrastructure lifecycle. Keep infrastructure application unavailable until this handoff
  and the exact model/firmware evidence are in place.

Next implementation slice: an Ops executor request/manifest/status contract
with identity, source, profile and lint tests. Then add delivery/receipt and a
provisioner client against that contract. Do not add a second renderer here.
