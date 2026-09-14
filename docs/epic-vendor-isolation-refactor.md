# Vendor isolation refactor: status and remaining work

Reconciled 2026-09-10. The original implementation plan is preserved in Git
history. Use [the current architecture review](ARCHITECTURE_ISOLATION_REVIEW.md)
and [the handler development guide](HANDLER_DEVELOPMENT.md) for new work.

| Original story | Current state |
| --- | --- |
| 0: Registry consistency | Implemented; tests cover derived views, fake-vendor insertion and registration removal |
| 1: Vendor-neutral engine | Implemented; firmware lookup uses a handler override and the engine has no brand strings |
| 2: Shared handler registration | Implemented; handler-derived CLI/API/setup lists |
| 3: Credential defaults | Implemented; registry defaults and generic credential schema; reconciliation also forwards all schema fields internally |
| 4: IP/boot-ping registry | Implemented; addresses derive from specs, with ordering regression tests |
| 5: Frontend metadata | Implemented; UI metadata derives from backend specs |
| 6: VendorSpec registry | Implemented; includes firmware sources, patterns, families, defaults and active-vendor filtering |
| 7: Fingerprint modularization | Remaining; signatures/probes/model extraction are still shared code |

## Remaining priorities

1. Keep source, deployed code, runtime templates and evidence provenance aligned.
   See [the reconciliation record](RECONCILIATION_2026-09-10.md). A stale host
   `.git/HEAD` or a `-dirty` deployment marker is not a reproducible release.
2. Require sibling-model regression coverage for shared family changes and
   preserve the real resolver path in tests. Do not expand hardware qualification
   based solely on matching family names.
3. Retain credential preflight and fresh authentication/readback checks. New
   credential fields must survive the real setup path.
4. If detection is modularized, preserve historical order, weights, simple-mode
   discovery, Evolution Digital's passive flow and MikroTik destructive-operation
   gates. Make this a separately tested change, not part of adding a new model.

The architecture work above is not a claim that every vendor/model has completed
hardware validation. Registry tests and bench qualification answer different
questions.
