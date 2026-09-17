# Hardware evidence handoff

Updated 2026-09-10 during [source reconciliation](RECONCILIATION_2026-09-10.md).
The previously separate evidence work through `432274f` and its dependencies
are now integrated into this checkout. Use these files directly:

- [Bench Evidence SOP](BENCH_EVIDENCE.md)
- [Capture runbook](EVIDENCE_RUNBOOK.md)
- [Contribution workflow](EVIDENCE_CONTRIBUTING.md)
- [Evidence inventory](../bench-evidence/INVENTORY.md)
- `scripts/summarize_har.py` and `scripts/check_bench_evidence.py`

The inventory's historical observations do not imply that every hardware gate
has passed. Consult the dated validation reports for subsequent bench results.

## Storage and references

Keep original HAR files and device exports outside Git on the provisioner:

```text
/var/lib/provisioner/bench-evidence/<vendor>/<model>/<firmware>/
```

Use root-owned directories with mode `700` and files with mode `600`. This
directory is separate from deployed code and runtime config templates. Retain
originals without overwriting an earlier capture; record the original filename,
capture time, purpose, and SHA-256 digest in private provenance metadata.

Use `~/bench-evidence-staging/` outside the checkout for local intake. Keep it
private with the same directory/file permissions. Copy files from Downloads;
do not move or delete the originals until the host copies are verified.

Commit reviewed manifests, capture summaries, and redacted fixtures under the
matching `bench-evidence/<vendor>/<model>/<firmware>/` record. Reference that
record from handler notes, tests, issues, and validation reports. Read its
summary before inspecting raw evidence. Never print raw headers, URLs with
query values, bodies, credentials, or device identities into tool output.

Raw exports are process evidence. Create and verify a separate sanitized
template before using any export as a new-deployment default.

## Tachyon findings to retain

- `TNA-303L-65/1.15.1-rev-8541`: the existing manifest records transition and
  reset/restore HARs, a known-good backup, and an exact post-reset backup.
  Its `transitions` list is empty, so these captures do not establish that
  automatic provisioning passed.
- `TNA-301/1.15.1-rev-55177`: the manifest records an AP process capture.
  The exact pre-first-apply baseline is missing; the supplied upload is not
  a post-apply backup or a reusable default template.
- The 303L migration record says a 1.12.4 export must not be imported directly
  onto 1.15: missing port/VAP management-VLAN flags can leave the device without
  a management address. Validate upgrade followed by a reviewed 1.15 baseline
  and a fresh device export.
- Separately, commit `1d8f5eb` fixes provisioner normalization that inserted
  inconsistent management-VLAN flags. Preserve the complete, coherent wired
  and wireless backhaul flag set. That fix is now included in this checkout.
- VLAN 12 validation must prove management DHCP and reachability over the
  intended path after apply and power cycle. A successful config POST alone
  does not prove this. Bench isolation VLANs and device management VLAN 12
  are separate networks.
- TNS-100 is legacy/end-of-life for this deployment program. Preserve historical
  evidence, but exclude it from the new-deployment validation queue.

## Current access gaps

Downloads enumeration was denied by macOS. The user subsequently uploaded seven
HARs and seven Tachyon TAR exports. All 14 are now privately staged, hash-verified,
and reviewed locally; see [the intake report](evidence-intake-2026-09-09.md) for
observations and integrity records. The reset HAR has an exact config readback
match to the supplied 303L baseline backup.

Bench access is now working: the earlier SSH failure was an unknown host key,
not a changed key. All 14 raw uploads have been copied into the host's private
intake directory and their hashes verified. See the
[303L validation record](303l-validation-2026-09-09.md) for the live investigation.

Next: reconcile the archived files with the existing model records and finish
the live validation. Capture only the remaining gaps before marking any exact
model/firmware/role validated.
