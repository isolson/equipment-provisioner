# Source and bench reconciliation — 2026-09-10

The development checkout was at `eee0106`, while the host reported a dirty
`4deb4c9` deployment plus scoped bench patches. Its `/opt/provisioner/.git/HEAD`
was older still (`74803bb`), so neither marker described the running files.

## Reconciled baseline

Merged the preserved Git work through `5835fbc` (contract, evidence records,
kiosk/assets pages and documentation), retaining the local agent-loop commit
and the September 9–10 validation notes. Compared SHA-256 hashes of 252 selected
host source, test, documentation and asset files: 213 matched that Git revision;
39 differed or existed only on the host. Private snapshots and the original
local edits were retained before reconciliation.

The reconciliation retains the newer Git safeguards rather than replacing
source wholesale with the older dirty host tree:

- Required-secret preflight in the shared flow and setup readiness.
- Host credential editing and scoped installation of bundled baselines.
- The newer assets page and its API/tests.
- Existing evidence fixtures and their capture provenance.

It integrates the hardware-tested Tachyon profile/merge/readback/root-password
fixes, the Cambium account/SNMP-write/scan-policy fixes, their regression tests,
and the three corrected Tachyon family baselines. Standard Cambium scan masks
are selected by model in the handler; a shared 4K template no longer assigns
160 MHz to the 4518. Dated scan observations supplement historical fixtures.
The 301/302 and 303X baselines omit four device-owned or unclassified fields
that failed the template gate; their profiles and management-VLAN policy are
preserved. Archive metadata is removed from the 303X template. These template
cleanups have passed static checks; their new bytes have not been deployed.

Internal credential forwarding now uses the complete credential model in both
main setup and readiness checks. This closes the class of omission that dropped
the new SNMP write field. The credential-edit API also accepts that field and asks handlers to resolve
missing deployment credentials, including credentials with a different internal
name. API tests isolate saved bench credentials so results do not depend on
private host state.

The vendor-isolation review, epic status, contributor instructions and model
checklist now describe the actual VendorSpec architecture. The old audits
remain in Git history.

## Operational boundaries

This source reconciliation is not a hardware deployment. The bench continues
running its previously tested scoped patches. Runtime credentials remain in
`/etc/provisioner/config.yaml`; runtime templates remain in
`/var/lib/provisioner/repo/configs/templates`. No device credentials, raw HARs,
raw device exports, databases or private host configuration were imported into
tracked source. The host-only `restart-kiosk.sh` was retained privately as an
operational artifact rather than installed as a new repository entry point.

A later promotion must deploy the tested reconciled revision, explicitly sync
reviewed runtime templates, and run the host/kiosk smoke checklist. Record the
exact clean commit and any scoped patch hashes; do not treat the host's `.git`
directory as deployment provenance. See [the branching contract](BRANCHING.md).

## Bench acceptance remains scoped

Use the dated [303L](303l-validation-2026-09-09.md),
[303X](303x-validation-2026-09-10.md), [302](302-validation-2026-09-10.md) and
[Cambium](cambium-validation-2026-09-10.md) reports for completed checks and gaps.
303X AP/management-VLAN connectivity is operator-confirmed. Correct scan masks
on 300-25/4518 are not RF validation at every width, and the 46xx 160 MHz policy
still needs a connected device. TNS-100 is excluded from new deployments.


## Validation environment

Tests run from a separate candidate checkout under the private reconciliation
record on the host, using the existing isolated test environment (Python 3.13).
No candidate code is installed into `/opt/provisioner`. Python 3.9 compatibility
is checked by the repository syntax gate; a native Python 3.9 run remains the CI
matrix's responsibility. Documentation, template ownership and committed-evidence
gates are also required. The stale PTP test now checks the specific rejection for
an incomplete settings profile rather than expecting an obsolete generic error.

Final result: **950 tests passed, 4 skipped**; documentation, Python 3.9 syntax,
template ownership and committed-evidence gates all passed. The isolated logs
are under `/var/lib/provisioner/bench-evidence/reconciliation-2026-09-10/`.
The final live health check returned HTTP 200; provisioner and kiosk watchdog
were active, and the deployed Cambium handler hash was unchanged.

## Deployment reconciliation — 2026-09-14

The September 11 scoped patches left the bench running a mixture of revisions.
The September 14 audit confirmed that the committed handlers retain those
hardware fixes. Remaining source differences add required-secret preflight,
credential editing, baseline installation/status, and profile upload handling;
MikroTik's handler difference was whitespace only.

The PTP test failure was environment-dependent: it expected an incomplete
profile but did not supply one. It now supplies an explicit profile without
`centerFrequency`, so it exercises the intended rejection on both CI and the
bench without relying on installed data files.

The reconciled deployment installs a clean Git archive into `/opt/provisioner`
and explicitly synchronizes every tracked `configs/templates/` file into
`/var/lib/provisioner/repo/`. The reviewed Tachyon differences remove fields
outside the template ownership contract; the Cambium generic PTP templates
add the committed protocol selector. They still require certified complete
profiles before use. Uploaded profiles outside tracked paths are preserved.
Installing corrected templates does not establish fresh hardware acceptance.

Private rollback snapshots, the source commit, per-file hashes, runtime
configuration integrity checks, and deployment results are recorded under
`/var/lib/provisioner/bench-evidence/reconciliation-2026-09-14/`.
`/opt/provisioner/.deployed-rev` identifies the installed commit;
`/opt/provisioner/.deployment-manifest.json` records the tracked-file hashes
for both code and active templates. Recheck those hashes after any subsequent
patch; a Git marker alone is not proof of the deployed bytes. Host credentials,
raw captures, firmware, and operational state remain outside this release.

Pre-deploy validation: 1,000 tests passed, 5 skipped on Python 3.13. Documentation,
Python 3.9 syntax, template ownership, and committed-evidence checks passed.
GitHub CI provides the separate Python 3.9 runtime result. PR 168 remains a
bench feature release; the MikroTik secret-handling acceptance work in issue
167 and the outstanding RF/cold-start hardware checks are not closed by source
reconciliation.
