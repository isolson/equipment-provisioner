# Cambium bench validation — 2026-09-10

Devices: ePMP 4518 on port 6 (5.11.1), Force 300-25 on port 3 (final readback: 5.11.1 in both banks).
Initial automatic runs passed config upload/verification but failed secrets.
An additional device on port 5 was not identified and failed login; it is not
part of these two model results.

## Findings and corrections

The 300-25 already had the intended Wi-Fi and SNMP read-only values. The old
unconditional secret write reported failure. The corrected path reads first
and skips an unnecessary write only when intended values and standard-admin
login have been verified.

The 4518 retained factory admin access and factory SNMP communities. Its settings
API rejected the secret update because the SNMP read-write community was shorter
than eight characters. Added a separate `snmp_write_community` credential field
and kept RO/RW distinct. The standard RW value in the supplied known-good 4518
HAR matches the live 300-25; it was migrated privately into the host config.
The main process must forward this field into handler credentials, and the
handler must preserve it when login fallback replaces authentication candidates.
A regression exercises the actual main setup-to-handler handoff.

General `set_param` updated Wi-Fi/SNMP but did not change the live 4518 admin
password. The supplied HAR records `set_account_params` for account changes
(entry 289); a live request returned success and fresh standard-admin login
worked. The handler now uses that confirmed endpoint and requires fresh
login/config access. Secrets stay outside templates. Both SNMP communities are
classified secret-owned. Readback, settings writes, and logout send authenticated
URLs via curl stdin config rather than process arguments.

Manual repair/readback passed on both units: Wi-Fi, SNMP RO, SNMP RW, and standard
admin access. This is recovery evidence, not factory qualification.

## Factory evidence

4518 factory run 1: reset and reboot requests were accepted. Boot took several
minutes; the device eventually accepted factory login, and its baseline was
captured before automatic provisioning restarted. No PoE cycle was needed.
Switch inventory confirmed ether6 belongs to isolation VLAN 1996.

The automatic run then failed closed because the new RW field was absent from
the main process's explicitly constructed credential dictionary. Direct scripts
used the full config model and had masked that handoff gap. The main process
forwarding correction is covered by a new setup-level regression. Factory run 2 passed every automatic step. Independent readback confirmed all
24 baseline fields, matching Wi-Fi/SNMP RO/SNMP RW secrets, working standard
admin login/config access, and rejection of factory and empty passwords.

The Force 300-25 factory run 1 also passed every automatic step and the same
independent 24-field, secret, and authentication checks, after a captured
factory baseline with default login accepted. Its mask-1 reset/reboot sequence
is confirmed in the supplied HAR. Both units still need operator
AP/link, management VLAN DHCP/reachability, traffic, and power-cycle acceptance.
Do not mark either model fully hardware-validated from recovery alone.

## Evidence and deployment

Private host records:

- `/var/lib/provisioner/bench-evidence/cambium/4518/live-2026-09-10/`
- `/var/lib/provisioner/bench-evidence/cambium/Force-300-25/live-2026-09-10/`
- `/var/lib/provisioner/bench-evidence/cambium/secret-correction-2026-09-10/`

They contain raw readbacks/responses, template/config snapshots, code backups,
and deployment hashes. Runtime config now includes the separate RW secret and
is root-owned with mode 0600. The original review source was kept in ignored `.context/` while the checkout
lagged the host. It is now integrated into tracked source; see the
[reconciliation record](RECONCILIATION_2026-09-10.md).

The account endpoint revision passed 56 focused tests and 913 full-suite tests,
with four skips and the same pre-existing Cambium API expectation failure.
The forwarding revision passes 57 focused tests and 914 full-suite tests,
with four skips and the same pre-existing failure.


## Final handoff

Both Cambium units passed factory-reset provisioning on their recorded firmware.
The kiosk/web service and watchdog are restored. AP/link, management VLAN DHCP
and reachability, traffic, and cold power-cycle persistence remain operator
acceptance work. Firmware was already current on these Cambiums; no new
migration path was qualified. No switch PoE cycle was required during these runs.

Final scoped source hashes:

- Cambium handler: `e9ac89ecc73bcb8840e264809ab5849d31e592c447c799b659fb2bc7fc683b74`
- Config schema: `67d272ff813f9c237da31991c8d51659b06119ca968a30bb586d42bfb9d4de35`
- Main credential forwarding: `8bc8c42990777be824c705dd2247561b105d64d5bb1d2f218b76e6bd35c73add`

Local review patch: `.context/cambium-secret-recovery.patch`, against the
original deployed snapshots. It includes the focused acceptance tests and the
main setup-to-handler secret forwarding regression.

## Scan-width correction and live readback

The initial 24-field acceptance omitted scan bandwidth because the handler
classified it as device-owned. Both earlier post-fix exports contain mask `3`
(20/40 only). This did not satisfy the deployment requirement.

The handler now selects `19` (20/40/80 MHz) for Force 300 and 4518, and `51`
(20/40/80/160 MHz) for all 46xx model numbers, including 4600C. Selection runs
in the standard SM JSON-import and set_param paths. It preserves explicit
AP/PTP mode settings. The mask is now fleet-owned and verified exactly. Model
selection is necessary because 4518 and 46xx share a template family.

After the scoped handler deployment and service restart, automatic provisioning
ran again. Both bench radios then had mask `19`; the follow-up tool needed no
scan write. Fresh standard-authenticated readbacks passed **25 baseline fields**
plus matching Wi-Fi, SNMP RO, and SNMP RW credentials. Frequency lists for all
three enabled widths were empty, meaning all country-permitted channels are
scanned. A preliminary redundant set_param call on the already-correct 300-25
returned false; the follow-up read-only check confirmed the desired state.

Both radios report **5.11.1 in both firmware banks** in this capture. The
300-25 factory-run export already reported 5.11.1 in both banks, so this scan
correction did not establish a new firmware transition. An earlier prose
summary labeling the final 300-25 result 5.12.0 was incorrect; use the saved
readback version.

This establishes configuration/readback acceptance, not RF association at
every width or cold-power persistence. No 46xx is connected; its 160 MHz policy
has code tests and the 4616 HAR as reference, but needs live qualification.

Validation: **87 focused tests passed**; full suite **928 passed, 4 skipped**,
with the same pre-existing operator-action error-message test failure noted
above. Python 3.9 syntax parsing passed. Provisioner and kiosk watchdog were
restored and active after the scoped deployment.

Private host evidence:

- `cambium/scan-policy-2026-09-10/deployment.json`, original source/test backups,
  and review patch under `/var/lib/provisioner/bench-evidence/`.
- Each model's `live-2026-09-10/scan-policy-before.private.json`,
  `scan-policy-after.private.json`, and `scan-policy-summary.json`.
- Isolated test logs `scan-final-focused.private.txt` and
  `scan-final-full.private.txt` in the existing 303L test workspace.

Deployed Cambium handler SHA-256:
`3ad7f59bd83b5145562093bb7a7ee9b5a3770e4549913f6832ec2c097a6c1b9c`.
The older hashes above remain historical deployment records. These changes are now integrated into tracked source; see the
[reconciliation record](RECONCILIATION_2026-09-10.md). The private recovery patch
is retained as historical provenance.
