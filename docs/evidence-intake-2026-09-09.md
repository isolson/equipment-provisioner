# Uploaded evidence intake — 2026-09-09

All 14 uploads were copied into `~/bench-evidence-staging/intake-2026-09-09/`,
outside the checkout. Each copy was verified against its upload with SHA-256.
Raw files and private provenance are mode `600`; staging directories are mode
`700`. Original uploads were preserved. Total raw size: 88,361,838 bytes.

This is an intake report for the existing evidence workflow identified in
[EVIDENCE_HANDOFF.md](EVIDENCE_HANDOFF.md), not a second validation registry.
All 14 files have subsequently been copied to the provisioner host's private
`/var/lib/provisioner/bench-evidence/intake-2026-09-09/` directory, and their
hashes verified there. Live investigation is recorded in
[the 303L validation report](303l-validation-2026-09-09.md); hardware validation
is not yet complete.

## Reviewed observations

Review used parsed HAR metadata, allowlisted API operations and selected config
fields. It did not publish request/response bodies, headers, identities, or
credentials. HAR status 0 means no HTTP response was recorded; it does not
establish either successful application or a device-side rejection. HTTP 200
alone does not establish semantic success, persistence, DHCP, or reachability.

The three checked 1.15 fields are `system.latitude`,
`services.snmp_traps.port`, and `services.snmp.v3.ro.encryption_mode`.
Presence establishes a schema observation, not the running firmware version.
Exact Tachyon firmware revisions should be reconciled with the existing
manifests and device status before final record classification.

| Uploaded file | Observation |
| --- | --- |
| `303L-resetconfigprovision1.15.har` | 134 requests; reset and four config POSTs returned HTTP 200. Entry 108 config readback exactly matches the 15:44:32 backup. |
| `cambium4616.upgraderesetconfig.har` | 247 requests; firmware 5.11.0 and 5.11.1 reported. Upgrade, polling, reboot, and two exports observed. Reset/config import not established by this review. |
| `cambium4518.upgraderesetconfig.har` | 375 requests; firmware 5.10.4 and 5.11.1 reported. Upgrade, polling, reset, reboot, and config import observed with HTTP 200. |
| `cambiumf325-reset-config-upgrade.har` | 245 requests; firmware 5.11.1 and 5.12.0 reported. Reset/export/upgrade observed; config import has HAR status 0, not a confirmed successful response. |
| `ubiquti-login-setup-upgrade-mgmtvlan.har` | 392 requests; model reports Wave Nano. Both observed mgmtVLAN values are null. VLAN 12 transition remains unproven. |
| `tachyon-301l-downgrade-upgrade-config.har` | 262 requests; device identifies as TNA-301 despite filename. Two firmware PUTs, two update POSTs, and two config POSTs returned HTTP 200. AP process evidence. |
| `tachyon-303l-downgrade-upgrade-config.har` | 213 requests; two firmware PUTs, two update POSTs, and two config POSTs returned HTTP 200. Readbacks show zero then four station profiles. |
| `20260902.155827.TNA-303L-65.tar` | Four station profiles, VLAN 12 present; management flags and three checked 1.15 fields absent. Legacy-shaped export; do not select it merely because it is newest. |
| `20260902.154432.TNA-303L-65.tar` | Zero station profiles, no VLAN 12 value. Management flags and checked 1.15 fields present. Exact match to reset HAR entry 108; supports baseline provenance. |
| `20260902.152619.TNA-303L-65.tar` | Four station profiles, VLAN 12 and management flags present; checked 1.15 fields present. Previously indexed known-good candidate, not independently hardware-validated here. |
| `20260901.150330.TNA-303L-65.tar` | Zero station profiles despite VLAN 12 and management flags being present. Re-check before using as an SM reference. |
| `20260831.152235.TNA-303L-65.tar` | Four station profiles, VLAN 12, management flags, and checked 1.15 fields present. Historical post-migration reference. |
| `20260831.105205.TNA-301.tar` | AP role, four profiles, VLAN 12 and management flags present; checked 1.15 fields present. AP process evidence, not an SM default. |
| `20260831.104517.TNA-301.tar` | AP role, four profiles, VLAN 12 present; management flags and checked 1.15 fields absent. Legacy-shaped reference. |

## Management VLAN evidence

The 303L exports with explicit flags have `eth0=true`, `wlan0` VAP 0 `true`,
and `wlan1` VAP 0 `false`. Preserve this device-authored combination; setting
every wireless flag to true or every flag to false would discard its meaning.
The older TNA-301 export and the newest supplied 303L export omit these flags.
This supports treating legacy export migration separately from the provisioner
normalization regression documented in commit `1d8f5eb`.

The reset HAR config response at entry 108 (`2026-09-02T20:44:21`, as recorded
in the HAR) is JSON-equal to `config.json` inside the 15:44:32 archive. The
archive was parsed in memory without extracting arbitrary archive paths.
This establishes a capture/export link, not a successful automatic provisioning
transition. A post-apply VLAN 12 DHCP/reachability check and power cycle remain
necessary before validation.

## Integrity inventory

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `303L-resetconfigprovision1.15.har` | 5057439 | `1fd482a5b5c7b00e3ef9520f6c4b63100f9482cf92686fdeef685ffe9004d391` |
| `cambium4616.upgraderesetconfig.har` | 15159649 | `0ffbcf3df5c741ceb9b0fa5ecedcbb64aba87014055682fd234a9d4195f5987a` |
| `cambium4518.upgraderesetconfig.har` | 20965990 | `e66d3efb34848e333b8e31715861f4025bd847c8abb12b20304ce3bfa601d214` |
| `cambiumf325-reset-config-upgrade.har` | 11764317 | `5bd1ddf9c6567ddf8183b1a924acc28a1d9be2725e088cc82ecd971999b3fc77` |
| `ubiquti-login-setup-upgrade-mgmtvlan.har` | 22073507 | `d76bbecdd495917c86c58a1c6050a7183d2c096e2cef3cf32933def75db50c56` |
| `tachyon-301l-downgrade-upgrade-config.har` | 8842149 | `8e10049a4111a0821322e5dfd0565a18fe6a67fe56971cb91ec480eb93b67942` |
| `tachyon-303l-downgrade-upgrade-config.har` | 4403555 | `a72754a0ef0e41a43728adb1f16e00fec3423770e1f6f4dabdab7be9c7a498ec` |
| `20260902.155827.TNA-303L-65.tar` | 14848 | `9c9e8eab613fe7699a999785a9d012c8696bdbc1d048b29b8cc4f4f16a167222` |
| `20260902.154432.TNA-303L-65.tar` | 11776 | `663eb1a9859bcfb9d3b2fc0d6400621b8dac4b5897fe1347e4f4dfe4d698d163` |
| `20260902.152619.TNA-303L-65.tar` | 14336 | `559a6ae6edce3a1da861c0d4ffac33632b9dfb3d64c2972191ec9ffa338baab0` |
| `20260901.150330.TNA-303L-65.tar` | 12800 | `b3425b8711db61b7055dd656646def70aff158a4840d303c55a81a0b7674222c` |
| `20260831.152235.TNA-303L-65.tar` | 15360 | `73efe126f6c9ea8f76f150354a020d1f5309b9900d2f27d1b63049006b9bd11d` |
| `20260831.105205.TNA-301.tar` | 13312 | `d05f7cac0993eea04d13ad23ce56cc7a889b26c0243699c36b8bb43172f534de` |
| `20260831.104517.TNA-301.tar` | 12800 | `a8173c0403fb94854346b362abebdbda96fc643a3b967538422fd8476f8ef5d0` |

## Remaining work

1. Host archival and hash verification are complete. Reconcile the private intake
   files with the existing per-model evidence records without overwriting history.
2. Integrate the existing evidence branch and reconcile each upload with its
   model/firmware/role manifest. Preserve both history and known-good candidates.
3. Add or update the 4616 process-capture reference and investigate the Force
   300-25 import with no recorded response. Do not classify by filename alone.
4. Complete missing baseline/post-apply exports and run the actual provisioning
   transitions before changing hardware validation status. Keep TNS-100 legacy-only.
