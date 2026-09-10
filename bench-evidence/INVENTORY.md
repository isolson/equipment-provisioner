# Capture inventory and gaps (2026-09-02)

Classification of the bench files on hand, by evidence record. Raw files live
on the bench host under `/var/lib/provisioner/bench-evidence/` and in the
local mirror `~/bench-evidence-staging/`. "Good" means usable as the record's
fixture source. "Re-check" means capture again before use.

## Tachyon TNA-303L-65: the 1.12.x to 1.15 migration

The 1.15 schema adds fields that 1.12.x exports do not have:
`services.snmp_traps.port`, `services.snmp.v3.ro.encryption_mode`,
`wireless...vaps[0].isolate`, `system.latitude`. The handler injects these on
apply (`_normalize_config_for_apply`). An export without them is pre-migration.

| Export (Downloads) | Schema | SM profiles | Class |
| --- | --- | --- | --- |
| `20260310.135219`, `20260424.143334`, `20260609.143022`, `20260804.121358`, `20260825.123417`, `20260831.094539` | 1.12.x | 4 or 0 | Pre-migration. Keep as history only. Not fixture sources. |
| `20260721.120711`, `20260804.121652`, `20260831.094637`, `20260831.152235` | 1.15 | 4 | **Good.** Post-migration SM exports with the AP profile list intact. |
| `20260804.122037`, `20260901.150330` | 1.15 | 0 | **Re-check.** Post-migration exports with an empty profile list. An SM with no profiles cannot associate. Confirm whether the migration or the operator cleared them. |
| host `firmware-transition/*` (7 backups, 2026-08-31) | 1.15 | see host | Process evidence for the transition run. `before-next-change` differs (cloud, ssh password login). Not fixture sources until each is labeled. |
| tracked `TNA-303L-65/SM/default.tar` | 1.15, rebuilt 2026-09-02 | 4 | **Good.** Rebuilt from the 15:26 working export with `scripts/build_baseline.py`: fleet policy, role, the full management VLAN set, and the 4-profile list without passphrases. |

Firmware images on hand for this family: `tna-303l-1.15.0-r8516`, `-r8520`,
`-v1.15.1-r8541` (target).

## Tachyon TNA-301, TNA-303X, tn-110-prs, tns-100

| Export | Role | Schema | Class |
| --- | --- | --- | --- |
| TNA-301 `20260831.105205` | ap | 1.15 | Good AP process capture (tower-specific, not a template). Record exists. |
| TNA-301 earlier (`20260219`, `20260310`, `20260602`, `20260825.*`, `20260831.104517`) | ap | 1.12.x | Pre-migration history. |
| TNA-303X `20260825.132533` | sta | 1.15 | **Good** SM post-migration export, 1 profile. Candidate fixture; no record yet. |
| TNA-303X `20260825.132539`, `20260727.083450` | ap | 1.12.x | AP history; the 303X AP template tar is pre-1.15 shape. Re-check. |
| TNA-303X `20260310`, `20260825.123627` | sta | 1.12.x | Pre-migration history. |
| tn-110-prs `20260325` (ap), `20260825.123311` (sta) | mixed | 1.12.x | Pre-migration history. |
| tns-100 `20260409`, `20260517`, `20260727` | switch | 1.12.x | History. The tracked `tns-100.json` had a community string removed on 2026-09-02. |
| `config-100-66-52-*.tar` (manager 1.3.1) | ap / switch | 1.12.x | Deployed-unit exports. History. |

Tracked templates `TNA-301-302/*` and `TNA-303X/*` are pre-1.15 shape with no
profile list. Re-check against a post-migration export per family.

## Cambium

| File | Model, firmware, role | Class |
| --- | --- | --- |
| `epmp-backup-goodconfig.json` | 4518, 5.11.1, SM | Good. Known-good fixture (record). |
| `ePMP-Backup-F4518_77fe98-*.json` | 4518, 5.10.4 factory | Good. No-config fixture (record). |
| `epmp-backup-BADCONFIG-apBAD.json` | 4518, 5.11.1, AP pattern | Failure witness (record, raw only). |
| `cambium4518.upgraderesetconfig.har` | 4518, 5.10.4 to 5.11.1 | Good. `workflow.har` (record). |
| `ePMP-Backup-tw32a-tw18-*.json` | 4616, 5.11.1, SM | Good. Known-good fixture (record). |
| `ePMP-Backup-F300-25_*.json`, `cambiumf325-reset-config-upgrade.har`, `cambium_169.254.1.1_5.11.1dualbanktestsuccess.har` | Force 300-25, 5.11.1 | Good. Record (role witness). |
| `ePMP-Backup-f4625-sm-*.json` | 4625, 5.11.1, SM | Good SM export. **No record yet.** Second PTP mode field reads 1 here. |
| `ePMP-Backup-2598358-*.json` (2026-09-02) | 5.11.1, SM, 18 dBi, scan mask 19 | Good SM field export, model not in the file (18 dBi = 4518 class). No record. |
| `ePMP-Backup-2351207-*.json`, `1604647-*.txt`, `ePMP-Backup-1686194-*.json` | 5.10.x to 5.11.1, SM | Field SM exports, customer-named. History only. |
| `tw32-tw18-PTPa-*.txt`, `tw32-tw18-PTPb-*.txt`, `tw18-tw17-PTPa-*.txt` | PTP pair (4625 / 4616), 5.11.1 | PTP link profiles for the mode workflow. Not SM evidence. |
| `EAGLES_3`, `SHADY_1`, `Sector_60`, `tw01-ap-000`, `Code/*ap01` | AP exports | AP process evidence, tower-specific. |
| `ePMP-Tech-Support-*.zip` (Feb to Mar) | various | Vendor support bundles. Not evidence. |
| `169.254.1.1_Archive [26-08-24].har` | unknown device | Unclassified capture. Summarize before use. |

Firmware on hand: `ePMP-AC-v5.11.1`, `ePMP-AX-v5.11.1`, `ePMP-AC-v5.12.0`.

## Ubiquiti Wave

`ubiquti-login-setup-upgrade-mgmtvlan.har` (record, management VLAN not
proven). Firmware GMC/GMP/MGMP 3.4.4 and 4.1.1. No exports. No no-config or
known-good backup.

## MikroTik

`postnetinstall.rsc` is a bench artifact. The other `.rsc` files are site
router and switch configs, not provisioner evidence.

## Other captures

`tachyon-radiusadd.har`, `tachyon-signal.har` (June), and
`portal.tcs.taranawireless.com.har` (May): process captures with no record.
Summarize with `scripts/summarize_har.py` before use.

## What is missing, per record and step

Steps: NC = no-config backup, UP = upgrade capture, CA = config-apply
capture, KG = known-good backup, SUM = capture summary, FIX = redacted
fixtures, TR = bench transitions recorded. Done = present. Open = to capture.
Runbook: `docs/EVIDENCE_RUNBOOK.md`. Flow: `docs/EVIDENCE_CONTRIBUTING.md`.

| Record | NC | UP | CA | KG | SUM | FIX | TR | Next step |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Cambium ePMP 4518 5.11.1 | done | done (in workflow.har) | done (in workflow.har) | done | done | done | open | Provision the factory unit on the bench after the endpoint fix; diff read-back against the no-config fixture; record `fresh->sm`. |
| Cambium ePMP 4616 5.11.1 | open | open | open | done | open | done (known-good) | open | Reset one 4616 with the laptop capture; export before and after; upload 5.11.1 twice. |
| Cambium ePMP 4625 5.11.1 | open | open | open | done (export on hand) | open | open | open | Create the record from the export; then a laptop capture as for the 4616. |
| Cambium Force 300-25 5.11.1 | open | done | done (reset.har) | done (role witness) | done | done | open | Provision one unit with our baseline and export it (baseline witness); export a factory unit. |
| Cambium ePMP 3K baseline | open | done | done | role witness only | done | done | open | Same as the Force 300-25 row; the 3K template stays unqualified until then. |
| Tachyon TNA-303L-65 1.15.1 | done (exact post-reset export, 2026-09-02) | done | done | done (15:26 hand-built working config; tracked SM template rebuilt from it) | done | done | open | Reset the bench unit, let the provisioner apply the rebuilt baseline with the host `wpa_key` set, export, diff against the fixture. That records `fresh->sm`. |
| Tachyon TNA-303L-65 1.12.4 (pre-migration) | open | n/a | n/a | done (production backup) | n/a | done | n/a | Never import this onto 1.15 (no port/VAP mgmt_vlan_enabled flags, unit loses its management address; Tachyon ticket open). Migration proof: upgrade a 1.12.4 unit on the bench, apply the tracked 1.15 baseline, export, confirm the management VLAN set and 4 profiles. |
| Tachyon TNA-303X 1.15.1 | open | open | open | done (export on hand, 1 profile) | open | open | open | Create the record; capture upgrade and apply on the bench. |
| Tachyon TNA-301 1.15.1 | open | done | done | open (AP capture only) | done | done | open | Export a post-apply backup; AP role stays process evidence. |
| Tachyon TNA-302, TNA-305X, TNA-305A, TNS-100 | open | open | open | open | open | open | open | Out of scope until a unit is on the bench. |
| Ubiquiti Wave Nano | open | done (in workflow.har) | done (VLAN not proven) | open | done | done (structure only) | open | Export before and after; capture the VLAN 12 transition with the reconnect. |
| Tarana G1 | open | open | open | n/a (operator id only) | open | open | open | Capture one operator-id apply and upgrade. |
| MikroTik | n/a | open | open (`.rsc` import) | open | open | open | open | Capture one netinstall and one `.rsc` import run. |
