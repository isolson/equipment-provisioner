# Provisioning North Star

The provisioner prepares a device for the network first. It does not guess
the device's final radio role.

## The invariant

Every supported radio follows this order:

1. Detect and identify the model.
2. Apply the verified standard SM baseline.
3. Apply firmware and verify the device.
4. Elevate the device to AP or PTP only when an operator requests it.

The SM baseline is the safe starting state. AP is an explicit deployment
choice. AP setup requires its own approved profile, such as a tower direction.
PTP setup requires its own link and side selection.

An AP process capture is not an AP default for every model in its firmware
family. For example, the TNA-301 bench capture is AP process evidence. It is
not a canonical template because it contains tower/customer identity. TNA-302
shares the TNA-301-302 family but normally uses an SM upload. TNA-303X can use
either role and requires an explicit choice. TNA-305X, TNA-305A, and TNS-100
are not in the current Tachyon scope.

## Family and role are different

The family selects compatible firmware and schema. The role selects the
upload package. The package is identified by:

```text
model → family → role → profile
```

The model-to-family mapping comes from `VendorSpec`. The model-to-role hint
comes from the handler. An ambiguous model must receive an explicit mode.
The upload API can derive the family and a known role when the model is
provided. It rejects a family that does not match the model.

This packaging helper does not change the provisioning baseline. The normal
provisioning resolver still selects the SM baseline. AP and PTP packages are
selected by the explicit post-provision mode workflow.

## Required model settings

Some models need a network setting in addition to the radio role. Wave Nano
requires management VLAN 12 in the standard deployment. This is a model
requirement, not a technician memory step or an optional site field.

After the bench path is verified, the sanitized Wave Nano baseline must carry
VLAN 12. The workflow must also check the switch port, the host VLAN 12
interface, and the reconnect path before it applies the setting. The workflow
must stop when that path is not ready. Customer, tower, IP, and credential
values remain job-specific.

The supplied Wave Nano HAR does not include the VLAN 12 transition. It remains
process evidence until that transition and the post-change reconnect are
captured and verified.

For Tachyon, the handler does not create `mgmt_vlan_enabled` fields. The
wired port and the wireless backhaul must use one coherent tag set: the wan
zone management block, the wired port flag, and the VAP flag. The 1.15
baseline carries all of them, the contract requires them
(`required_fields`), and the verifier compares them. A 1.12 export has no
port or VAP flag, and 1.15 firmware treats a missing flag as off, so the unit
ends with no management address (Tachyon ticket open, no fixed firmware).
The provisioner therefore never imports a 1.12 export onto 1.15. A 1.12 unit
is upgraded first and then receives the tracked 1.15 baseline. The SM
profile list is fleet policy (the same SSID set on every SM in the fleet);
its shared passphrase is a secret delivered by `apply_secrets`.

## Field ownership

Every configuration field has exactly one owner. A field never belongs to two
groups. A field that no contract names is a device default.

| Owner | Rule |
| --- | --- |
| `fleet_policy` | The SM baseline writes it. Read-back verifies the exact value. |
| `role` | The SM baseline writes it. Read-back verifies the exact value. These fields define the radio role. |
| `secret` | Only the handler secret path writes it, from the host credentials. Never in a template. Never logged. Presence only. |
| `device_default` | Never written. Optionally verified unchanged against the no-config fixture. |
| `mode_action` | Never in the SM baseline. Only the explicit AP or PTP workflow writes it. |

Each handler declares one table (`FIELD_OWNERSHIP`). The shared module
`provisioner/field_ownership.py` lints templates, derives verification, and
contains no vendor name. `scripts/check_templates.py` fails CI on a template
that carries a secret, a device default, a site identity, or an unclassified
field, or that lacks a required role field.

Every value in a template or a handler table must trace to a redacted
known-good fixture under `bench-evidence/` (`values` map). A test compares
them. A value change starts with a new fixture, not a discussion.

## Qualification

A post-provision mode is offered for an exact model and firmware only when a
committed bench manifest records both directions of the transition as
`success` (`sm->ap` and `ap->sm`, or `sm->ptp` and `ptp->sm`). The standard
baseline is qualified when `fresh->sm` is recorded. Unknown model or firmware
proves nothing. The kiosk shows the reason a mode is not offered.

## Change rule

Do not make a model's captured role change the standard provisioning path.
Before changing the baseline, capture and verify a complete model-specific
SM flow. Before enabling AP or PTP, capture the role-specific apply flow,
identity fields, profile selection, and read-back result. Add a regression
test for each confirmed rule.

When a device fails, read the exact model and firmware evidence first. Check
the manifest's `config_role`. Do not reuse an AP capture as an SM baseline or
use an SM capture as an AP profile.
