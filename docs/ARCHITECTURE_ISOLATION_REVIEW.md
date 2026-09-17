# Vendor isolation: current architecture

Reconciled 2026-09-10 against the vendor registry, its consumers, regression
suite, and the provisioner bench deployment. This replaces the earlier audit
of approximately ten independent vendor lists; that audit described the
pre-registry implementation and remains in Git history.

## What is isolated

`provisioner/vendor_registry.py` contains one `VendorSpec` registration per
vendor. `DeviceType` remains an explicit enum in `fingerprint.py`; a consistency
test requires enum members and specs to agree. These are the two shared
registration edits for a new vendor, in addition to its implementation/assets
and any required detection support.

| Consumer | Source |
| --- | --- |
| Handler dispatch | `handler_map()` → `HANDLER_MAP` |
| Firmware fetchers | `firmware_source_map()` → `SOURCE_MAP` |
| Model-to-firmware matching | `model_firmware_patterns()` |
| Device addresses and boot probes | `link_local_ips()` → `vendor_ips.py` |
| Credential and firmware defaults | `credential_defaults()`, `firmware_source_config_defaults()` |
| API credentials and UI metadata | `builtin_ui_credentials()`, `ui_styles()` |
| CLI/API/setup device lists | `provisionable_device_types()` → handler map |
| Model families and PTP compatibility | `ConfigFamilySpec` and registry lookup helpers |

`handlers/__init__.py` and `firmware_sources/__init__.py` do not maintain
vendor imports. Tests cover stale imports, import order, fake-vendor addition,
registration removal, and restricted-vendor boot. `PROVISIONER_VENDORS` selects
active specs; it is not a security boundary or proof of hardware support.

The shared `BaseHandler.provision()` flow uses handler properties. It contains
no vendor brand strings. Vendor handlers do not import sibling vendor handlers.
Firmware transport, configuration payloads, credentials and model differences
belong in the relevant handler. `FIELD_OWNERSHIP` defines what a template can
write and what readback must verify; it does not itself prove that every
required deployment setting has been declared.

## What still needs care

- Detection signatures, probes and model extraction remain in `fingerprint.py`.
  Preserve probe order and confidence weights. Registry consolidation did not
  make detection changes automatically safe.
- Evolution Digital intentionally bypasses ordinary handler dispatch for its
  passive cross-port workflow. MikroTik netinstall/BOOTP and OUI gates are
  intentional hardware-specific paths. Preserve these exceptions.
- Shared engine, credential schema, UI and deployment changes can affect every
  vendor. Forward credential models as a whole internally; do not add another
  hand-maintained field list that silently drops a new secret.
- Family templates are shared assets. A directory named after a model is not
  enough to make the resolver select it. Use the registered family and test the
  actual `ConfigStore` resolution. Model-specific policy belongs in the handler
  when members of one family need different values.
- Hardware/API behavior still needs real-device evidence. A passing unit test
  cannot prove AP association, management VLAN DHCP, traffic or power-cycle
  persistence. Qualification is scoped to model, firmware, role and transition.

The bench exposed both remaining risks: TNA-302 resolves through `TNA-301-302`,
and Cambium 4518/46xx share `ePMP-4K` while requiring different scan masks.
See the dated [reconciliation record](RECONCILIATION_2026-09-10.md) and
[Cambium validation](cambium-validation-2026-09-10.md).

## Required regression coverage

`tests/test_vendor_registry.py` checks registration consistency and add/remove
behavior. `tests/test_vendor_golden.py` locks the derived values and probe
ordering. Handler property, provision-flow, fingerprint and field-ownership
tests protect behavior. Run the complete suite plus the documentation,
Python 3.9, template and committed-evidence gates before promotion.

For a model-family change, cover both the changed model and an existing sibling
with different capabilities. For a credential change, test the path from config
through setup/manager construction to the handler, not just direct handler
construction. Preserve factory-reset evidence separately from recovery runs.

This architecture reduces the chance that adding hardware breaks existing
hardware. It does not justify a guarantee of no regressions.
