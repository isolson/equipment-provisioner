"""Registry-consistency contract test (vendor-isolation epic, Story 0 / #70).

The vendor list is currently duplicated across ~10 registries (see
docs/ARCHITECTURE_ISOLATION_REVIEW.md for the touchpoint map). Until they
are consolidated into a single VendorSpec registry
(docs/epic-vendor-isolation-refactor.md), this test locks the *current
effective* vendor set in every copy, so drift — adding, removing, or
renaming a vendor in one place but not another — fails CI instead of
crashing the service at boot (S1 sites) or silently breaking detection and
the setup UI (S2 sites).

When a refactor story consolidates a registry, update the matching test
here. That is expected and is the point of the contract.

Known, documented exceptions:

- ``DeviceType.UNKNOWN`` — sentinel, not a vendor.
- ``DeviceType.EVOLUTION_DIGITAL`` — intentionally absent from
  ``HANDLER_MAP``; its passive cross-port qualification flow is dispatched
  directly from ``main.py``.
- ``MockHandler`` — simulation-only (``provision --mock``); exported from
  the handlers package but absent from every vendor registry.
- ``cli.py`` used to lack ``ubiquiti`` (pre-existing gap, audit map site
  #4). **Resolved by Story 2 (#72)** — the CLI now derives from
  ``HANDLER_MAP`` via ``HandlerManager.provisionable_device_types()``, so
  the gap closed and the ``CLI_VENDORS`` exception is gone.
- No ``tarana`` firmware source exists (``SOURCE_MAP``,
  ``firmware_sources``, config defaults): Tarana's firmware download
  endpoint requires authentication, so firmware is uploaded manually
  instead of auto-fetched.
- ``mikrotik`` has no entry in ``_template_requirements`` (setup_tools.py):
  MikroTik is configured via netinstall/ZTP ``.rsc`` scripts, not
  deep-merge config templates, so it has no template readiness check.
"""

import re
from pathlib import Path

from provisioner import firmware_sources
from provisioner import handlers as handlers_pkg
from provisioner.config import (
    CredentialsConfig,
    DeviceIPsConfig,
    _default_firmware_sources,
)
from provisioner.fingerprint import DeviceType
from provisioner.firmware_checker import FirmwareChecker
from provisioner.handler_manager import HandlerManager
from provisioner.port_manager import DeviceLinkLocalIP
from provisioner.setup_tools import (
    SUPPORTED_DEVICE_TYPES,
    _read_primary_credentials,
    _template_requirements,
)
from provisioner.web.api import BUILTIN_CREDENTIALS, VALID_DEVICE_TYPES

REPO_ROOT = Path(__file__).resolve().parent.parent

# The canonical provisionable vendor set: DeviceType minus the documented
# sentinels. Every other registry is asserted against this.
CANONICAL = {"cambium", "mikrotik", "tachyon", "tarana", "ubiquiti"}

# Vendors with an auto-fetch firmware source. Documented exception: Tarana's
# download endpoint requires authentication, so its firmware is uploaded
# manually and no source class exists. A newly added vendor without an
# auto-fetch source joins this exception the same way.
FIRMWARE_SOURCE_VENDORS = CANONICAL - {"tarana"}



class TestPythonRegistries:
    """Registries that are importable constants."""

    def test_device_type_defines_the_canonical_set(self):
        actual = {dt.value for dt in DeviceType} - {"unknown", "evolution_digital"}
        assert actual == CANONICAL, (
            "DeviceType (fingerprint.py) drifted from the canonical vendor set. "
            "If a vendor was legitimately added/removed, update CANONICAL here "
            "and every registry this file checks."
        )

    def test_handler_map_covers_every_vendor(self):
        actual = {dt.value for dt in HandlerManager.HANDLER_MAP}
        assert actual == CANONICAL, (
            "HANDLER_MAP (handler_manager.py) out of sync with DeviceType — "
            "missing entries make devices unprovisionable."
        )

    def test_handlers_package_exports_one_handler_per_vendor(self):
        expected = {vendor.capitalize() + "Handler" for vendor in CANONICAL}
        missing = expected - set(handlers_pkg.__all__)
        assert not missing, (
            "handlers/__init__.py __all__ is missing {} — an S1 site: a missing "
            "import crashes the service at boot.".format(sorted(missing))
        )

    def test_provisionable_device_types_is_the_derived_source(self):
        # Story 2 (#72): the one helper cli.py, VALID_DEVICE_TYPES and
        # setup_tools.SUPPORTED_DEVICE_TYPES all derive from.
        assert set(HandlerManager.provisionable_device_types()) == CANONICAL
        assert HandlerManager.provisionable_device_types() == tuple(
            sorted(CANONICAL)
        ), "callers rely on a stable sorted order for UI listing"

    def test_cli_resolves_a_handler_for_every_vendor(self):
        # Includes ubiquiti, which cli.py's inline dict used to omit.
        for vendor in CANONICAL:
            assert HandlerManager.handler_class_for(vendor) is not None, (
                f"cli.py can no longer resolve a handler for {vendor}"
            )

    def test_valid_device_types_matches(self):
        assert VALID_DEVICE_TYPES == CANONICAL, (
            "VALID_DEVICE_TYPES (web/api.py) out of sync — API rejects valid "
            "vendors or accepts unknown ones."
        )

    def test_builtin_credentials_cover_every_vendor(self):
        assert set(BUILTIN_CREDENTIALS) == CANONICAL, (
            "BUILTIN_CREDENTIALS (web/api.py) out of sync — credentials UI "
            "shows dead or missing vendor entries."
        )

    def test_credentials_config_fields_match(self):
        # Story 3 (#73) consolidated this: CredentialsConfig is now a single
        # `vendors` dict fed by config._default_credentials(), so the check
        # moved from model fields to the table's keys. main.py derives its
        # assembly from the same table, so the S1 crash-coupling is gone.
        assert set(CredentialsConfig().vendors) == CANONICAL, (
            "config._default_credentials() out of sync with the vendor set."
        )

    def test_device_ips_config_fields_match(self):
        # Story 4 (#74) consolidated this: DeviceIPsConfig now derives its
        # per-vendor defaults from DeviceLinkLocalIP.ALL, so the check moved
        # from model fields to the derived table's keys.
        assert set(DeviceIPsConfig().vendors) == CANONICAL, (
            "DeviceIPsConfig (config.py) out of sync with the vendor set."
        )

    def test_link_local_probe_list_covers_every_vendor(self):
        probed = set()
        for _ip, vendors in DeviceLinkLocalIP.ALL:
            probed.update(vendors)
        assert probed == CANONICAL, (
            "DeviceLinkLocalIP.ALL (port_manager.py) out of sync — a vendor "
            "missing from the boot-ping list adds ~120s detection delay."
        )

    def test_setup_tools_supported_device_types_match(self):
        assert set(SUPPORTED_DEVICE_TYPES) == CANONICAL, (
            "SUPPORTED_DEVICE_TYPES (setup_tools.py) out of sync — the "
            "first-run setup UI shows dead or missing vendor entries."
        )

    def test_setup_readiness_credential_hints_cover_every_vendor(self):
        # _read_primary_credentials iterates SUPPORTED_DEVICE_TYPES and
        # indexes its inline `defaults` dict — a vendor missing there makes
        # /setup/readiness raise KeyError. The getattr chains all have
        # defaults, so a bare object() exercises exactly that lookup.
        entries = _read_primary_credentials(object())
        assert {e["device_type"] for e in entries} == CANONICAL, (
            "_read_primary_credentials defaults (setup_tools.py) out of sync "
            "with SUPPORTED_DEVICE_TYPES."
        )

    def test_setup_template_requirements_cover_template_vendors(self):
        assert set(_template_requirements(object())) == CANONICAL - {"mikrotik"}, (
            "_template_requirements (setup_tools.py) out of sync — a missing "
            "vendor silently gets no template readiness check (mikrotik is "
            "the documented exception: configured via netinstall/ZTP .rsc, "
            "not templates)."
        )

    def test_firmware_source_map_matches(self):
        assert set(FirmwareChecker.SOURCE_MAP) == FIRMWARE_SOURCE_VENDORS, (
            "SOURCE_MAP (firmware_checker.py) out of sync — an S1 site when "
            "paired with a missing/removed firmware_sources module."
        )

    def test_firmware_sources_package_exports_match_source_map(self):
        expected = {v.capitalize() + "FirmwareSource" for v in FIRMWARE_SOURCE_VENDORS}
        assert {cls.__name__ for cls in FirmwareChecker.SOURCE_MAP.values()} == expected
        missing = expected - set(firmware_sources.__all__)
        assert not missing, (
            "firmware_sources/__init__.py __all__ is missing {} — an S1 site: "
            "a missing import crashes the service at boot.".format(sorted(missing))
        )

    def test_default_firmware_source_config_matches(self):
        assert set(_default_firmware_sources()) == FIRMWARE_SOURCE_VENDORS, (
            "_default_firmware_sources (config.py) out of sync with SOURCE_MAP."
        )


class TestSourceParsedRegistries:
    """Registries that only exist as literals inside function bodies or
    templates — parsed from source, since they can't be imported."""

    def test_cli_keeps_no_vendor_list_of_its_own(self):
        # Story 2 (#72) removed cli.py's inline handler dict and hardcoded
        # choices=[...]; both now derive from HANDLER_MAP, which also fixed
        # the long-standing missing-ubiquiti gap.
        source = (REPO_ROOT / "provisioner" / "cli.py").read_text()
        assert not re.search(r"handlers\s*=\s*\{", source), (
            "cli.py re-introduced an inline handler dict; derive from "
            "HandlerManager.handler_class_for() instead."
        )
        for vendor in CANONICAL:
            assert not re.search(rf'"{vendor}"\s*:\s*\w+Handler', source), (
                f"cli.py re-introduced a hardcoded handler entry for {vendor}."
            )

    def test_main_no_longer_enumerates_credential_vendors(self):
        # Story 3 (#73) killed the S1 crash-coupling: main.py used to
        # hand-build the HandlerManager dict from five
        # `config.credentials.<vendor>` accesses, so a vendor present there
        # but absent from CredentialsConfig was an AttributeError at boot.
        # It now derives from config.credentials.vendors. The only
        # remaining per-vendor access is the MikroTik management switch,
        # which is a specific device, not the vendor table.
        source = (REPO_ROOT / "provisioner" / "main.py").read_text()
        attribute_access = set(re.findall(r"self\.config\.credentials\.(\w+)", source))
        assert attribute_access <= {"vendors", "for_vendor"}, (
            "main.py re-introduced per-vendor credential attribute access; "
            "derive from config.credentials.vendors instead."
        )

    def test_port_manager_keeps_no_hand_maintained_ip_list(self):
        # Story 4 (#74) removed the inline boot-ping `ips_to_try = [...]`
        # copy; both the boot-wait ping and detection now call
        # DeviceLinkLocalIP.probe_ips(). An IP present in ALL but missing
        # from a parallel list used to cost ~120s of boot detection delay.
        source = (REPO_ROOT / "provisioner" / "port_manager.py").read_text()
        assert not re.search(r"ips_to_try\s*=\s*\[\s*\n\s*DeviceLinkLocalIP\.", source), (
            "port_manager.py re-introduced a hand-maintained boot-ping IP "
            "list; call DeviceLinkLocalIP.probe_ips() instead."
        )
        assert source.count("DeviceLinkLocalIP.probe_ips()") >= 2, (
            "both the boot-ping and detection paths should derive from "
            "the registry"
        )

    def test_probe_ips_matches_the_registry_in_order(self):
        assert DeviceLinkLocalIP.probe_ips() == [
            ip for ip, _vendors in DeviceLinkLocalIP.ALL
        ], "probe order is behavioral — first responder wins"

    def test_every_vendor_has_a_primary_ip(self):
        assert set(DeviceLinkLocalIP.primary_ip_by_vendor()) == CANONICAL

    def test_index_html_vendor_map_matches(self):
        html = (
            REPO_ROOT / "provisioner" / "web" / "templates" / "index.html"
        ).read_text()
        match = re.search(
            r"const\s+deviceVendors\s*=\s*\{(.*?)\n\s*\};", html, re.DOTALL
        )
        assert match, (
            "index.html: couldn't find `const deviceVendors = {...}` — if the "
            "frontend now derives vendors from the API (Story 5 / #75), update "
            "this test."
        )
        keys = set(re.findall(r"^\s*(\w+):\s*\{", match.group(1), re.MULTILINE))
        assert keys == CANONICAL | {"evolution_digital", "unknown"}, (
            "index.html deviceVendors map out of sync — vendor cards render "
            "without names/colors/icons."
        )
