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
- ``cli.py`` (inline handler dict and ``choices=[...]``) lacks
  ``ubiquiti`` — pre-existing gap, audit map site #4 ("duplicate of #2").
  Story 2 (#72) derives the CLI list from ``HANDLER_MAP``; remove
  ``CLI_VENDORS`` when it lands.
- No ``tarana`` firmware source exists (``SOURCE_MAP``,
  ``firmware_sources``, config defaults): Tarana's firmware download
  endpoint requires authentication, so firmware is uploaded manually
  instead of auto-fetched.
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
from provisioner.setup_tools import SUPPORTED_DEVICE_TYPES
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

# cli.py predates Ubiquiti support and hardcodes its own handler list
# (documented exception, fixed by Story 2 / #72).
CLI_VENDORS = CANONICAL - {"ubiquiti"}


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
        assert set(CredentialsConfig.model_fields) == CANONICAL, (
            "CredentialsConfig (config.py) out of sync — this is one half of "
            "the config.py/main.py S1 crash-coupling (Story 3 / #73)."
        )

    def test_device_ips_config_fields_match(self):
        assert set(DeviceIPsConfig.model_fields) == CANONICAL, (
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

    def test_cli_handler_dict_matches(self):
        source = (REPO_ROOT / "provisioner" / "cli.py").read_text()
        match = re.search(r"handlers\s*=\s*\{([^}]*)\}", source)
        assert match, (
            "cli.py: couldn't find the inline `handlers = {...}` dict in "
            "get_handler() — if it moved or was derived from HANDLER_MAP "
            "(Story 2 / #72), update this test."
        )
        keys = set(re.findall(r'"(\w+)"\s*:', match.group(1)))
        assert keys == CLI_VENDORS, (
            "cli.py handler dict drifted (expected the documented "
            "missing-ubiquiti state until Story 2 / #72 lands)."
        )

    def test_cli_choices_matches(self):
        source = (REPO_ROOT / "provisioner" / "cli.py").read_text()
        match = re.search(r"choices=\[([^\]]*)\]", source)
        assert match, "cli.py: couldn't find the device-type choices=[...] list."
        keys = set(re.findall(r'"(\w+)"', match.group(1)))
        assert keys == CLI_VENDORS, (
            "cli.py choices=[...] drifted (expected the documented "
            "missing-ubiquiti state until Story 2 / #72 lands)."
        )

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
