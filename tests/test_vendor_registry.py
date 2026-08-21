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
- No ``tarana`` firmware source exists (``SOURCE_MAP``,
  ``firmware_sources``, config defaults): Tarana's firmware download
  endpoint requires authentication, so firmware is uploaded manually
  instead of auto-fetched.
- ``mikrotik`` has no entry in ``_template_requirements`` (setup_tools.py):
  MikroTik is configured via netinstall/ZTP ``.rsc`` scripts, not
  deep-merge config templates, so it has no template readiness check.
"""

import asyncio
import re
from pathlib import Path

import pytest
from fastapi import HTTPException

from provisioner import firmware_sources
from provisioner import handlers as handlers_pkg
from provisioner.config import (
    CredentialsConfig,
    DeviceIPsConfig,
    _default_firmware_sources,
)
from provisioner.fingerprint import DeviceType
from provisioner.firmware_checker import FirmwareChecker
from provisioner.handler_manager import HandlerManager, provisionable_device_types
from provisioner.port_manager import DeviceLinkLocalIP
from provisioner.vendor_ips import VENDOR_LINK_LOCAL_IPS
from provisioner.setup_tools import (
    _read_primary_credentials,
    _template_requirements,
)
from provisioner.web.api import BUILTIN_CREDENTIALS, _validate_device_type

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

    def test_api_device_type_validation_matches(self):
        # web/api.py no longer keeps its own VALID_DEVICE_TYPES copy — it
        # validates against provisionable_device_types() (Story 2 / #72).
        for vendor in CANONICAL:
            assert _validate_device_type(vendor) == vendor, (
                "web/api.py device-type validation rejects a valid vendor."
            )
        for rejected in ("evolution_digital", "unknown", "netgear"):
            with pytest.raises(HTTPException):
                _validate_device_type(rejected)

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

    def test_vendor_ip_registry_covers_every_vendor(self):
        # Story 4 / #74: the single vendor-IP registry that
        # DeviceLinkLocalIP, the boot-ping list, and DeviceIPsConfig
        # defaults derive from.
        assert set(VENDOR_LINK_LOCAL_IPS) == CANONICAL, (
            "VENDOR_LINK_LOCAL_IPS (vendor_ips.py) out of sync — a vendor "
            "missing from the IP registry is undetectable at link-up and "
            "adds ~120s detection delay."
        )

    def test_link_local_probe_list_covers_every_vendor(self):
        probed = set()
        for _ip, vendors in DeviceLinkLocalIP.ALL:
            probed.update(vendors)
        assert probed == CANONICAL, (
            "DeviceLinkLocalIP.ALL (port_manager.py) out of sync — a vendor "
            "missing from the boot-ping list adds ~120s detection delay."
        )

    def test_provisionable_device_types_derives_from_handler_map(self):
        # The Story 2 (#72) derivation helper behind the CLI, API
        # validation, and setup tooling. Sorted, because the order is
        # user-visible (setup-UI row order, argparse choices display).
        assert provisionable_device_types() == sorted(CANONICAL), (
            "provisionable_device_types (handler_manager.py) drifted from "
            "the canonical vendor set."
        )

    def test_setup_readiness_credential_hints_cover_every_vendor(self):
        # _read_primary_credentials iterates the derived vendor list and
        # reads its hand-keyed `defaults` hint dict with .get() (the dict
        # consolidates in Stories 3/6). The getattr chains all have
        # defaults, so a bare object() exercises exactly that iteration.
        entries = _read_primary_credentials(object())
        assert {e["device_type"] for e in entries} == CANONICAL, (
            "_read_primary_credentials (setup_tools.py) out of sync with "
            "the derived vendor list."
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

    def test_main_credentials_assembly_matches(self):
        # main.py hand-builds the HandlerManager credentials dict from
        # config.credentials.<vendor> attribute accesses — the other half of
        # the config.py/main.py S1 crash-coupling (Story 3 / #73): a vendor
        # present here but absent from CredentialsConfig is an
        # AttributeError at boot.
        source = (REPO_ROOT / "provisioner" / "main.py").read_text()
        vendors = set(re.findall(r"self\.config\.credentials\.(\w+)", source))
        assert vendors == CANONICAL, (
            "main.py credential assembly out of sync with CredentialsConfig."
        )

    def test_boot_ping_list_covers_the_same_ips_as_probe_list(self):
        # Story 4 / #74 removed the inline boot-ping ips_to_try literal:
        # both lists now derive from vendor_ips.VENDOR_LINK_LOCAL_IPS. This
        # asserts the two derived views stay in agreement (an IP present in
        # ALL but missing from BOOT_PING delays boot detection).
        boot_ips = set(DeviceLinkLocalIP.BOOT_PING)
        probe_ips = {ip for ip, _vendors in DeviceLinkLocalIP.ALL}
        assert boot_ips == probe_ips, (
            "DeviceLinkLocalIP.BOOT_PING covers different IPs than "
            "DeviceLinkLocalIP.ALL — the vendor_ips.py derivations drifted."
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


class TestHandlerMapDerivation:
    """Story 2 (#72): the CLI, API validation, and setup tooling derive
    their vendor lists from ``HANDLER_MAP`` instead of keeping copies."""

    def test_cli_builds_a_handler_for_every_vendor(self):
        # The CLI resolves handlers through HandlerManager.handler_class_for,
        # so every HANDLER_MAP vendor is constructible via the CLI path —
        # including ubiquiti, which the old hardcoded dict was missing.
        from provisioner import cli

        for vendor in sorted(CANONICAL):
            handler = asyncio.run(cli.get_handler("192.0.2.1", vendor, "admin", ""))
            assert handler is not None, f"CLI built no handler for {vendor}"
            assert type(handler) is HandlerManager.HANDLER_MAP[DeviceType(vendor)]

    def test_cli_rejects_side_door_and_unknown_types(self):
        # Evolution Digital is a DeviceType but intentionally has no handler
        # (main.py side-door dispatch); unknown strings fail the same way.
        from provisioner import cli

        for rejected in ("evolution_digital", "netgear"):
            assert asyncio.run(
                cli.get_handler("192.0.2.1", rejected, "admin", "")
            ) is None

    def test_cli_choices_cover_every_vendor(self):
        from provisioner import cli

        args = cli.build_parser().parse_args(["test", "--device-type", "ubiquiti"])
        assert args.device_type == "ubiquiti"

    def test_handler_map_deletion_propagates_everywhere(self, monkeypatch):
        from provisioner import cli

        trimmed = {
            device_type: handler_class
            for device_type, handler_class in HandlerManager.HANDLER_MAP.items()
            if device_type is not DeviceType.TARANA
        }
        monkeypatch.setattr(HandlerManager, "HANDLER_MAP", trimmed)

        assert "tarana" not in provisionable_device_types()

        # CLI: handler lookup and argparse choices both drop the vendor.
        assert asyncio.run(cli.get_handler("192.0.2.1", "tarana", "admin", "")) is None
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["test", "--device-type", "tarana"])

        # API: device-type validation rejects it.
        with pytest.raises(HTTPException):
            _validate_device_type("tarana")

        # Setup tooling: readiness rows drop it.
        entries = _read_primary_credentials(object())
        assert {e["device_type"] for e in entries} == CANONICAL - {"tarana"}
