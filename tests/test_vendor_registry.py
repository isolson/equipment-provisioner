"""Registry contract tests (Story 0 / #70, collapsed by Story 6 / #76).

Before the VendorSpec registry, this file locked ~10 hand-kept copies of
the vendor list against each other. Those copies now all derive from
``provisioner.vendor_registry``, so the contract collapses to:

1. **spec set <-> enum** — the hand-written ``DeviceType`` enum
   (decision #1 of issue #76: never generate it at runtime) and the
   registered specs must cover the same vendors, in the same order.
2. **derived views** — every bound constant (``HANDLER_MAP``,
   ``SOURCE_MAP``, ``MODEL_FIRMWARE_PATTERNS``, IP registry, credential
   and firmware-source defaults, credentials-UI builtins, kiosk
   metadata) equals its registry derivation.
3. **propagation** — adding a vendor spec, removing one, or filtering
   with the ``PROVISIONER_VENDORS`` allowlist reaches every derived
   surface (CLI, API validation, setup rows, detection candidates, UI)
   with no ImportError.

Exact historical *values* are locked separately in
``tests/test_vendor_golden.py`` (the #76 zero-behavior-change proof).

Known, documented exceptions:

- ``DeviceType.UNKNOWN`` — sentinel, not a vendor; no spec.
- ``DeviceType.EVOLUTION_DIGITAL`` — registered with
  ``provisionable=False``: real device type with a kiosk card, but its
  passive cross-port qualification flow is dispatched from the
  ``main.py`` side-door, so it has no ``HANDLER_MAP`` entry.
- ``MockHandler`` — simulation-only (``provision --mock``); stays
  outside the registry by design.
- No ``tarana`` firmware source (``firmware_source_cls=None``): Tarana's
  firmware download endpoint requires authentication, so firmware is
  uploaded manually instead of auto-fetched.
- ``mikrotik`` has no ``config_template_dir`` and no entry in
  ``_template_requirements`` (setup_tools.py): MikroTik is configured
  via netinstall/ZTP ``.rsc`` scripts, not deep-merge config templates.
"""

import ast
import asyncio
import json
import os
import re
import subprocess
import sys
from enum import Enum
from pathlib import Path

import pytest
from fastapi import HTTPException

from provisioner import vendor_registry
from provisioner import vendor_ips
from provisioner.config import (
    DeviceIPsConfig,
    _FIRMWARE_SOURCE_DEFAULTS_ORDER,
    _default_credentials,
    _default_firmware_sources,
)
from provisioner.fingerprint import DeviceType
from provisioner.firmware import FirmwareManager
from provisioner.firmware_checker import FirmwareChecker
from provisioner.firmware_sources.base import BaseFirmwareSource
from provisioner.handler_manager import HandlerManager, provisionable_device_types
from provisioner.handlers.mock import MockHandler
from provisioner.setup_tools import (
    _read_primary_credentials,
    _template_requirements,
)
from provisioner.vendor_registry import VendorSpec
from provisioner.web import api as web_api
from provisioner.web.api import (
    BUILTIN_CREDENTIALS,
    _validate_device_type,
    vendor_ui_metadata,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# The canonical provisionable vendor set: every spec with
# provisionable=True. Every derived view is asserted against this.
CANONICAL = {"cambium", "mikrotik", "tachyon", "tarana", "ubiquiti"}

# Vendors with an auto-fetch firmware source (documented exception:
# tarana has none).
FIRMWARE_SOURCE_VENDORS = CANONICAL - {"tarana"}


def _module_level_vendor_imports(source, vendor_modules):
    """Module-level import statements in ``source`` that reference a
    vendor module, in any style (relative from inside the package,
    relative from the package root, absolute, plain ``import``).

    Only ``tree.body`` (module level) is scanned: function-level lazy
    imports are the documented side-door pattern and cannot crash at
    boot. A dotted path is offending when any segment names a vendor.
    """
    tree = ast.parse(source)
    offending = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if set((node.module or "").split(".")) & vendor_modules:
                offending.append(ast.unparse(node))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if set(alias.name.split(".")) & vendor_modules:
                    offending.append(ast.unparse(node))
    return offending


class TestSpecEnumConsistency:
    """Decision #1 of #76: DeviceType stays hand-written; the registry
    must agree with it exactly (the enum member + the register() call are
    the two hand-edited locations when adding a vendor)."""

    def test_every_non_sentinel_enum_member_has_a_spec(self):
        spec_types = {s.device_type.value for s in vendor_registry.all_specs()}
        enum_types = {dt.value for dt in DeviceType} - {"unknown"}
        assert spec_types == enum_types, (
            "VendorSpec registry and DeviceType enum drifted. Adding a "
            "vendor requires BOTH the enum member (fingerprint.py) and the "
            "register(VendorSpec(...)) call (vendor_registry.py)."
        )
        assert all(
            isinstance(s.device_type, DeviceType)
            for s in vendor_registry.all_specs()
        )

    def test_registration_order_is_enum_declaration_order(self):
        # Documented determinism: the register() block runs in DeviceType
        # declaration order, so every derived view's order is fixed by
        # the enum, not by which consumer imports the registry first.
        assert [s.device_type for s in vendor_registry.all_specs()] == [
            dt for dt in DeviceType if dt is not DeviceType.UNKNOWN
        ]

    def test_provisionable_specs_are_the_canonical_set(self):
        assert {
            s.device_type.value
            for s in vendor_registry.all_specs()
            if s.provisionable
        } == CANONICAL

    def test_evolution_digital_is_a_documented_side_door(self):
        spec = vendor_registry.spec_for("evolution_digital")
        assert spec is not None
        assert spec.provisionable is False
        assert spec.handler_cls is None
        assert DeviceType.EVOLUTION_DIGITAL not in vendor_registry.handler_map()
        # The side-door dispatch must stay in main.py.
        main_src = (REPO_ROOT / "provisioner" / "main.py").read_text()
        assert "_provision_evolution_digital" in main_src

    def test_mock_handler_stays_outside_the_registry(self):
        assert MockHandler not in vendor_registry.handler_map().values()
        from provisioner import handlers as handlers_pkg

        assert "MockHandler" in handlers_pkg.__all__

    def test_duplicate_registration_raises(self):
        with pytest.raises(ValueError, match="already registered"):
            vendor_registry.register(
                VendorSpec(
                    device_type=DeviceType.MIKROTIK,
                    handler_cls=MockHandler,
                )
            )

    def test_provisionable_spec_requires_a_handler(self, monkeypatch):
        monkeypatch.setattr(vendor_registry, "_SPECS", {})
        with pytest.raises(ValueError, match="without handler_cls"):
            vendor_registry.register(
                VendorSpec(device_type=DeviceType.MIKROTIK, handler_cls=None)
            )


class TestDerivedViews:
    """Every bound constant equals its registry derivation, and covers
    the canonical vendor set."""

    def test_handler_map_is_the_registry_derivation(self):
        assert HandlerManager.HANDLER_MAP == vendor_registry.handler_map()
        assert {dt.value for dt in HandlerManager.HANDLER_MAP} == CANONICAL

    def test_source_map_is_the_registry_derivation(self):
        assert FirmwareChecker.SOURCE_MAP == vendor_registry.firmware_source_map()
        assert set(FirmwareChecker.SOURCE_MAP) == FIRMWARE_SOURCE_VENDORS

    def test_model_firmware_patterns_is_the_registry_derivation(self):
        assert (
            FirmwareManager.MODEL_FIRMWARE_PATTERNS
            == vendor_registry.model_firmware_patterns()
        )
        # Vendors contributing patterns today (a new vendor without
        # patterns simply contributes nothing).
        contributing = {
            s.device_type.value
            for s in vendor_registry.specs()
            if s.model_firmware_patterns
        }
        assert contributing == {"cambium", "tachyon", "ubiquiti"}

    def test_vendor_ip_registry_is_the_registry_derivation(self):
        assert set(vendor_ips.VENDOR_LINK_LOCAL_IPS) == CANONICAL, (
            "A vendor missing from the IP registry is undetectable at "
            "link-up and adds ~120s detection delay."
        )
        registry_view = vendor_registry.link_local_ips()
        assert {
            v: list(ips) for v, ips in vendor_ips.VENDOR_LINK_LOCAL_IPS.items()
        } == registry_view

    def test_boot_ping_list_covers_the_same_ips_as_probe_list(self):
        boot_ips = set(vendor_ips.boot_ping_ips())
        probe_ips = {ip for ip, _vendors in vendor_ips.probe_ip_candidates()}
        assert boot_ips == probe_ips

    def test_order_tuples_contain_no_stale_vendors(self):
        # The historical partial-order tuples may lag a vendor ADDITION
        # (new vendors append in registration order) but must never name
        # a vendor that no longer exists.
        registered = {s.device_type.value for s in vendor_registry.all_specs()}
        for tup in (
            vendor_ips._PROBE_VENDOR_ORDER,
            vendor_ips._BOOT_PING_VENDOR_ORDER,
            vendor_ips._DEVICE_IPS_FIELD_ORDER,
            _FIRMWARE_SOURCE_DEFAULTS_ORDER,
        ):
            assert set(tup) <= registered, (
                "Stale vendor in a historical order tuple: {}".format(
                    sorted(set(tup) - registered)
                )
            )

    def test_credentials_defaults_table_matches(self):
        table = _default_credentials()
        assert set(table) == CANONICAL
        assert {
            v: {"username": c.username, "password": c.password}
            for v, c in table.items()
        } == vendor_registry.credential_defaults()

    def test_default_firmware_source_config_matches(self):
        assert set(_default_firmware_sources()) == FIRMWARE_SOURCE_VENDORS
        assert set(_default_firmware_sources()) == set(
            vendor_registry.firmware_source_config_defaults()
        )

    def test_builtin_credentials_is_the_registry_derivation(self):
        assert BUILTIN_CREDENTIALS == vendor_registry.builtin_ui_credentials()
        assert set(BUILTIN_CREDENTIALS) == CANONICAL

    def test_device_ips_config_fields_match(self):
        assert set(DeviceIPsConfig.model_fields) == CANONICAL

    def test_provisionable_device_types_derives_from_handler_map(self):
        assert provisionable_device_types() == sorted(CANONICAL)

    def test_api_device_type_validation_matches(self):
        for vendor in CANONICAL:
            assert _validate_device_type(vendor) == vendor
        for rejected in ("evolution_digital", "unknown", "netgear"):
            with pytest.raises(HTTPException):
                _validate_device_type(rejected)

    def test_setup_readiness_credential_hints_cover_every_vendor(self):
        entries = _read_primary_credentials(object())
        assert {e["device_type"] for e in entries} == CANONICAL

    def test_setup_template_requirements_cover_template_vendors(self):
        assert set(_template_requirements(object())) == CANONICAL - {"mikrotik"}, (
            "mikrotik is the documented exception: configured via "
            "netinstall/ZTP .rsc, not templates."
        )

    def test_declared_template_dirs_exist(self):
        for spec in vendor_registry.all_specs():
            if spec.config_template_dir is not None:
                assert (
                    REPO_ROOT / "configs" / "templates" / spec.config_template_dir
                ).is_dir(), (
                    "{} declares config_template_dir={!r} but the bundled "
                    "directory is missing".format(
                        spec.device_type.value, spec.config_template_dir
                    )
                )

    def test_vendor_ui_metadata_covers_every_vendor(self):
        # index.html injects the server-derived metadata (Story 5 / #75).
        html = (
            REPO_ROOT / "provisioner" / "web" / "templates" / "index.html"
        ).read_text()
        assert re.search(
            r"const\s+deviceVendors\s*=\s*\{\{\s*vendor_metadata\s*\|\s*tojson\s*\}\}",
            html,
        )
        assert set(vendor_ui_metadata()) == CANONICAL | {
            "evolution_digital",
            "unknown",
        }
        assert web_api._VENDOR_UI_STYLE == dict(
            vendor_registry.ui_styles(), unknown={"name": "Unknown", "color": "#6b7280"}
        )

    def test_no_vendor_enumerating_imports_remain(self):
        """The ImportError-on-removal S1 class is gone: no module other
        than vendor_registry imports per-vendor handler/firmware-source
        modules at module level, so deleting a vendor's modules plus its
        spec entry cannot crash the service at boot.

        AST-based (not regex): it must catch every module-level import
        style — `from .mikrotik import X` inside the package __init__s,
        `from .handlers.mikrotik import X` / `from
        provisioner.handlers.mikrotik import X` / `import
        provisioner.handlers.mikrotik` elsewhere — and is
        mutation-proved against each of those below."""
        vendor_modules = {s.device_type.value for s in vendor_registry.all_specs()}

        for rel in (
            "handlers/__init__.py",
            "firmware_sources/__init__.py",
            "firmware_checker.py",
            "handler_manager.py",
        ):
            source = (REPO_ROOT / "provisioner" / rel).read_text()
            offending = _module_level_vendor_imports(source, vendor_modules)
            assert not offending, (
                "provisioner/{} enumerates vendor modules again: {}".format(
                    rel, offending
                )
            )

    def test_vendor_import_guard_catches_every_import_style(self):
        """Mutation-proof the guard above: each style of re-added vendor
        import must be flagged (the reviewer's `from .mikrotik import`
        relative style was regex-blind in an earlier version), and the
        legitimate imports must not be."""
        vendor_modules = {s.device_type.value for s in vendor_registry.all_specs()}

        caught_mutations = [
            # package-__init__ relative style (the reviewer's mutation)
            "from .mikrotik import MikrotikHandler",
            "from .evolution_digital import EvolutionDigitalHandler",
            # package-root relative style (the pre-#76 handler_manager /
            # firmware_checker style)
            "from .handlers.mikrotik import MikrotikHandler",
            "from ..firmware_sources.tachyon import TachyonFirmwareSource",
            # absolute styles
            "from provisioner.handlers.cambium import CambiumHandler",
            "import provisioner.firmware_sources.ubiquiti",
            "import provisioner.handlers.tarana as tarana_handler",
        ]
        for mutation in caught_mutations:
            assert _module_level_vendor_imports(mutation, vendor_modules), (
                "import guard is blind to: {}".format(mutation)
            )

        allowed = [
            # base/mock and non-vendor imports stay legal
            "from .base import BaseHandler, DeviceInfo",
            "from .mock import MockHandler",
            "from .firmware_sources.base import BaseFirmwareSource",
            "from .vendor_registry import handler_map",
            "import logging",
            # function-level (lazy) vendor imports are the documented
            # side-door pattern (main.py) — module-level is what crashes
            # at boot, so only tree.body is scanned.
            "def _side_door():\n    from .handlers.evolution_digital import EvolutionDigitalHandler\n",
        ]
        for source in allowed:
            assert not _module_level_vendor_imports(source, vendor_modules), (
                "import guard false-positive on: {}".format(source)
            )

    def test_main_credentials_assembly_is_table_driven(self):
        # Story 3 (#73): main.py iterates the config.credentials table —
        # a per-vendor attribute access reappearing here would
        # reintroduce the config.py/main.py S1 crash-coupling.
        source = (REPO_ROOT / "provisioner" / "main.py").read_text()
        attr_accesses = set(re.findall(r"self\.config\.credentials\.(\w+)", source))
        assert not (attr_accesses & CANONICAL)


class TestHandlerMapDerivation:
    """The CLI, API validation, and setup tooling derive their vendor
    lists from ``HANDLER_MAP`` (Story 2 / #72), which derives from the
    registry — so a deletion propagates everywhere."""

    def test_cli_builds_a_handler_for_every_vendor(self):
        from provisioner import cli

        for vendor in sorted(CANONICAL):
            handler = asyncio.run(cli.get_handler("192.0.2.1", vendor, "admin", ""))
            assert handler is not None, f"CLI built no handler for {vendor}"
            assert type(handler) is HandlerManager.HANDLER_MAP[DeviceType(vendor)]

    def test_cli_rejects_side_door_and_unknown_types(self):
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


# --- Fake-vendor propagation (acceptance #1 of #76) ------------------------

# A fake device type standing in for the hand-written enum member a real
# vendor addition would add to fingerprint.py (an Enum cannot be extended
# at runtime — that hand edit plus register() is the whole budget).
_FakeDeviceType = Enum("_FakeDeviceType", {"ACME": "acme"}, type=str)


class _AcmeHandler(MockHandler):
    """Fake vendor handler (BaseHandler via MockHandler)."""


class _AcmeFirmwareSource(BaseFirmwareSource):
    async def check_for_updates(self):
        return []


def _acme_spec():
    return VendorSpec(
        device_type=_FakeDeviceType.ACME,
        handler_cls=_AcmeHandler,
        firmware_source_cls=_AcmeFirmwareSource,
        firmware_source_defaults={"enabled": False},
        default_credentials={"username": "acme", "password": "acmepass"},
        link_local_ips=("192.0.2.77",),
        model_firmware_patterns={"acme-x1": ["acme-x"]},
        ui_style={"name": "Acme", "color": "#123456"},
    )


@pytest.fixture
def fake_vendor(monkeypatch):
    """Register the fake vendor and re-bind every import-time view, the
    way a process boot would after a real vendor addition."""
    monkeypatch.setattr(vendor_registry, "_SPECS", dict(vendor_registry._SPECS))
    vendor_registry.register(_acme_spec())

    monkeypatch.setattr(HandlerManager, "HANDLER_MAP", vendor_registry.handler_map())
    monkeypatch.setattr(
        FirmwareChecker, "SOURCE_MAP", vendor_registry.firmware_source_map()
    )
    monkeypatch.setattr(
        FirmwareManager,
        "MODEL_FIRMWARE_PATTERNS",
        vendor_registry.model_firmware_patterns(),
    )
    monkeypatch.setattr(
        vendor_ips, "VENDOR_LINK_LOCAL_IPS", vendor_ips._ordered_vendor_ips()
    )
    monkeypatch.setattr(
        web_api, "BUILTIN_CREDENTIALS", vendor_registry.builtin_ui_credentials()
    )
    monkeypatch.setattr(
        web_api,
        "_VENDOR_UI_STYLE",
        dict(vendor_registry.ui_styles(),
             unknown={"name": "Unknown", "color": "#6b7280"}),
    )


class TestFakeVendorPropagation:
    """Acceptance #1 of #76: one register(VendorSpec(...)) call reaches
    every derived view."""

    def test_fake_vendor_appears_in_every_derived_view(self, fake_vendor):
        # Handler map + everything that derives from it.
        assert "acme" in provisionable_device_types()
        assert HandlerManager.HANDLER_MAP[_FakeDeviceType.ACME] is _AcmeHandler
        assert _validate_device_type("acme") == "acme"

        # CLI choices (parser is built call-time from the derived list).
        from provisioner import cli

        args = cli.build_parser().parse_args(["test", "--device-type", "acme"])
        assert args.device_type == "acme"

        # Firmware: source map, checker config defaults, model patterns.
        assert FirmwareChecker.SOURCE_MAP["acme"] is _AcmeFirmwareSource
        assert _default_firmware_sources()["acme"].enabled is False
        assert FirmwareManager.MODEL_FIRMWARE_PATTERNS["acme-x1"] == ["acme-x"]

        # Credentials: config defaults, setup readiness rows, UI builtins.
        assert _default_credentials()["acme"].username == "acme"
        entries = _read_primary_credentials(object())
        assert "acme" in {e["device_type"] for e in entries}
        assert web_api.BUILTIN_CREDENTIALS["acme"] == [
            {"username": "acme", "password": "acmepass"}
        ]

        # Detection candidates: probe list, boot-ping list, config fields.
        assert ("192.0.2.77", ["acme"]) in vendor_ips.probe_ip_candidates()
        assert "192.0.2.77" in vendor_ips.boot_ping_ips()
        assert "acme" in vendor_ips.device_ips_vendors()
        assert vendor_ips.primary_ip("acme") == "192.0.2.77"

        # Kiosk UI metadata.
        metadata = vendor_ui_metadata()
        assert metadata["acme"] == {
            "name": "Acme",
            "color": "#123456",
            "defaultUser": "acme",
            "icon": "",  # no bundled icon yet — the no-icon path renders
        }

    def test_fake_vendor_probe_position_appends_after_historical_order(
        self, fake_vendor
    ):
        # New vendors join the probe order at the END (the historical
        # partial-order tuples pin existing vendors' positions).
        assert list(vendor_ips.VENDOR_LINK_LOCAL_IPS)[-1] == "acme"


# --- Determinism and the VENDORS allowlist (decisions #3 and #6) -----------


def _spawn_subprocess(code, extra_env=None):
    """Run ``code`` in a fresh interpreter; return the CompletedProcess.
    PROVISIONER_VENDORS is scrubbed unless supplied via extra_env."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env.pop("PROVISIONER_VENDORS", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=120,
    )


def _run_subprocess(code, extra_env=None):
    result = _spawn_subprocess(code, extra_env=extra_env)
    assert result.returncode == 0, (
        "subprocess failed\nstdout: {}\nstderr: {}".format(
            result.stdout, result.stderr
        )
    )
    return result.stdout.strip().splitlines()[-1]


_DUMP_VIEWS = """
import json
from provisioner import vendor_registry as vr
print(json.dumps({
    "order": [s.device_type.value for s in vr.all_specs()],
    "handler_map": {dt.value: cls.__name__ for dt, cls in vr.handler_map().items()},
    "source_map": {v: cls.__name__ for v, cls in vr.firmware_source_map().items()},
    "patterns": vr.model_firmware_patterns(),
    "ips": vr.link_local_ips(),
    "creds": vr.credential_defaults(),
    "fw_defaults": vr.firmware_source_config_defaults(),
    "builtin": vr.builtin_ui_credentials(),
    "ui": vr.ui_styles(),
}))
"""


class TestRegistrationDeterminism:
    def test_views_are_identical_across_import_orders(self):
        """Registration happens inside vendor_registry's own module body
        (explicit ordered register() calls, no filesystem discovery), so
        the derived views cannot depend on which consumer imports the
        registry first."""
        registry_first = "import provisioner.vendor_registry\n" \
            "import provisioner.web.api\n" \
            "import provisioner.firmware_checker\n" + _DUMP_VIEWS
        consumers_first = "import provisioner.web.app\n" \
            "import provisioner.cli\n" \
            "import provisioner.vendor_registry\n" + _DUMP_VIEWS
        assert _run_subprocess(registry_first) == _run_subprocess(consumers_first)

    def test_reimporting_the_registry_is_idempotent(self):
        # A second import is a sys.modules no-op — no duplicate
        # registration, same object.
        out = _run_subprocess(
            "import provisioner.vendor_registry as a\n"
            "import provisioner.vendor_registry as b\n"
            "print(a is b and len(a.all_specs()))\n"
        )
        assert out == str(len(vendor_registry.all_specs()))


_SINGLE_VENDOR_BOOT = """
import json, re

# The SERVICE entry point: importing provisioner.main pulls in
# port_manager (DeviceLinkLocalIP class body) and every other consumer —
# this import crashing under an allowlist is exactly the reviewer-found
# regression this guards against.
import provisioner.main as main_module

from fastapi.testclient import TestClient
from provisioner import cli
from provisioner.config import Config
from provisioner.handler_manager import provisionable_device_types
from provisioner.port_manager import DeviceLinkLocalIP, PortManager
from provisioner.vendor_ips import VENDOR_LINK_LOCAL_IPS, probe_ip_candidates
from provisioner.web.app import create_app


class DummyProvisioner:
    def __init__(self, config):
        self.config = config


config = Config()

# Provisioner + PortManager construction (the sync part of service boot;
# async setup() needs real interfaces/db paths).
provisioner_obj = main_module.Provisioner(config)
port_manager = PortManager(base_interface="eth0", num_ports=2, setup_vlans=False)

client = TestClient(create_app(provisioner=DummyProvisioner(config)))
page = client.get("/")
creds = client.get("/api/default-credentials")
match = re.search(r"const deviceVendors = (\\{.*\\});", page.text)

try:
    cli.build_parser().parse_args(["test", "--device-type", "cambium"])
    cli_rejects_cambium = False
except SystemExit:
    cli_rejects_cambium = True

print(json.dumps({
    "dashboard_status": page.status_code,
    "health": client.get("/health").json(),
    "provisionable": provisionable_device_types(),
    "ip_vendors": list(VENDOR_LINK_LOCAL_IPS),
    "probe": probe_ip_candidates(),
    "ui_vendors": sorted(json.loads(match.group(1))) if match else None,
    "cred_rows": sorted({row["device_type"] for row in creds.json()}),
    "config_credentials": sorted(config.credentials),
    "device_ips_fields": list(type(config.ports.device_ips).model_fields),
    "cli_rejects_cambium": cli_rejects_cambium,
    "cli_accepts_mikrotik": cli.build_parser().parse_args(
        ["test", "--device-type", "mikrotik"]).device_type,
    "port_manager_ports": port_manager.num_ports,
    "boot_ping": DeviceLinkLocalIP.BOOT_PING,
    # Excluded vendors' address constants stay defined (facts about
    # vendor gear, not detection candidates).
    "cambium_const": DeviceLinkLocalIP.CAMBIUM,
    "tachyon_alt_const": DeviceLinkLocalIP.TACHYON_ALT,
    "switch_creds": list(main_module._switch_management_credentials(config)),
}))
"""

# A non-mikrotik subset: exercises the switch-management credential
# fallback (the bench switch is infrastructure — its login must resolve
# even when mikrotik is filtered out of the credentials table).
_NON_MIKROTIK_BOOT = """
import json
import provisioner.main as main_module
from provisioner.config import Config
from provisioner.port_manager import DeviceLinkLocalIP, PortManager

config = Config()
main_module.Provisioner(config)
PortManager(base_interface="eth0", num_ports=2, setup_vlans=False)

print(json.dumps({
    "config_credentials": sorted(config.credentials),
    "switch_creds": list(main_module._switch_management_credentials(config)),
    "mikrotik_const": DeviceLinkLocalIP.MIKROTIK,
    "probe": [[ip, vendors] for ip, vendors in DeviceLinkLocalIP.ALL],
}))
"""


class TestSingleVendorBuild:
    """Decision #6 of #76 (Direction B): a PROVISIONER_VENDORS allowlist
    filters the registry; excluded vendors disappear from detection
    candidates, CLI, API, setup, and UI — and the web app still boots
    with no ImportError."""

    def test_mikrotik_only_build_boots_and_excludes_other_vendors(self):
        out = json.loads(
            _run_subprocess(
                _SINGLE_VENDOR_BOOT,
                extra_env={"PROVISIONER_VENDORS": "mikrotik"},
            )
        )
        assert out["dashboard_status"] == 200
        assert out["health"] == {"status": "healthy"}
        assert out["provisionable"] == ["mikrotik"]
        assert out["ip_vendors"] == ["mikrotik"]
        assert out["probe"] == [["192.168.88.1", ["mikrotik"]]]
        # evolution_digital is allowlist-filtered too; `unknown` is the
        # UI-only fallback card, not a vendor, so it always renders.
        assert out["ui_vendors"] == ["mikrotik", "unknown"]
        assert out["cred_rows"] == ["mikrotik"]
        assert out["config_credentials"] == ["mikrotik"]
        assert out["device_ips_fields"] == ["mikrotik"]
        assert out["cli_rejects_cambium"] is True
        assert out["cli_accepts_mikrotik"] == "mikrotik"
        # The service entry point booted: provisioner.main imported (the
        # port_manager/DeviceLinkLocalIP import path), Provisioner and
        # PortManager constructed.
        assert out["port_manager_ports"] == 1  # setup_vlans=False → 1 port
        assert out["boot_ping"] == ["192.168.88.1"]
        # Excluded vendors' address constants stay defined (unfiltered
        # facts), while detection candidates are filtered.
        assert out["cambium_const"] == "169.254.1.1"
        assert out["tachyon_alt_const"] == "192.168.1.1"
        assert out["switch_creds"] == ["admin", ""]

    def test_non_mikrotik_build_boots_with_switch_credential_fallback(self):
        out = json.loads(
            _run_subprocess(
                _NON_MIKROTIK_BOOT,
                extra_env={"PROVISIONER_VENDORS": "cambium"},
            )
        )
        assert out["config_credentials"] == ["cambium"]
        # The bench switch is infrastructure: its login resolves to the
        # MikroTik factory default even with mikrotik filtered out.
        assert out["switch_creds"] == ["admin", ""]
        assert out["mikrotik_const"] == "192.168.88.1"
        assert out["probe"] == [["169.254.1.1", ["cambium"]]]

    def test_unset_and_blank_allowlists_yield_the_full_vendor_set(self):
        dump = (
            "import json\n"
            "from provisioner.handler_manager import provisionable_device_types\n"
            "from provisioner import vendor_registry as vr\n"
            "print(json.dumps({'pdt': provisionable_device_types(),"
            " 'vendors': vr.VENDORS is None}))\n"
        )
        for env in (None, {"PROVISIONER_VENDORS": ""}, {"PROVISIONER_VENDORS": "  "}):
            out = json.loads(_run_subprocess(dump, extra_env=env))
            assert out["pdt"] == sorted(CANONICAL)
            assert out["vendors"] is True

    def test_typo_in_allowlist_fails_fast_naming_the_bad_entry(self):
        result = _spawn_subprocess(
            "import provisioner.vendor_registry",
            extra_env={"PROVISIONER_VENDORS": "mikrotik,netgear"},
        )
        assert result.returncode != 0
        assert "netgear" in result.stderr
        # The error names the valid set so the fix is obvious.
        for vendor in sorted(CANONICAL):
            assert vendor in result.stderr

    def test_separators_only_allowlist_fails_fast(self):
        for value in (",", " , ,, "):
            result = _spawn_subprocess(
                "import provisioner.vendor_registry",
                extra_env={"PROVISIONER_VENDORS": value},
            )
            assert result.returncode != 0, (
                "PROVISIONER_VENDORS={!r} must be an error, not a "
                "zero-vendor kiosk".format(value)
            )
            assert "selects no vendors" in result.stderr

    def test_active_allowlist_is_logged_at_info(self):
        result = _spawn_subprocess(
            "import logging\n"
            "logging.basicConfig(level=logging.INFO)\n"
            "import provisioner.vendor_registry\n",
            extra_env={"PROVISIONER_VENDORS": "mikrotik,tarana"},
        )
        assert result.returncode == 0, result.stderr
        assert "PROVISIONER_VENDORS active" in result.stderr
        assert "mikrotik" in result.stderr and "tarana" in result.stderr
