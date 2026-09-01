"""The single vendor registry: one ``VendorSpec`` per vendor (Story 6 / #76).

Every place that used to keep its own copy of "the vendor list" now
derives from the specs registered here:

- ``HandlerManager.HANDLER_MAP`` <- :func:`handler_map`
- ``FirmwareChecker.SOURCE_MAP`` (and the old ``firmware_sources``
  import block) <- :func:`firmware_source_map`
- ``FirmwareManager.MODEL_FIRMWARE_PATTERNS`` <- :func:`model_firmware_patterns`
- ``vendor_ips.VENDOR_LINK_LOCAL_IPS`` <- :func:`link_local_ips`
  (and through it the probe list, boot-ping list, and ``DeviceIPsConfig``)
- ``config._default_credentials`` <- :func:`credential_defaults`
- ``config._default_firmware_sources`` <- :func:`firmware_source_config_defaults`
- ``web.api.BUILTIN_CREDENTIALS`` <- :func:`builtin_ui_credentials`
- ``web.api._VENDOR_UI_STYLE`` / ``vendor_ui_metadata`` <- :func:`ui_styles`
  and :func:`nonprovisionable_device_types`
- the CLI / API validation / setup device-type lists, via
  ``handler_manager.provisionable_device_types()`` (which reads
  ``HANDLER_MAP``, which derives from here)

Adding a vendor is now: ``handlers/x.py`` + ``firmware_sources/x.py`` (if
it has an auto-fetch source) + templates + a ``DeviceType`` enum member +
one ``register(VendorSpec(...))`` call below. Removing one is the
reverse for everything *enumerated*: nothing else imports the vendor's
modules (so deletion cannot leave a crashing stale import behind), and
the derived views — including the generated per-vendor
``DeviceLinkLocalIP`` address constants — drop the vendor automatically.
Vendor-specific *behavior* remains a documented exception: MikroTik's
netinstall/BOOTP paths in ``port_manager.py`` and the Evolution Digital
side-door in ``main.py`` reference their vendors by name and would need
code removal too.

Design decisions (issue #76; keep these invariants):

- **``DeviceType`` stays a hand-written enum** (``fingerprint.py``). It
  is a ``str`` Enum used in pydantic models everywhere; generating it at
  runtime would break IDE/type tooling and risk equality/pickling
  subtleties. ``tests/test_vendor_registry.py`` asserts spec <-> enum
  consistency instead. The enum member plus the ``register()`` call are
  the two hand-edited shared locations.
- **Registration is explicit and ordered** — the ``register()`` block at
  the bottom of this module, in ``DeviceType`` declaration order. No
  filesystem discovery, no import side-effect ordering: the registry's
  state is fixed by this module's own top-to-bottom execution, so it is
  identical no matter which consumer imports it first.
- **Import position.** This module imports each vendor's handler and
  firmware-source classes, so it sits import-graph-downstream of them.
  Nothing imported by ``fingerprint.py`` may import this module
  (``fingerprint.py`` imports nothing package-internal, so everything it
  defines — ``DeviceType`` — is safely importable here). The handler and
  firmware-source modules themselves import only leaf modules
  (``handlers.base``, ``firmware_sources.base``, ``config_merge``,
  ``config_templates``); in particular they must never import
  ``config.py``, ``vendor_ips.py``, or this module at module level.
- **Specs hold enumeration data, not behavior.** Class-level handler
  traits (``allows_prefixed_config_exports``, handler-internal
  ``DEFAULT_CREDENTIALS`` retry lists, the handler-local
  ``MODEL_FIRMWARE_PATTERNS`` *validation* dicts...) stay on the handler
  classes; the spec points at the class and does not duplicate them.
- **Documented exceptions.** Evolution Digital registers with
  ``provisionable=False``: it is a real ``DeviceType`` with a UI card,
  but its passive cross-port qualification flow is dispatched from the
  ``main.py`` side-door, so it has no entry in ``handler_map()``.
  ``MockHandler`` is simulation-only and stays outside the registry.
  Tarana has no firmware-source class (its download endpoint requires
  authentication; firmware is uploaded manually).

Single-vendor builds (Direction B): set the ``PROVISIONER_VENDORS``
environment variable to a comma-separated allowlist (e.g.
``PROVISIONER_VENDORS=mikrotik``) before the service starts. Specs stay
registered (spec <-> enum consistency is checked against the full set),
but every derived view — detection probe list, handler map, CLI/API/setup
lists, UI metadata — only sees the allowlisted vendors. An unknown
vendor name or an allowlist that selects nothing fails fast at import
with an error naming the valid set (``_validate_vendor_allowlist``);
when the knob is active, the effective filter is logged at INFO.
"""

import logging
import os
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Dict, FrozenSet, List, Optional, Tuple, Type

from .fingerprint import DeviceType
from .firmware_sources.base import BaseFirmwareSource
from .firmware_sources.cambium import CambiumFirmwareSource
from .firmware_sources.mikrotik import MikrotikFirmwareSource
from .firmware_sources.tachyon import TachyonFirmwareSource
from .firmware_sources.ubiquiti import UbiquitiFirmwareSource
from .handlers.base import BaseHandler
from .handlers.cambium import CambiumHandler
from .handlers.mikrotik import MikrotikHandler
from .handlers.tachyon import TachyonHandler
from .handlers.tarana import TaranaHandler
from .handlers.ubiquiti import UbiquitiHandler

logger = logging.getLogger(__name__)


def _parse_vendors_env() -> Optional[FrozenSet[str]]:
    """Parse the ``PROVISIONER_VENDORS`` allowlist.

    None = unset or blank = all vendors. Entries are validated against
    the registered specs after the register() block below runs
    (``_validate_vendor_allowlist``): a typo or an all-separators value
    fails fast at import instead of silently disabling vendors.
    """
    raw = os.environ.get("PROVISIONER_VENDORS", "").strip()
    if not raw:
        return None
    return frozenset(v.strip() for v in raw.split(",") if v.strip())


# Optional vendor allowlist, fixed at import (i.e. process start) because
# the derived views are bound at their consumers' import time.
VENDORS = _parse_vendors_env()  # type: Optional[FrozenSet[str]]


@dataclass(frozen=True)
class ConfigFamilySpec:
    """A model family represented in the standard config library."""

    name: str
    directory: str
    model_patterns: Tuple[str, ...]
    roles: Tuple[str, ...] = ("AP", "SM", "PTP")
    # Explicit certification list for PTP links.  An empty tuple means that
    # the family is not certified for PTP, even when PTP is listed as a
    # possible asset role.  Directory names are used because they are the
    # stable on-disk family identifiers.
    ptp_compatible_families: Tuple[str, ...] = ()

    def matches(self, model: Optional[str]) -> bool:
        if not model:
            return False
        normalized = " ".join(str(model).lower().strip().split())
        return any(fnmatchcase(normalized, pattern.lower()) for pattern in self.model_patterns)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "directory": self.directory,
            "model_patterns": list(self.model_patterns),
            "roles": list(self.roles),
            "ptp_compatible_families": list(self.ptp_compatible_families),
        }


@dataclass(frozen=True)
class VendorSpec:
    """Everything the provisioner needs to enumerate one vendor.

    Data only — behavior lives in ``handler_cls`` (and its class-level
    traits) and ``firmware_source_cls``.
    """

    # The hand-written enum member (fingerprint.py). Also usable as its
    # string value everywhere (str Enum).
    device_type: DeviceType

    # Provisioning handler; None only for non-provisionable vendors
    # (Evolution Digital's main.py side-door flow).
    handler_cls: Optional[Type[BaseHandler]] = None

    # False -> absent from handler_map() and every list derived from it
    # (CLI, API validation, setup rows); still gets a kiosk UI card.
    provisionable: bool = True

    # Auto-fetch firmware source class, or None (Tarana: manual upload).
    firmware_source_cls: Optional[Type[BaseFirmwareSource]] = None

    # Kwargs for config.FirmwareSourceConfig — the vendor's default
    # firmware-checker config. Only meaningful with firmware_source_cls.
    firmware_source_defaults: Optional[Dict[str, Any]] = None

    # Config-level factory-default login ({"username", "password"}).
    # Public factory logins only (admin/admin, root/admin, ubnt/ubnt) —
    # fleet passwords come from config.yaml / env vars.
    default_credentials: Optional[Dict[str, str]] = None

    # Credentials-UI "built-in" rows, when they differ from
    # default_credentials (Tarana ships admin/admin123, but the config
    # default keeps an empty password because each fleet sets its own).
    # None -> derive [default_credentials].
    builtin_ui_credentials: Optional[Tuple[Dict[str, str], ...]] = None

    # Factory-default link-local IPs; first entry is the primary/default
    # address (DeviceIPsConfig default), later entries are alternates.
    # Probe ORDER across vendors is vendor_ips.py order metadata, not
    # spec data.
    link_local_ips: Tuple[str, ...] = ()

    # model-key -> firmware filename patterns, for the firmware-file
    # lookup in FirmwareManager. (Distinct from the handler-local
    # MODEL_FIRMWARE_PATTERNS *validation* dicts, which are class traits.)
    model_firmware_patterns: Dict[str, List[str]] = field(default_factory=dict)

    # Directory under configs/templates/ with this vendor's bundled
    # deep-merge templates; None when the vendor doesn't use them
    # (MikroTik: netinstall/ZTP .rsc; Tarana: operator_id only).
    config_template_dir: Optional[str] = None

    # Standard device-config families.  This is metadata only; config
    # behavior remains in the vendor handler and the resolver.
    config_families: Tuple[ConfigFamilySpec, ...] = ()

    # Kiosk presentation data ({"name", "color"}); the rest of the UI
    # entry (defaultUser, icon) is derived in web/api.py.
    ui_style: Optional[Dict[str, str]] = None


# device-type value -> VendorSpec, in registration order. Private:
# consumers go through specs()/all_specs() and the derivation functions.
_SPECS = {}  # type: Dict[str, VendorSpec]


def register(spec: VendorSpec) -> None:
    """Register a vendor. Called once per vendor, at the bottom of this
    module, in DeviceType declaration order."""
    if not isinstance(spec.device_type, DeviceType) and not hasattr(
        spec.device_type, "value"
    ):
        raise TypeError(
            "VendorSpec.device_type must be a DeviceType member, got "
            + repr(spec.device_type)
        )
    key = spec.device_type.value
    if key in _SPECS:
        raise ValueError("Vendor already registered: " + key)
    if spec.provisionable and spec.handler_cls is None:
        raise ValueError("Provisionable vendor without handler_cls: " + key)
    _SPECS[key] = spec


def all_specs() -> List[VendorSpec]:
    """Every registered spec, ignoring the VENDORS allowlist (for
    spec <-> enum consistency checks)."""
    return list(_SPECS.values())


def specs() -> List[VendorSpec]:
    """Enabled specs, in registration order (VENDORS allowlist applied)."""
    return [
        s
        for s in _SPECS.values()
        if VENDORS is None or s.device_type.value in VENDORS
    ]


def spec_for(device_type: str) -> Optional[VendorSpec]:
    """Enabled spec for a device-type string, or None."""
    spec = _SPECS.get(device_type)
    if spec is None:
        return None
    if VENDORS is not None and spec.device_type.value not in VENDORS:
        return None
    return spec


def config_family_for_model(
    device_type: str, model: Optional[str]
) -> Optional[ConfigFamilySpec]:
    """Return the registry-declared config family for a detected model."""
    spec = spec_for(device_type)
    if spec is None:
        return None
    normalized_model = " ".join(str(model or "").lower().strip().split())
    device_name = str(getattr(device_type, "value", device_type)).lower()
    device_name = device_name.replace("_", " ")
    if normalized_model.startswith(device_name + " "):
        normalized_model = normalized_model[len(device_name) + 1:]
    for family in spec.config_families:
        if family.matches(normalized_model):
            return family
    return None


def config_family_metadata() -> Dict[str, List[Dict[str, Any]]]:
    """Return family metadata for API/UI consumers."""
    return {
        spec.device_type.value: [family.as_dict() for family in spec.config_families]
        for spec in specs()
        if spec.config_families
    }


def ptp_families_compatible(
    device_type: str,
    model: Optional[str],
    peer_device_type: str,
    peer_model: Optional[str],
) -> bool:
    """Return whether two detected models have a certified PTP pairing.

    PTP certification is deliberately explicit in the family registry.  A
    model without a recognized family, a family without a PTP role, or a
    cross-vendor pair fails closed.
    """
    if device_type != peer_device_type:
        return False

    family = config_family_for_model(device_type, model)
    peer_family = config_family_for_model(peer_device_type, peer_model)
    if family is None or peer_family is None:
        return False
    if "PTP" not in family.roles or "PTP" not in peer_family.roles:
        return False

    return (
        peer_family.directory in family.ptp_compatible_families
        and family.directory in peer_family.ptp_compatible_families
    )


# ---------------------------------------------------------------------------
# Derived views. Call-time over specs(), so tests can register a vendor and
# re-derive; production consumers bind them once at import.
# ---------------------------------------------------------------------------


def handler_map() -> Dict[DeviceType, Type[BaseHandler]]:
    """DeviceType -> handler class (HandlerManager.HANDLER_MAP)."""
    return {
        s.device_type: s.handler_cls for s in specs() if s.provisionable
    }


def firmware_source_map() -> Dict[str, Type[BaseFirmwareSource]]:
    """device-type value -> firmware source class (FirmwareChecker.SOURCE_MAP)."""
    return {
        s.device_type.value: s.firmware_source_cls
        for s in specs()
        if s.firmware_source_cls is not None
    }


def model_firmware_patterns() -> Dict[str, List[str]]:
    """Merged model->patterns table (FirmwareManager.MODEL_FIRMWARE_PATTERNS).

    Merged in registration order. Model keys must be globally unique — a
    collision would let one vendor's firmware match another's model, so
    it raises instead of silently overriding.
    """
    merged = {}  # type: Dict[str, List[str]]
    for spec in specs():
        for model_key, patterns in spec.model_firmware_patterns.items():
            if model_key in merged:
                raise ValueError(
                    "Duplicate model firmware pattern key across vendors: "
                    + model_key
                )
            merged[model_key] = list(patterns)
    return merged


def link_local_ips(enabled_only: bool = True) -> Dict[str, List[str]]:
    """vendor -> ordered link-local IPs, in registration order.

    ``vendor_ips.py`` re-orders this into the historical detection-probe
    order (order metadata lives there, next to the other probe-order
    tuples) and is what ``port_manager`` / ``config`` consume.

    ``enabled_only=False`` ignores the VENDORS allowlist: used for the
    static per-vendor address constants (``DeviceLinkLocalIP.<VENDOR>``),
    which are facts about vendor gear and must stay importable in a
    single-vendor build. Detection *candidates* always use the filtered
    default.
    """
    source = specs() if enabled_only else all_specs()
    return {
        s.device_type.value: list(s.link_local_ips)
        for s in source
        if s.link_local_ips
    }


def credential_defaults() -> Dict[str, Dict[str, str]]:
    """vendor -> DeviceCredentials kwargs, sorted by vendor (the
    historical config.py declaration order was alphabetical)."""
    entries = {
        s.device_type.value: dict(s.default_credentials)
        for s in specs()
        if s.default_credentials is not None
    }
    return {vendor: entries[vendor] for vendor in sorted(entries)}


def firmware_source_config_defaults() -> Dict[str, Dict[str, Any]]:
    """vendor -> FirmwareSourceConfig kwargs, for vendors with a source
    class, in registration order (``config.py`` applies the historical
    serialization order)."""
    return {
        s.device_type.value: dict(s.firmware_source_defaults or {})
        for s in specs()
        if s.firmware_source_cls is not None
    }


def builtin_ui_credentials() -> Dict[str, List[Dict[str, str]]]:
    """vendor -> credentials-UI built-in rows (web.api.BUILTIN_CREDENTIALS),
    sorted by vendor (matching the historical derivation from the sorted
    credential defaults)."""
    entries = {}  # type: Dict[str, List[Dict[str, str]]]
    for spec in specs():
        if spec.builtin_ui_credentials is not None:
            entries[spec.device_type.value] = [
                dict(cred) for cred in spec.builtin_ui_credentials
            ]
        elif spec.default_credentials is not None:
            entries[spec.device_type.value] = [
                {
                    "username": spec.default_credentials["username"],
                    "password": spec.default_credentials["password"],
                }
            ]
    return {vendor: entries[vendor] for vendor in sorted(entries)}


def ui_styles() -> Dict[str, Dict[str, str]]:
    """vendor -> kiosk style ({"name", "color"}) for every enabled spec
    that declares one (including non-provisionable vendors)."""
    return {
        s.device_type.value: dict(s.ui_style)
        for s in specs()
        if s.ui_style is not None
    }


def nonprovisionable_device_types() -> List[str]:
    """Enabled vendors absent from handler_map() but still real device
    types with a UI card (Evolution Digital), in registration order."""
    return [s.device_type.value for s in specs() if not s.provisionable]


# ---------------------------------------------------------------------------
# Registrations — one per vendor, in DeviceType declaration order. This
# block is THE place to add or remove a vendor (plus its enum member).
# ---------------------------------------------------------------------------

register(VendorSpec(
    device_type=DeviceType.MIKROTIK,
    handler_cls=MikrotikHandler,
    firmware_source_cls=MikrotikFirmwareSource,
    firmware_source_defaults={
        "enabled": True, "auto_download": True, "channel": "long-term",
    },
    default_credentials={"username": "admin", "password": ""},
    # MikroTik default subnet; devices often use DHCP instead. The
    # post-miss fallback subnets (192.168.0.1, 10.0.0.1) are probe
    # *behavior* and stay in port_manager.DeviceLinkLocalIP.MIKROTIK_FALLBACKS.
    link_local_ips=("192.168.88.1",),
    # No config_template_dir: configured via netinstall/ZTP .rsc scripts,
    # not deep-merge templates (documented exception).
    ui_style={"name": "MikroTik", "color": "#0E0E10"},
))

register(VendorSpec(
    device_type=DeviceType.CAMBIUM,
    handler_cls=CambiumHandler,
    firmware_source_cls=CambiumFirmwareSource,
    firmware_source_defaults={"enabled": False},
    default_credentials={"username": "admin", "password": "admin"},
    link_local_ips=("169.254.1.1",),
    model_firmware_patterns={
        # ePMP AX series (WiFi 6) - uses ePMP-ax firmware
        "epmp 4518": ["epmp-ax", "epmp_ax"],
        "epmp 4525": ["epmp-ax", "epmp_ax"],
        "epmp 4600": ["epmp-ax", "epmp_ax"],
        "epmp 4600c": ["epmp-ax", "epmp_ax"],
        "epmp 4616": ["epmp-ax", "epmp_ax"],
        "epmp 4625": ["epmp-ax", "epmp_ax"],
        # Force 300 series - uses AC firmware
        "force 300-25": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-19": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-16": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-13": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300 csm": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        # ePMP 3000 series - uses AC firmware
        "epmp 3000": ["epmp-ac", "epmp_ac"],
        "epmp 3000l": ["epmp-ac", "epmp_ac"],
        "epmp 3000 mp": ["epmp-ac", "epmp_ac"],
        # ePMP 2000/1000 series
        "epmp 2000": ["epmp-nongps", "epmp2000"],
        "epmp 1000": ["epmp1000", "epmp-nongps"],
    },
    config_template_dir="cambium",
    config_families=(
        ConfigFamilySpec(
            name="ePMP 3K",
            directory="ePMP-3K",
            model_patterns=("epmp 3000", "epmp 3000l", "epmp 3000 mp"),
            roles=("AP", "SM", "PTP"),
            ptp_compatible_families=("ePMP-3K", "ePMP-4K"),
        ),
        ConfigFamilySpec(
            name="ePMP 4K",
            directory="ePMP-4K",
            model_patterns=(
                "epmp 4518", "epmp 4525", "epmp 4600", "epmp 4600c",
                "epmp 4616", "epmp 4625",
            ),
            roles=("AP", "SM", "PTP"),
            ptp_compatible_families=("ePMP-3K", "ePMP-4K"),
        ),
    ),
    ui_style={"name": "Cambium", "color": "#1A73E9"},
))

register(VendorSpec(
    device_type=DeviceType.TACHYON,
    handler_cls=TachyonHandler,
    firmware_source_cls=TachyonFirmwareSource,
    firmware_source_defaults={"enabled": True, "auto_download": True},
    default_credentials={"username": "root", "password": "admin"},
    # 192.168.1.1: some Tachyon devices use this
    link_local_ips=("169.254.1.1", "192.168.1.1"),
    model_firmware_patterns={
        # TNA-30x series (standard 60 GHz) - uses tna-30x firmware
        "tna-303x": ["tna-30x", "tna30x"],
        "tna-301": ["tna-30x", "tna30x"],
        "tna-302": ["tna-30x", "tna30x"],
        # TNA-303L series (long range) - uses tna-303l firmware
        "tna-303l": ["tna-303l", "tna303l"],
        "tna-303l-65": ["tna-303l", "tna303l"],
        "tna-303l-lib": ["tna-303l", "tna303l"],
        # TNA-305 series (60 GHz + 5/6 GHz) - uses tna-305 firmware
        "tna-305a": ["tna-305", "tna305"],
        "tna-305x": ["tna-305", "tna305"],
        # TNS-100 series (subscriber) - uses tns-100 firmware
        "tns-100": ["tns-100", "tns100"],
    },
    config_template_dir="tachyon",
    config_families=(
        ConfigFamilySpec(
            name="TNA-301-302",
            directory="TNA-301-302",
            model_patterns=("tna-301*", "tna-302*"),
            roles=("AP", "SM", "PTP"),
            ptp_compatible_families=(
                "TNA-301-302", "TNA-303X", "TNA-303L-65",
            ),
        ),
        ConfigFamilySpec(
            name="TNA-303X",
            directory="TNA-303X",
            model_patterns=("tna-303x*",),
            roles=("AP", "SM", "PTP"),
            ptp_compatible_families=(
                "TNA-301-302", "TNA-303X", "TNA-303L-65",
            ),
        ),
        ConfigFamilySpec(
            name="TNA-303L-65",
            directory="TNA-303L-65",
            model_patterns=("tna-303l-65*",),
            roles=("SM", "PTP"),
            ptp_compatible_families=(
                "TNA-301-302", "TNA-303X", "TNA-303L-65",
            ),
        ),
    ),
    ui_style={"name": "Tachyon", "color": "#a855f7"},
))

register(VendorSpec(
    device_type=DeviceType.TARANA,
    handler_cls=TaranaHandler,
    # No firmware_source_cls: Tarana's firmware download endpoint
    # requires authentication, so firmware is uploaded manually
    # (documented exception).
    default_credentials={"username": "admin", "password": ""},
    # Devices ship with admin/admin123; the config default keeps an empty
    # password because each fleet sets its own.
    builtin_ui_credentials=({"username": "admin", "password": "admin123"},),
    link_local_ips=("169.254.100.1",),
    # No config_template_dir: Tarana "config" is just the operator_id
    # integer (device_settings), not a template file.
    ui_style={"name": "Tarana", "color": "#d97706"},
))

register(VendorSpec(
    device_type=DeviceType.UBIQUITI,
    handler_cls=UbiquitiHandler,
    firmware_source_cls=UbiquitiFirmwareSource,
    firmware_source_defaults={"enabled": False},
    default_credentials={"username": "ubnt", "password": "ubnt"},
    # Ubiquiti AirMax and Wave default
    link_local_ips=("192.168.1.20",),
    model_firmware_patterns={
        # Wave series - mapped to specific firmware variants
        # GMC (75ba) = GigaBeam Connect: Wave-AP, Wave-Pro, Wave-AP-Micro, Wave-Pico
        # MGMP (02da) = Mini GigaBeam Micro/Pico: Wave-Nano, Wave-Micro, Wave-LR
        "wave-pro": ["75ba-wave", "gmc"],
        "wave-ap": ["75ba-wave", "gmc"],
        "wave-ap-micro": ["75ba-wave", "gmc"],
        "wave-pico": ["75ba-wave", "gmc"],
        "wave-nano": ["02da-wave", "mgmp"],
        "wave-micro": ["02da-wave", "mgmp"],
        "wave-lr": ["02da-wave", "mgmp"],
        # AirMax series
        "rocket": ["airmax"],
        "nanostation": ["airmax"],
        "litebeam": ["airmax"],
        "powerbeam": ["airmax"],
        "nanobeam": ["airmax"],
        # AirFiber series. Each AF SKU has its own firmware prefix in
        # the Ubiquiti manifest; "airfiber" alone is too broad to
        # disambiguate. 322c = AF-5XHD (LTU PtP, 1.x firmware line, per
        # repo manifest.yaml).
        "af-5xhd": ["322c-airfiber"],
        "af60-lr": ["airfiber"],
        "af60-xr": ["airfiber"],
        "af60-hd": ["airfiber"],
        "af-11fx": ["airfiber"],
    },
    ui_style={"name": "Ubiquiti", "color": "#0559C9"},
))

register(VendorSpec(
    device_type=DeviceType.EVOLUTION_DIGITAL,
    # Non-provisionable: ED's passive cross-port qualification flow needs
    # port_manager cross-port access and is dispatched directly from
    # main.py._provision_evolution_digital (the side-door). Its
    # EvolutionDigitalHandler is not a BaseHandler and is imported lazily
    # there, so handler_cls stays None here.
    handler_cls=None,
    provisionable=False,
    # No credentials / IPs / firmware: ED devices are detected passively
    # (DHCP + OUI) and only qualified, never logged into.
    ui_style={"name": "Evolution", "color": "#ec4899"},
))


def _validate_vendor_allowlist() -> None:
    """Fail fast on a bad PROVISIONER_VENDORS value.

    Runs after the register() block so the valid vendor set is known. A
    typo'd vendor name or an all-separators value (e.g. ``","``) would
    otherwise silently disable vendors — a zero- or wrong-vendor kiosk
    with no error anywhere.
    """
    raw = os.environ.get("PROVISIONER_VENDORS")
    if raw is None or not raw.strip():
        # Unset or blank = full build; nothing to validate or log.
        return
    valid = ", ".join(sorted(_SPECS))
    if not VENDORS:
        raise RuntimeError(
            "PROVISIONER_VENDORS is set but selects no vendors "
            "(value: {!r}). Unset it for a full build, or set a "
            "comma-separated subset of: {}".format(raw, valid)
        )
    unknown = sorted(set(VENDORS) - set(_SPECS))
    if unknown:
        raise RuntimeError(
            "PROVISIONER_VENDORS names unknown vendor(s) {}. Valid "
            "vendors: {}. Refusing to start — a typo here would "
            "silently disable the vendor.".format(unknown, valid)
        )
    logger.info(
        "PROVISIONER_VENDORS active: enabled vendors = %s (registered: %s)",
        sorted(VENDORS),
        sorted(_SPECS),
    )


_validate_vendor_allowlist()
