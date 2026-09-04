"""Family- and mode-aware configuration asset catalog.

The catalog is deliberately filesystem based.  The vendor registry describes
which model belongs to which family; the tree on disk describes which assets
are actually installed.  This keeps the web UI and the runtime resolver on
the same source of truth without introducing another vendor enumeration.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import Dict, List, Optional, Tuple

CONFIG_EXTENSIONS = (".json", ".rsc", ".yaml", ".yml", ".tar", ".tar.gz", ".tgz")
SAFE_TEXT_EXTENSIONS = (".json", ".rsc", ".yaml", ".yml")
PTP_ROLE = "ptp"
PTP_SIDE_TO_MODE = {"main": "ptp-a", "sm": "ptp-b"}
MODE_TO_PTP_SIDE = {"ptp-a": "Main", "ptp-b": "SM"}
_SECRET_FIELD_RE = re.compile(
    r"(?:password|passphrase|psk|secret|token|community|private[_-]?key|encryption[_-]?key)",
    re.IGNORECASE,
)
_DYNAMIC_FIELD_RE = re.compile(
    r"(?:ip|addr|gateway|hostname|name|ssid|frequency|serial|mac|identity|location)",
    re.IGNORECASE,
)


def is_config_asset(path: Path) -> bool:
    """Return whether *path* has a supported configuration extension."""
    name = path.name.lower()
    return any(name.endswith(extension) for extension in CONFIG_EXTENSIONS)


def file_extension(path: Path) -> str:
    """Return the logical asset extension, including ``.tar.gz``."""
    name = path.name.lower()
    for extension in CONFIG_EXTENSIONS:
        if name.endswith(extension):
            return extension
    return path.suffix.lower()


def _clean_component(value: str, label: str = "path component") -> str:
    if not value or value in (".", "..") or "\x00" in value:
        raise ValueError("Invalid %s" % label)
    if "/" in value or "\\" in value:
        raise ValueError("Invalid %s" % label)
    return value


def safe_relative_path(value: str) -> PurePosixPath:
    """Validate a data-root-relative POSIX path and reject traversal."""
    if not value or "\x00" in value:
        raise ValueError("Invalid asset path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("Invalid asset path")
    return path


@dataclass(frozen=True)
class ConfigAsset:
    """Metadata for one installed configuration asset.

    ``path`` is relative to the data root (for example,
    ``configs/templates/cambium/ePMP-4K/...``).  No file content is stored in
    this object, which makes it safe to return from catalog endpoints.
    """

    path: str
    device_type: str
    config_type: str
    filename: str
    size: int
    modified: str
    family: Optional[str] = None
    firmware: Optional[str] = None
    role: Optional[str] = None
    mode: Optional[str] = None
    profile: Optional[str] = None
    link_profile: Optional[str] = None
    scope: Optional[str] = None
    asset_kind: str = "standard"
    secret_present: bool = False
    property_count: int = 0
    dynamic_fields: Tuple[str, ...] = ()
    content_type: str = ""
    protected: bool = False
    editable: bool = False

    def as_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "device_type": self.device_type,
            "config_type": self.config_type,
            "filename": self.filename,
            "size": self.size,
            "modified": self.modified,
            "family": self.family,
            "firmware": self.firmware,
            "role": self.role,
            "mode": self.mode,
            "profile": self.profile,
            "link_profile": self.link_profile,
            "scope": self.scope,
            "asset_kind": self.asset_kind,
            "secret_present": self.secret_present,
            "property_count": self.property_count,
            "dynamic_fields": list(self.dynamic_fields),
            "content_type": self.content_type,
            "protected": self.protected,
            "editable": self.editable,
        }


def _mode_for_role(role: Optional[str], profile: Optional[str]) -> Optional[str]:
    if not role:
        return None
    role_lower = role.lower()
    if role_lower == "ap":
        return "ap"
    if role_lower == "sm":
        return "sm"
    if role_lower == PTP_ROLE and profile:
        return PTP_SIDE_TO_MODE.get(profile.lower())
    return None


def _has_secret_value(value: object) -> bool:
    """Return whether a config contains a non-empty secret-shaped value."""
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_FIELD_RE.search(str(key)) and child not in (None, "", [], {}):
                return True
            if _has_secret_value(child):
                return True
    elif isinstance(value, list):
        return any(_has_secret_value(child) for child in value)
    return False


def _content_metadata(path: Path, extension: str) -> Tuple[str, bool, int, Tuple[str, ...]]:
    """Inspect safe metadata without retaining or logging config values."""
    parsed = None
    try:
        if extension == ".json":
            parsed = json.loads(path.read_text(encoding="utf-8"))
        elif extension in (".tar", ".tar.gz", ".tgz"):
            with tarfile.open(path, mode="r:*") as archive:
                member = next(
                    (entry for entry in archive.getmembers()
                     if Path(entry.name).name == "config.json"),
                    None,
                )
                if member is not None:
                    config_file = archive.extractfile(member)
                    if config_file is not None:
                        parsed = json.load(config_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, tarfile.TarError, ValueError):
        return "standard", False, 0, ()

    if not isinstance(parsed, dict):
        return "standard", False, 0, ()
    device_props = parsed.get("device_props")
    template_props = parsed.get("template_props")
    is_full_export = isinstance(device_props, dict) and isinstance(template_props, dict)
    if not isinstance(device_props, dict):
        device_props = parsed
    property_count = len(device_props)
    if isinstance(template_props, dict):
        property_count += len(template_props)
    dynamic_fields = tuple(
        sorted(key for key in device_props if _DYNAMIC_FIELD_RE.search(str(key)))
    )
    return (
        "field_export" if is_full_export else "standard",
        _has_secret_value(parsed),
        property_count,
        dynamic_fields,
    )


def describe_asset(path: Path, data_root: Path, config_type: str) -> ConfigAsset:
    """Build metadata for *path* using the canonical nested tree layout."""
    relative = path.relative_to(data_root).as_posix()
    parts = PurePosixPath(relative).parts
    # configs/{templates|overrides}/{device_type}/...
    # Root-level files are legacy assets whose vendor is inferred by the
    # legacy endpoint.  Do not mistake the filename for a device type.
    device_type = parts[2] if len(parts) >= 4 else "unknown"
    rest = list(parts[3:-1]) if len(parts) >= 4 else []
    family = firmware = role = mode = profile = link_profile = scope = None

    if len(rest) >= 2:
        scope = "family"
        if rest[0].lower() == "shared":
            scope = "shared"
            family = None
            path_after_scope = rest[1:]
        else:
            family = rest[0]
            path_after_scope = rest[1:]
        if path_after_scope and path_after_scope[0].lower() in ("ap", "sm", "ptp"):
            # Tachyon's approved library is not firmware-versioned.
            firmware = None
            role = path_after_scope[0]
            role_parts = path_after_scope[1:]
        else:
            firmware = path_after_scope[0] if path_after_scope else None
            role = path_after_scope[1] if len(path_after_scope) >= 2 else None
            role_parts = path_after_scope[2:]
        if role:
            role_lower = role.lower()
            if role_lower == "ap":
                profile = role_parts[0] if role_parts else "default"
            elif role_lower == "ptp":
                link_profile = role_parts[0] if role_parts else None
                profile = role_parts[1] if len(role_parts) >= 2 else None
            else:
                profile = role_parts[0] if role_parts else "default"
            mode = _mode_for_role(role, profile)

    extension = file_extension(path)
    asset_kind, secret_present, property_count, dynamic_fields = _content_metadata(path, extension)
    protected = (
        bool(role and role.lower() == PTP_ROLE)
        or asset_kind == "field_export"
        or secret_present
    )
    return ConfigAsset(
        path=relative,
        device_type=device_type,
        config_type=config_type,
        filename=path.name,
        size=path.stat().st_size,
        modified=datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
        family=family,
        firmware=firmware,
        role=role,
        mode=mode,
        profile=profile,
        link_profile=link_profile,
        scope=scope,
        asset_kind=asset_kind,
        secret_present=secret_present,
        property_count=property_count,
        dynamic_fields=dynamic_fields,
        content_type=extension.lstrip("."),
        protected=protected,
        editable=(not protected and extension in SAFE_TEXT_EXTENSIONS),
    )


class ConfigAssetCatalog:
    """Enumerate and safely resolve assets in a config store."""

    def __init__(self, data_root: Path):
        self.data_root = Path(data_root).resolve()

    def _root_for_type(self, config_type: str) -> Path:
        if config_type == "template":
            return self.data_root / "configs" / "templates"
        if config_type == "override":
            return self.data_root / "configs" / "overrides"
        raise ValueError("Invalid config type")

    def iter_assets(self, config_type: Optional[str] = None) -> Iterable[ConfigAsset]:
        types = (config_type,) if config_type else ("template", "override")
        for current_type in types:
            root = self._root_for_type(current_type)
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file() and not path.name.startswith(".") and is_config_asset(path):
                    yield describe_asset(path, self.data_root, current_type)

    def list_assets(
        self,
        device_type: Optional[str] = None,
        family: Optional[str] = None,
        firmware: Optional[str] = None,
        role: Optional[str] = None,
        mode: Optional[str] = None,
        scope: Optional[str] = None,
        config_type: Optional[str] = None,
    ) -> List[ConfigAsset]:
        values = list(self.iter_assets(config_type=config_type))
        filters = {
            "device_type": device_type,
            "family": family,
            "firmware": firmware,
            "role": role,
            "mode": mode,
            "scope": scope,
        }
        return sorted(
            [
                asset for asset in values
                if all(
                    expected is None or getattr(asset, key) == expected
                    for key, expected in filters.items()
                )
            ],
            key=lambda asset: (
                asset.config_type,
                asset.device_type,
                asset.family or "",
                asset.firmware or "",
                asset.role or "",
                asset.profile or "",
                asset.path,
            ),
        )

    def resolve(self, relative_path: str) -> Tuple[Path, ConfigAsset]:
        """Resolve an installed asset without allowing path traversal."""
        relative = safe_relative_path(relative_path)
        if len(relative.parts) < 4 or relative.parts[0] != "configs":
            raise ValueError("Invalid asset path")
        config_type = {
            "templates": "template",
            "overrides": "override",
        }.get(relative.parts[1])
        if config_type is None:
            raise ValueError("Invalid asset path")
        path = (self.data_root / Path(*relative.parts)).resolve()
        root = self._root_for_type(config_type).resolve()
        if root != path and root not in path.parents:
            raise ValueError("Invalid asset path")
        if not path.is_file() or not is_config_asset(path):
            raise FileNotFoundError(relative_path)
        return path, describe_asset(path, self.data_root, config_type)

    def destination(
        self,
        config_type: str,
        device_type: str,
        family: Optional[str],
        firmware: Optional[str],
        role: Optional[str],
        mode: Optional[str],
        profile: Optional[str],
        link_profile: Optional[str],
        filename: str,
        scope: Optional[str] = None,
    ) -> Path:
        """Build a structured upload destination after validating components."""
        root = self._root_for_type(config_type)
        device_type = _clean_component(device_type, "device type")
        filename = _clean_component(filename, "filename")
        if not is_config_asset(Path(filename)):
            raise ValueError("Unsupported config file type")

        if role and role.lower() == PTP_ROLE and mode:
            expected_mode = _mode_for_role(role, profile)
            if expected_mode != mode:
                expected_profile = MODE_TO_PTP_SIDE.get(mode)
                if expected_profile:
                    raise ValueError(
                        "{} exports require the {} side profile".format(
                            mode, expected_profile
                        )
                    )
                raise ValueError("PTP assets require a valid PTP mode")

        components = [root, device_type]
        if scope:
            scope = _clean_component(scope, "scope").lower()
            if scope not in ("shared", "family"):
                raise ValueError("Invalid asset scope")
        if scope == "shared":
            if family:
                raise ValueError("Shared assets cannot specify a family")
            if not role or not firmware:
                raise ValueError("Shared assets require firmware and role")
            components.extend(("shared", _clean_component(firmware, "firmware")))
            components.append(_clean_component(role, "role"))
            role_lower = role.lower()
            if role_lower == "ap" and profile and profile.lower() != "default":
                components.append(_clean_component(profile, "profile"))
            elif role_lower == PTP_ROLE:
                if not link_profile or not profile:
                    raise ValueError("Shared PTP assets require link and side profiles")
                components.extend(
                    (_clean_component(link_profile, "link profile"),
                     _clean_component(profile, "profile"))
                )
        elif family:
            if not role:
                raise ValueError("Family uploads require a role")
            components.append(_clean_component(family, "family"))
            if firmware:
                components.append(_clean_component(firmware, "firmware"))
            components.append(_clean_component(role, "role"))
            role_lower = role.lower()
            if role_lower == "ap":
                # AP/default.json is the family default; directional profiles
                # live below AP/{North,East,South,West}/default.json.
                if profile and profile.lower() != "default":
                    components.append(_clean_component(profile, "profile"))
            elif role_lower == "sm":
                # SM/default.json is directly below the role directory.
                pass
            elif role_lower == PTP_ROLE:
                if not link_profile or not profile:
                    raise ValueError("PTP assets require link and side profiles")
                components.extend(
                    (_clean_component(link_profile, "link profile"),
                     _clean_component(profile, "profile"))
                )
            elif profile:
                components.append(_clean_component(profile, "profile"))
        elif any(value for value in (firmware, role, mode, profile, link_profile)):
            raise ValueError("Family is required for structured asset uploads")

        destination = Path(*components) / filename
        resolved = destination.resolve()
        if root.resolve() != resolved and root.resolve() not in resolved.parents:
            raise ValueError("Invalid asset destination")
        return resolved

    @staticmethod
    def infer_structured_fields_for_model(
        device_type: str,
        model: Optional[str],
        family: Optional[str] = None,
        role: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Infer a safe family/role pair from a detected model.

        Family membership comes from ``VendorSpec``. A model-specific role
        hint comes from the handler. An explicit role is preserved, while an
        explicit family must match the detected model. A requested AP/SM mode
        is itself an explicit role for models whose family supports both
        roles.
        """
        from .vendor_registry import config_family_for_model

        family_spec = config_family_for_model(device_type, model)
        if family_spec is None:
            return family, role

        if family is not None and family != family_spec.directory:
            raise ValueError(
                "Model %s belongs to config family %s, not %s"
                % (model, family_spec.directory, family)
            )
        family = family_spec.directory

        if role is None and mode in ("ap", "sm"):
            role = mode.upper()
        if role is None:
            # Local import avoids making the asset catalog import the handler
            # package during module initialization.
            from .handler_manager import HandlerManager

            role = HandlerManager.upload_role_for_model(device_type, model)
        return family, role

    def destination_for_model(
        self,
        config_type: str,
        device_type: str,
        model: Optional[str],
        family: Optional[str],
        firmware: Optional[str],
        role: Optional[str],
        mode: Optional[str],
        profile: Optional[str],
        link_profile: Optional[str],
        filename: str,
    ) -> Path:
        """Build a structured asset destination from model metadata.

        This is the packaging seam for model-specific uploads. It keeps the
        model-to-family decision in the registry and the model-to-role
        decision in the handler, so TNA-301 AP assets cannot silently become
        TNA-302 SM assets (or the reverse).
        """
        family, role = self.infer_structured_fields_for_model(
            device_type, model, family=family, role=role, mode=mode
        )
        return self.destination(
            config_type,
            device_type,
            family,
            firmware,
            role,
            mode,
            profile,
            link_profile,
            filename,
        )
