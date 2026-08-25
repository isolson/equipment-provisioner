"""Family- and mode-aware configuration asset catalog.

The catalog is deliberately filesystem based.  The vendor registry describes
which model belongs to which family; the tree on disk describes which assets
are actually installed.  This keeps the web UI and the runtime resolver on
the same source of truth without introducing another vendor enumeration.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

CONFIG_EXTENSIONS = (".json", ".rsc", ".yaml", ".yml", ".tar", ".tar.gz", ".tgz")
SAFE_TEXT_EXTENSIONS = (".json", ".rsc", ".yaml", ".yml")
PTP_ROLE = "ptp"
PTP_SIDE_TO_MODE = {"main": "ptp-a", "sm": "ptp-b"}
MODE_TO_PTP_SIDE = {"ptp-a": "Main", "ptp-b": "SM"}


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


def describe_asset(path: Path, data_root: Path, config_type: str) -> ConfigAsset:
    """Build metadata for *path* using the canonical nested tree layout."""
    relative = path.relative_to(data_root).as_posix()
    parts = PurePosixPath(relative).parts
    # configs/{templates|overrides}/{device_type}/...
    # Root-level files are legacy assets whose vendor is inferred by the
    # legacy endpoint.  Do not mistake the filename for a device type.
    device_type = parts[2] if len(parts) >= 4 else "unknown"
    rest = list(parts[3:-1]) if len(parts) >= 4 else []
    family = firmware = role = mode = profile = link_profile = None

    if len(rest) >= 2:
        family = rest[0]
        if rest[1].lower() in ("ap", "sm", "ptp"):
            # Tachyon's approved library is not firmware-versioned.
            firmware = None
            role = rest[1]
            role_parts = rest[2:]
        else:
            firmware = rest[1]
            role = rest[2] if len(rest) >= 3 else None
            role_parts = rest[3:]
        role_lower = role.lower()
        if role_lower == "ap":
            profile = role_parts[0] if role_parts else "default"
        elif role_lower == "ptp":
            link_profile = role_parts[0] if role_parts else None
            profile = role_parts[1] if len(role_parts) >= 2 else None
        else:
            profile = role_parts[0] if role_parts else "default"
        mode = _mode_for_role(role, profile)

    protected = bool(role and role.lower() == PTP_ROLE)
    extension = file_extension(path)
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
        config_type: Optional[str] = None,
    ) -> List[ConfigAsset]:
        values = list(self.iter_assets(config_type=config_type))
        filters = {
            "device_type": device_type,
            "family": family,
            "firmware": firmware,
            "role": role,
            "mode": mode,
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
    ) -> Path:
        """Build a structured upload destination after validating components."""
        root = self._root_for_type(config_type)
        device_type = _clean_component(device_type, "device type")
        filename = _clean_component(filename, "filename")
        if not is_config_asset(Path(filename)):
            raise ValueError("Unsupported config file type")

        components = [root, device_type]
        if family:
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
                raise ValueError("PTP assets must be installed through the host-only workflow")
            elif profile:
                components.append(_clean_component(profile, "profile"))
        elif any(value for value in (firmware, role, mode, profile, link_profile)):
            raise ValueError("Family is required for structured asset uploads")

        destination = Path(*components) / filename
        resolved = destination.resolve()
        if root.resolve() != resolved and root.resolve() not in resolved.parents:
            raise ValueError("Invalid asset destination")
        return resolved
