"""Shared static config template loading and validation.

This module intentionally does not define vendor semantics. It only turns a
static JSON file, or a tar export containing config.json, into a validated JSON
object. Handlers still decide whether that object is a full config or a patch.
"""

import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


PLACEHOLDER_RE = re.compile(r"{{[^{}]+}}")


class ConfigTemplateError(ValueError):
    """Raised when a config template cannot be loaded safely."""


@dataclass
class LoadedConfigTemplate:
    config: Dict[str, Any]
    source_type: str
    path: Path
    member_name: Optional[str] = None

    @property
    def top_level_keys(self):
        return sorted(self.config.keys())


def load_config_template(config_path: str) -> LoadedConfigTemplate:
    """Load a static JSON config template from a JSON file or tar export.

    The loader validates only generic properties:
    - file exists
    - JSON parses
    - top-level JSON value is an object
    - static templates do not contain ``{{placeholder}}`` strings

    Vendor handlers own all device-specific interpretation.
    """
    path = Path(config_path)
    if not path.exists():
        raise ConfigTemplateError(f"Config file not found: {config_path}")

    try:
        if tarfile.is_tarfile(str(path)):
            loaded = _load_tar_config(path)
        else:
            loaded = _load_json_config(path)
    except ConfigTemplateError:
        raise
    except json.JSONDecodeError as exc:
        raise ConfigTemplateError(f"Invalid JSON in config file {config_path}: {exc}")
    except tarfile.TarError as exc:
        raise ConfigTemplateError(f"Invalid tar config file {config_path}: {exc}")
    except OSError as exc:
        raise ConfigTemplateError(f"Failed to read config file {config_path}: {exc}")

    if not isinstance(loaded.config, dict):
        raise ConfigTemplateError(f"Config template must contain a JSON object: {config_path}")

    placeholder = find_placeholder(loaded.config)
    if placeholder:
        raise ConfigTemplateError(
            f"Config template contains unsupported placeholder at {placeholder}"
        )

    return loaded


def _load_json_config(path: Path) -> LoadedConfigTemplate:
    with open(path, "r") as handle:
        config = json.load(handle)
    return LoadedConfigTemplate(config=config, source_type="json", path=path)


def _load_tar_config(path: Path) -> LoadedConfigTemplate:
    with tarfile.open(path, "r:*") as tar:
        config_member = None
        for member in tar.getmembers():
            if member.name == "config.json" or member.name.endswith("/config.json"):
                config_member = member
                break

        if config_member is None:
            raise ConfigTemplateError(f"No config.json found in tarball: {path}")

        extracted = tar.extractfile(config_member)
        if extracted is None:
            raise ConfigTemplateError(f"Failed to extract config.json from tarball: {path}")

        config = json.load(extracted)
        return LoadedConfigTemplate(
            config=config,
            source_type="tar",
            path=path,
            member_name=config_member.name,
        )


def find_placeholder(value: Any, path: str = "$") -> Optional[str]:
    """Return the first path containing ``{{placeholder}}`` syntax, if any."""
    if isinstance(value, str):
        return path if PLACEHOLDER_RE.search(value) else None
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            match = find_placeholder(child, child_path)
            if match:
                return match
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            match = find_placeholder(child, child_path)
            if match:
                return match
    return None
