"""Local config/firmware store — replaces GitHub sync with simple filesystem paths."""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)


class ConfigStore:
    """Provides config template and firmware path lookups from a local data directory."""

    def __init__(self, local_path: str):
        self.local_path = Path(local_path)

    @property
    def configs_path(self) -> Path:
        return self.local_path / "configs"

    @property
    def templates_path(self) -> Path:
        return self.local_path / "configs" / "templates"

    @property
    def overrides_path(self) -> Path:
        return self.local_path / "configs" / "overrides"

    @property
    def firmware_path(self) -> Path:
        return self.local_path / "firmware"

    # Model aliases for config templates — maps model to config name
    CONFIG_MODEL_ALIASES = {
        "tachyon": {
            "tna-301": "tna-30x",
            "tna-302": "tna-30x",
            "tna-303x": "tna-30x",
            "tna-303l": "tna-303l",
            "tna-303l-65": "tna-303l",
            "tna-303l-lib": "tna-303l",
            "tna-305a": "tna-305",
            "tna-305x": "tna-305",
            "tns-100": "tns-100",
        },
        "cambium": {
            "epmp 4518": "f4518-sm-defaultconfig",
        },
    }

    @staticmethod
    def _find_named_template(
        directory: Path,
        name: str,
        extensions,
        allow_prefixed_export: bool = False,
    ) -> Optional[Path]:
        """Find a template by model/name, returning the actual path casing.

        Also accepts timestamp-prefixed exports such as
        ``20260424.143334.TNA-303L-65.tar`` for model ``TNA-303L-65``.
        """
        if not directory.exists() or not directory.is_dir():
            return None

        entries = list(directory.iterdir())
        for ext in extensions:
            expected = f"{name}{ext}"
            for entry in entries:
                if entry.name == expected and entry.is_file():
                    return entry

        for ext in extensions:
            expected = f"{name}{ext}".lower()
            for entry in entries:
                if entry.name.lower() == expected and entry.is_file():
                    return entry

        if allow_prefixed_export:
            for ext in extensions:
                expected_suffix = f".{name}{ext}".lower()
                matches = [
                    entry
                    for entry in entries
                    if entry.name.lower().endswith(expected_suffix) and entry.is_file()
                ]
                if matches:
                    return sorted(matches, key=lambda entry: entry.name)[-1]

        return None

    @staticmethod
    def _handler_traits(device_type: str):
        """Class-level template traits for a vendor, via its handler class.

        Falls back to BaseHandler defaults for types without a handler
        (e.g. evolution_digital, unknown). Imported locally so importing
        config_store does not pull in the handlers package.
        """
        from .handler_manager import HandlerManager
        from .handlers.base import BaseHandler

        return HandlerManager.handler_class_for(device_type) or BaseHandler

    def _get_model_alias(self, device_type: str, model: Optional[str]) -> Optional[str]:
        if not model or device_type not in self.CONFIG_MODEL_ALIASES:
            return None

        model_key = model.lower()
        aliases = self.CONFIG_MODEL_ALIASES[device_type]
        alias = aliases.get(model_key)
        if alias:
            return alias

        if self._handler_traits(device_type).config_alias_prefix_matching:
            for prefix in sorted(aliases, key=len, reverse=True):
                if model_key.startswith(f"{prefix}-"):
                    return aliases[prefix]

        return None

    def _get_family_template(
        self, device_type: str, model: Optional[str], role: str = "SM"
    ) -> Optional[Path]:
        """Find the approved family/firmware/role default for a model.

        Family selection comes only from ``VendorSpec``.  The filesystem may
        contain multiple firmware directories; the newest directory by name
        wins, matching the operator-facing library convention.  There is no
        arbitrary family fallback, because a valid config for another radio
        family can still be destructive.
        """
        if not model:
            return None

        from .vendor_registry import config_family_for_model

        family = config_family_for_model(device_type, model)
        if family is None:
            return None

        family_dir = self.templates_path / device_type / family.directory
        if not family_dir.is_dir():
            return None

        extensions = [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]
        version_dirs = sorted(
            (entry for entry in family_dir.iterdir() if entry.is_dir()),
            key=lambda entry: entry.name.lower(),
            reverse=True,
        )
        # Some approved libraries are firmware-versioned (Cambium) and some
        # are intentionally family-versioned only (Tachyon).
        containers = [family_dir] + version_dirs
        for version_dir in containers:
            role_dir = next(
                (
                    entry for entry in version_dir.iterdir()
                    if entry.is_dir() and entry.name.lower() == role.lower()
                ),
                None,
            )
            if role_dir is None:
                continue
            template = self._find_named_template(role_dir, "default", extensions)
            if template:
                return template
        return None

    def _get_shared_template(
        self, device_type: str, role: str = "SM"
    ) -> Optional[Path]:
        """Find the vendor-neutral shared baseline for a role.

        Shared profiles are intentionally checked before model families.  A
        shared SM profile is the no-touch baseline for every model that the
        handler can provision.  The directory is still selected from the
        filesystem, so adding a shared profile does not add a vendor registry.
        """
        shared_dir = self.templates_path / device_type / "shared"
        if not shared_dir.is_dir():
            return None

        extensions = [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]
        version_dirs = sorted(
            (entry for entry in shared_dir.iterdir() if entry.is_dir()),
            key=lambda entry: entry.name.lower(),
            reverse=True,
        )
        containers = [shared_dir] + version_dirs
        for version_dir in containers:
            role_dir = next(
                (
                    entry for entry in version_dir.iterdir()
                    if entry.is_dir() and entry.name.lower() == role.lower()
                ),
                None,
            )
            if role_dir is None:
                continue
            template = self._find_named_template(role_dir, "default", extensions)
            if template:
                return template
        return None

    def _has_family_tree(self, device_type: str) -> bool:
        """Return whether this vendor has any installed family assets.

        Older installations may have only the historical flat templates.  In
        that case the legacy lookup remains available.  Once any structured
        family tree is installed, a recognized model must stay within its
        declared family so a missing role cannot silently cross-apply a flat
        template.
        """
        from .vendor_registry import spec_for

        spec = spec_for(device_type)
        if spec is None:
            return False
        device_dir = self.templates_path / device_type
        return any(
            (device_dir / family.directory).is_dir()
            for family in spec.config_families
        )

    def get_config_template(self, device_type: str, model: Optional[str] = None) -> Optional[Path]:
        """Get the path to the config template for a device type.

        Searches the shared SM baseline first, then the approved model
        family/firmware/SM tree, historical flat vendor tree, and legacy root.
        """
        from .vendor_registry import config_family_for_model

        device_dir = self.templates_path / device_type

        model_names = []
        if model:
            model_names.append(model)
            model_lower = model.lower()
            if model_lower != model:
                model_names.append(model_lower)

        model_alias = self._get_model_alias(device_type, model)
        if model_alias:
            logger.debug(f"Config model alias: {model} -> {model_alias}")
        traits = self._handler_traits(device_type)

        shared_template = self._get_shared_template(device_type)
        if shared_template:
            logger.info(
                "Using shared config template: %s for %s/%s",
                shared_template,
                device_type,
                model,
            )
            return shared_template

        family_template = self._get_family_template(device_type, model)
        if family_template:
            logger.info(
                "Using family config template: %s for %s/%s",
                family_template,
                device_type,
                model,
            )
            return family_template
        if config_family_for_model(device_type, model) is not None and self._has_family_tree(device_type):
            logger.warning(
                "No family config template for recognized model %s/%s; refusing legacy fallback",
                device_type,
                model,
            )
            return None

        if device_dir.exists() and device_dir.is_dir():
            if model_names:
                for model_name in model_names:
                    model_template = self._find_named_template(
                        device_dir,
                        model_name,
                        [".json", ".rsc", ".yaml", ".tar", ".tar.gz"],
                        allow_prefixed_export=traits.allows_prefixed_config_exports,
                    )
                    if model_template:
                        return model_template

            if model_alias:
                alias_template = self._find_named_template(
                    device_dir,
                    model_alias,
                    [".json", ".rsc", ".yaml", ".tar", ".tar.gz"],
                    allow_prefixed_export=traits.allows_prefixed_config_exports,
                )
                if alias_template:
                    logger.info(f"Using aliased config template: {alias_template.name} for model {model}")
                    return alias_template

            default_template = self._find_named_template(
                device_dir,
                "default",
                [".json", ".rsc", ".yaml", ".tar", ".tar.gz"],
            )
            if default_template:
                return default_template

            if traits.allows_arbitrary_template_fallback:
                # Historical fallback. Vendors with product-family templates
                # (e.g. Tachyon) disable this on their handler class, since an
                # arbitrary file could cross-apply switch/radio configs.
                for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                    files = [
                        f for f in device_dir.glob(f"*{ext}")
                        if not f.stem.lower().startswith("ap")
                    ]
                    if files:
                        return sorted(files)[0]

        # Legacy: model-specific template in root
        if model_names:
            for model_name in model_names:
                model_template = self._find_named_template(
                    self.templates_path,
                    f"{device_type}_{model_name}",
                    [".json", ".rsc", ".yaml"],
                )
                if model_template:
                    return model_template

        if model_alias:
            alias_template = self._find_named_template(
                self.templates_path,
                f"{device_type}_{model_alias}",
                [".json", ".rsc", ".yaml"],
            )
            if alias_template:
                logger.info(f"Using aliased config template: {alias_template.name} for model {model}")
                return alias_template

        template = self._find_named_template(
            self.templates_path,
            device_type,
            [".json", ".rsc", ".yaml", ".txt"],
        )
        if template:
            return template

        logger.warning(f"No config template found for {device_type}/{model}")
        return None

    def get_device_override(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get device-specific override configuration by MAC address."""
        mac_normalized = mac_address.upper().replace(":", "-")

        for ext in [".json", ".yaml"]:
            override_path = self.overrides_path / f"{mac_normalized}{ext}"
            if override_path.exists():
                with open(override_path, "r") as f:
                    return yaml.safe_load(f)

        return None

    def ensure_directories(self) -> None:
        """Create data directories if they don't exist."""
        self.firmware_path.mkdir(parents=True, exist_ok=True)
        self.templates_path.mkdir(parents=True, exist_ok=True)
        self.overrides_path.mkdir(parents=True, exist_ok=True)


# Global instance
_store: Optional[ConfigStore] = None


def init_store(local_path: str) -> ConfigStore:
    """Initialize the global ConfigStore instance."""
    global _store
    _store = ConfigStore(local_path)
    return _store


def get_store() -> ConfigStore:
    """Get the global ConfigStore instance."""
    if _store is None:
        raise RuntimeError("ConfigStore not initialized. Call init_store() first.")
    return _store
