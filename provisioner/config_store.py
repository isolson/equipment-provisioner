"""Local config/firmware store — replaces GitHub sync with simple filesystem paths."""

import logging
from pathlib import Path
from typing import Optional, Dict, Any

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
            "tna-303l": "tna-303x",
            "tna-303l-65": "tna-303x",
        },
        "cambium": {
            "epmp 4518": "f4518-sm-defaultconfig",
        },
    }

    def get_config_template(self, device_type: str, model: Optional[str] = None) -> Optional[Path]:
        """Get the path to the config template for a device type.

        Searches in order:
        1. {templates_path}/{device_type}/{model}.* (model-specific in subdir)
        2. {templates_path}/{device_type}/{alias}.* (aliased model in subdir)
        3. {templates_path}/{device_type}/default.* (default in subdir)
        4. {templates_path}/{device_type}/*.* (any file in subdir)
        5. {templates_path}/{device_type}_{model}.* (legacy model-specific)
        6. {templates_path}/{device_type}.* (legacy device type)
        """
        device_dir = self.templates_path / device_type

        model_alias = None
        if model and device_type in self.CONFIG_MODEL_ALIASES:
            model_key = model.lower()
            model_alias = self.CONFIG_MODEL_ALIASES[device_type].get(model_key)
            if model_alias:
                logger.debug(f"Config model alias: {model} -> {model_alias}")

        if device_dir.exists() and device_dir.is_dir():
            if model:
                for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                    model_template = device_dir / f"{model}{ext}"
                    if model_template.exists():
                        return model_template

            if model_alias:
                for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                    alias_template = device_dir / f"{model_alias}{ext}"
                    if alias_template.exists():
                        logger.info(f"Using aliased config template: {alias_template.name} for model {model}")
                        return alias_template

            for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                default_template = device_dir / f"default{ext}"
                if default_template.exists():
                    return default_template

            # Any config file in subdirectory (exclude ap.* AP-naming templates)
            for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                files = [f for f in device_dir.glob(f"*{ext}")
                         if not f.stem.lower().startswith("ap")]
                if files:
                    return sorted(files)[0]

        # Legacy: model-specific template in root
        if model:
            for ext in [".json", ".rsc", ".yaml"]:
                model_template = self.templates_path / f"{device_type}_{model}{ext}"
                if model_template.exists():
                    return model_template

        if model_alias:
            for ext in [".json", ".rsc", ".yaml"]:
                alias_template = self.templates_path / f"{device_type}_{model_alias}{ext}"
                if alias_template.exists():
                    logger.info(f"Using aliased config template: {alias_template.name} for model {model}")
                    return alias_template

        for ext in [".json", ".rsc", ".yaml", ".txt"]:
            template = self.templates_path / f"{device_type}{ext}"
            if template.exists():
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
