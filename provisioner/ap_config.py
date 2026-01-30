"""AP (Access Point) configuration management.

Handles loading AP config templates and generating device naming
based on tower number and direction (North/South/East/West).

Supports two modes:
1. Placeholder mode: Replace {{variable}} patterns in config
2. Field injection mode: Overwrite specific known fields per device type
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class APConfigManager:
    """Manages AP configuration templates and naming generation."""

    # Valid directions
    DIRECTIONS = ["north", "south", "east", "west"]

    # SSID patterns by device type
    SSID_PATTERNS = {
        "tachyon": "{{direction_upper}}",  # Just "NORTH"
        "cambium": "tw{{tower_padded}}-{{direction}}",  # "tw05-north"
    }

    # Known fields to inject per device type
    # Each entry is a tuple of (json_path, variable_name)
    # json_path uses dot notation for nested fields
    # Array indices supported: "wireless.radios.wlan0.vaps[0].ssid"
    INJECT_FIELDS = {
        "cambium": [
            ("wirelessInterfaceSSID", "ssid"),
            ("snmpSystemName", "hostname"),
            ("systemConfigDeviceName", "hostname"),
        ],
        "tachyon": [
            ("system.hostname", "hostname"),
            ("system.name", "hostname"),
            ("wireless.radios.wlan0.vaps[0].ssid", "ssid"),
        ],
    }

    def __init__(self, templates_path: str):
        """Initialize AP config manager.

        Args:
            templates_path: Path to config templates directory
                           (e.g., /var/lib/provisioner/repo/configs/templates)
        """
        self.templates_path = Path(templates_path)

    def get_ap_template_path(
        self, device_type: str, model: Optional[str] = None
    ) -> Optional[Path]:
        """Get path to AP config template for a device type.

        Searches in order:
        1. {templates_path}/{device_type}/{model}-ap.json
        2. {templates_path}/{device_type}/ap.json
        3. {templates_path}/{device_type}_ap.json (legacy)

        Args:
            device_type: Device type (tachyon, cambium, etc.)
            model: Optional model name for model-specific AP configs

        Returns:
            Path to AP template file, or None if not found
        """
        device_dir = self.templates_path / device_type

        # Check device type subdirectory
        if device_dir.exists() and device_dir.is_dir():
            # Model-specific AP template
            if model:
                for ext in [".json", ".tar", ".tar.gz"]:
                    model_ap = device_dir / f"{model.lower()}-ap{ext}"
                    if model_ap.exists():
                        return model_ap

            # Default AP template in subdirectory
            for ext in [".json", ".tar", ".tar.gz"]:
                default_ap = device_dir / f"ap{ext}"
                if default_ap.exists():
                    return default_ap

        # Legacy: Check root templates folder
        for ext in [".json", ".tar", ".tar.gz"]:
            legacy_ap = self.templates_path / f"{device_type}_ap{ext}"
            if legacy_ap.exists():
                return legacy_ap

        logger.warning(f"No AP config template found for {device_type}")
        return None

    def load_ap_template(
        self, device_type: str, model: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Load AP config template as a dictionary.

        Args:
            device_type: Device type (tachyon, cambium, etc.)
            model: Optional model name

        Returns:
            Template dictionary, or None if not found/invalid
        """
        template_path = self.get_ap_template_path(device_type, model)
        if not template_path:
            return None

        try:
            # Handle tarball (extract config.json)
            if template_path.suffix in [".tar", ".gz"]:
                import tarfile
                with tarfile.open(template_path, "r:*") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith("config.json") or member.name == "config.json":
                            f = tar.extractfile(member)
                            if f:
                                return json.load(f)
                logger.error(f"No config.json found in tarball: {template_path}")
                return None

            # Plain JSON file
            with open(template_path, "r") as f:
                return json.load(f)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in AP template {template_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load AP template {template_path}: {e}")
            return None

    def generate_naming(
        self, tower: int, direction: str, device_type: str
    ) -> Dict[str, str]:
        """Generate naming variables for AP configuration.

        Args:
            tower: Tower number (1-99)
            direction: Direction (north, south, east, west)
            device_type: Device type for SSID pattern selection

        Returns:
            Dictionary with all naming variables:
            - hostname: e.g., "tw05-north"
            - systemname: e.g., "tw05-north"
            - ssid: device-specific (e.g., "NORTH" or "tw05-north")
            - tower: raw number as string
            - tower_padded: zero-padded (e.g., "05")
            - direction: lowercase (e.g., "north")
            - direction_upper: uppercase (e.g., "NORTH")

        Raises:
            ValueError: If tower or direction is invalid
        """
        # Validate inputs
        if not 1 <= tower <= 99:
            raise ValueError(f"Tower number must be 1-99, got {tower}")

        direction = direction.lower().strip()
        if direction not in self.DIRECTIONS:
            raise ValueError(
                f"Direction must be one of {self.DIRECTIONS}, got '{direction}'"
            )

        # Generate base variables
        tower_padded = f"{tower:02d}"
        direction_upper = direction.upper()
        hostname = f"tw{tower_padded}-{direction}"

        # Generate SSID based on device type
        ssid_pattern = self.SSID_PATTERNS.get(device_type, "tw{{tower_padded}}-{{direction}}")
        ssid = self._render_string(ssid_pattern, {
            "tower": str(tower),
            "tower_padded": tower_padded,
            "direction": direction,
            "direction_upper": direction_upper,
        })

        return {
            "hostname": hostname,
            "systemname": hostname,
            "ssid": ssid,
            "tower": str(tower),
            "tower_padded": tower_padded,
            "direction": direction,
            "direction_upper": direction_upper,
        }

    def render_template(
        self,
        template: Dict[str, Any],
        variables: Dict[str, str],
        device_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Render a config template with variable substitution.

        Uses two methods:
        1. Replace {{placeholder}} patterns in string values
        2. Inject values into known fields for the device type

        Args:
            template: Config template dictionary
            variables: Dictionary of variable names to values
            device_type: Device type for field injection (optional)

        Returns:
            Rendered config dictionary with values substituted
        """
        # First, replace any {{placeholder}} patterns
        rendered = self._render_dict(template, variables)

        # Then, inject into known fields for this device type
        if device_type and device_type in self.INJECT_FIELDS:
            rendered = self._inject_fields(rendered, variables, device_type)

        return rendered

    def _inject_fields(
        self,
        config: Dict[str, Any],
        variables: Dict[str, str],
        device_type: str,
    ) -> Dict[str, Any]:
        """Inject values into known fields for a device type.

        Args:
            config: Config dictionary to modify
            variables: Variable values to inject
            device_type: Device type for field mapping

        Returns:
            Modified config with injected values
        """
        fields = self.INJECT_FIELDS.get(device_type, [])

        for field_path, var_name in fields:
            if var_name not in variables:
                continue

            value = variables[var_name]

            try:
                self._set_nested_value(config, field_path, value)
                logger.debug(f"Injected {field_path} = {value}")
            except (KeyError, IndexError, TypeError) as e:
                logger.warning(f"Failed to inject {field_path}: {e}")

        return config

    def _set_nested_value(self, obj: Any, path: str, value: Any) -> None:
        """Set a value at a nested path, supporting array indices.

        Path examples:
        - "hostname" -> obj["hostname"] = value
        - "system.hostname" -> obj["system"]["hostname"] = value
        - "wireless.radios.wlan0.vaps[0].ssid" -> obj["wireless"]["radios"]["wlan0"]["vaps"][0]["ssid"] = value

        Args:
            obj: Root object to modify
            path: Dot-notation path with optional array indices
            value: Value to set
        """
        # Parse path into parts, handling array indices
        parts = self._parse_path(path)

        # Navigate to parent
        for part in parts[:-1]:
            if isinstance(part, int):
                obj = obj[part]
            else:
                if part not in obj:
                    obj[part] = {}
                obj = obj[part]

        # Set the final value
        final_part = parts[-1]
        if isinstance(final_part, int):
            obj[final_part] = value
        else:
            obj[final_part] = value

    def _parse_path(self, path: str) -> List[Any]:
        """Parse a dot-notation path into parts, extracting array indices.

        "wireless.radios.wlan0.vaps[0].ssid" ->
        ["wireless", "radios", "wlan0", "vaps", 0, "ssid"]

        Args:
            path: Dot-notation path string

        Returns:
            List of path parts (strings and integers for array indices)
        """
        parts = []
        for segment in path.split("."):
            # Check for array index: "vaps[0]" -> "vaps", 0
            if "[" in segment and segment.endswith("]"):
                bracket_pos = segment.index("[")
                key = segment[:bracket_pos]
                index = int(segment[bracket_pos + 1:-1])
                parts.append(key)
                parts.append(index)
            else:
                parts.append(segment)
        return parts

    def _render_dict(self, obj: Any, variables: Dict[str, str]) -> Any:
        """Recursively render placeholders in a dictionary/list/string."""
        if isinstance(obj, dict):
            return {k: self._render_dict(v, variables) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._render_dict(item, variables) for item in obj]
        elif isinstance(obj, str):
            return self._render_string(obj, variables)
        else:
            return obj

    def _render_string(self, text: str, variables: Dict[str, str]) -> str:
        """Replace {{placeholder}} patterns in a string."""
        def replace_var(match):
            var_name = match.group(1).strip()
            if var_name in variables:
                return variables[var_name]
            logger.warning(f"Unknown template variable: {{{{{var_name}}}}}")
            return match.group(0)  # Keep original if not found

        return re.sub(r"\{\{(\w+)\}\}", replace_var, text)


# Global instance
_ap_config_manager: Optional[APConfigManager] = None


def get_ap_config_manager() -> APConfigManager:
    """Get the global AP config manager instance."""
    if _ap_config_manager is None:
        raise RuntimeError("AP config manager not initialized")
    return _ap_config_manager


def init_ap_config_manager(templates_path: str) -> APConfigManager:
    """Initialize the global AP config manager.

    Args:
        templates_path: Path to config templates directory
    """
    global _ap_config_manager
    _ap_config_manager = APConfigManager(templates_path)
    return _ap_config_manager
