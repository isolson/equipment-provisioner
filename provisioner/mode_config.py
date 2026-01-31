"""Device mode configuration management (AP and PTP).

Handles loading config templates and generating device naming for
post-provisioning mode changes:

  * **AP mode** — tower number + direction (N/S/E/W)
  * **PTP mode** — my tower + remote tower, auto-assigned side A/B

Supports two template rendering strategies:
1. Placeholder mode: Replace ``{{variable}}`` patterns in config values
2. Field injection mode: Overwrite specific known fields per device type
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Valid modes
# ---------------------------------------------------------------------------

VALID_MODES = ("ap", "ptp-a", "ptp-b")

# ---------------------------------------------------------------------------
# ModeConfigManager
# ---------------------------------------------------------------------------


class ModeConfigManager:
    """Manages config templates and naming generation for AP and PTP modes."""

    # Valid directions for AP mode
    DIRECTIONS = ["north", "south", "east", "west"]

    # SSID patterns by device type — AP mode
    AP_SSID_PATTERNS: Dict[str, str] = {
        "tachyon": "{{direction_upper}}",            # "NORTH"
        "cambium": "tw{{tower_padded}}-{{direction}}",  # "tw05-north"
    }

    # SSID pattern for PTP mode (same for both sides, all device types)
    PTP_SSID_PATTERN = "tw{{my_tower_padded}}-tw{{remote_tower_padded}}"

    # Known fields to inject per device type.
    # Each entry: (json_path, variable_name)
    # json_path uses dot notation; array indices supported ("vaps[0].ssid").
    INJECT_FIELDS: Dict[str, List[Tuple[str, str]]] = {
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

    # Template filename mapping per mode
    _MODE_TEMPLATE_NAMES: Dict[str, str] = {
        "ap": "ap",
        "ptp-a": "ptp-a",
        "ptp-b": "ptp-b",
    }

    def __init__(self, templates_path: str):
        self.templates_path = Path(templates_path)

    # ------------------------------------------------------------------
    # Template loading
    # ------------------------------------------------------------------

    def get_template_path(
        self,
        device_type: str,
        mode: str,
        model: Optional[str] = None,
    ) -> Optional[Path]:
        """Get path to a mode config template.

        Search order:
        1. ``{templates}/{device_type}/{model}-{mode}.json``
        2. ``{templates}/{device_type}/{mode}.json``
        3. ``{templates}/{device_type}_{mode}.json`` (legacy)
        """
        base_name = self._MODE_TEMPLATE_NAMES.get(mode)
        if base_name is None:
            logger.error(f"Unknown mode: {mode}")
            return None

        device_dir = self.templates_path / device_type

        if device_dir.is_dir():
            # Model-specific template
            if model:
                for ext in (".json", ".tar", ".tar.gz"):
                    p = device_dir / f"{model.lower()}-{base_name}{ext}"
                    if p.exists():
                        return p

            # Default template in subdirectory
            for ext in (".json", ".tar", ".tar.gz"):
                p = device_dir / f"{base_name}{ext}"
                if p.exists():
                    return p

        # Legacy flat naming
        for ext in (".json", ".tar", ".tar.gz"):
            p = self.templates_path / f"{device_type}_{base_name}{ext}"
            if p.exists():
                return p

        logger.warning(f"No {mode} config template found for {device_type}")
        return None

    def load_template(
        self,
        device_type: str,
        mode: str,
        model: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Load a mode config template as a dictionary."""
        template_path = self.get_template_path(device_type, mode, model)
        if not template_path:
            return None

        try:
            if template_path.suffix in (".tar", ".gz"):
                import tarfile
                with tarfile.open(template_path, "r:*") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith("config.json") or member.name == "config.json":
                            f = tar.extractfile(member)
                            if f:
                                return json.load(f)
                logger.error(f"No config.json in tarball: {template_path}")
                return None

            with open(template_path, "r") as f:
                return json.load(f)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in template {template_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load template {template_path}: {e}")
            return None

    # ------------------------------------------------------------------
    # Backward-compatible AP helpers
    # ------------------------------------------------------------------

    def get_ap_template_path(
        self, device_type: str, model: Optional[str] = None
    ) -> Optional[Path]:
        """Get path to AP config template (backward-compatible alias)."""
        return self.get_template_path(device_type, "ap", model)

    def load_ap_template(
        self, device_type: str, model: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Load AP config template (backward-compatible alias)."""
        return self.load_template(device_type, "ap", model)

    # ------------------------------------------------------------------
    # Naming generation
    # ------------------------------------------------------------------

    def generate_ap_naming(
        self, tower: int, direction: str, device_type: str
    ) -> Dict[str, str]:
        """Generate naming variables for AP mode.

        Returns dict with keys: hostname, systemname, ssid, tower,
        tower_padded, direction, direction_upper.
        """
        if not 1 <= tower <= 99:
            raise ValueError(f"Tower number must be 1-99, got {tower}")

        direction = direction.lower().strip()
        if direction not in self.DIRECTIONS:
            raise ValueError(
                f"Direction must be one of {self.DIRECTIONS}, got '{direction}'"
            )

        tower_padded = f"{tower:02d}"
        direction_upper = direction.upper()
        hostname = f"tw{tower_padded}-{direction}"

        ssid_pattern = self.AP_SSID_PATTERNS.get(
            device_type, "tw{{tower_padded}}-{{direction}}"
        )
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

    # Keep old name as alias
    generate_naming = generate_ap_naming

    def generate_ptp_naming(
        self,
        my_tower: int,
        remote_tower: int,
        side: str,
        device_type: str,
    ) -> Dict[str, str]:
        """Generate naming variables for PTP mode.

        Naming convention:
          SSID (both sides): ``tw05-tw12``
          Hostname side A:   ``tw05a-tw12``
          Hostname side B:   ``tw05-tw12b``

        Args:
            my_tower: This device's tower number (1-99).
            remote_tower: Remote tower number (1-99).
            side: ``"a"`` or ``"b"``.
            device_type: Device type (for field injection selection).

        Returns:
            Dict with keys: hostname, systemname, ssid, my_tower,
            my_tower_padded, remote_tower, remote_tower_padded, side,
            ptp_ssid.
        """
        if not 1 <= my_tower <= 99:
            raise ValueError(f"my_tower must be 1-99, got {my_tower}")
        if not 1 <= remote_tower <= 99:
            raise ValueError(f"remote_tower must be 1-99, got {remote_tower}")

        side = side.lower().strip()
        if side not in ("a", "b"):
            raise ValueError(f"side must be 'a' or 'b', got '{side}'")

        my_padded = f"{my_tower:02d}"
        remote_padded = f"{remote_tower:02d}"

        # SSID is the same for both sides
        ptp_ssid = f"tw{my_padded}-tw{remote_padded}"

        # Hostname: side letter goes on *this* device's tower number
        if side == "a":
            hostname = f"tw{my_padded}a-tw{remote_padded}"
        else:
            hostname = f"tw{my_padded}-tw{remote_padded}b"

        return {
            "hostname": hostname,
            "systemname": hostname,
            "ssid": ptp_ssid,
            "my_tower": str(my_tower),
            "my_tower_padded": my_padded,
            "remote_tower": str(remote_tower),
            "remote_tower_padded": remote_padded,
            "side": side,
            "ptp_ssid": ptp_ssid,
        }

    # ------------------------------------------------------------------
    # Unified mode naming
    # ------------------------------------------------------------------

    def generate_mode_naming(
        self,
        mode: str,
        device_type: str,
        **kwargs,
    ) -> Dict[str, str]:
        """Generate naming variables for any mode.

        For AP mode pass ``tower`` and ``direction``.
        For PTP mode pass ``my_tower``, ``remote_tower``, and ``side``.
        """
        if mode == "ap":
            return self.generate_ap_naming(
                tower=kwargs["tower"],
                direction=kwargs["direction"],
                device_type=device_type,
            )
        elif mode in ("ptp-a", "ptp-b"):
            side = "a" if mode == "ptp-a" else "b"
            return self.generate_ptp_naming(
                my_tower=kwargs["my_tower"],
                remote_tower=kwargs["remote_tower"],
                side=side,
                device_type=device_type,
            )
        else:
            raise ValueError(f"Unknown mode: {mode}")

    # ------------------------------------------------------------------
    # Template rendering
    # ------------------------------------------------------------------

    def render_template(
        self,
        template: Dict[str, Any],
        variables: Dict[str, str],
        device_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Render a config template with variable substitution.

        1. Replace ``{{placeholder}}`` patterns in string values.
        2. Inject values into known fields for the device type.
        """
        rendered = self._render_dict(template, variables)

        if device_type and device_type in self.INJECT_FIELDS:
            rendered = self._inject_fields(rendered, variables, device_type)

        return rendered

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _inject_fields(
        self,
        config: Dict[str, Any],
        variables: Dict[str, str],
        device_type: str,
    ) -> Dict[str, Any]:
        fields = self.INJECT_FIELDS.get(device_type, [])
        for field_path, var_name in fields:
            if var_name not in variables:
                continue
            try:
                self._set_nested_value(config, field_path, variables[var_name])
                logger.debug(f"Injected {field_path} = {variables[var_name]}")
            except (KeyError, IndexError, TypeError) as e:
                logger.warning(f"Failed to inject {field_path}: {e}")
        return config

    def _set_nested_value(self, obj: Any, path: str, value: Any) -> None:
        parts = self._parse_path(path)
        for part in parts[:-1]:
            if isinstance(part, int):
                obj = obj[part]
            else:
                if part not in obj:
                    obj[part] = {}
                obj = obj[part]
        final = parts[-1]
        obj[final] = value

    def _parse_path(self, path: str) -> List[Any]:
        parts: List[Any] = []
        for segment in path.split("."):
            if "[" in segment and segment.endswith("]"):
                bracket_pos = segment.index("[")
                parts.append(segment[:bracket_pos])
                parts.append(int(segment[bracket_pos + 1:-1]))
            else:
                parts.append(segment)
        return parts

    def _render_dict(self, obj: Any, variables: Dict[str, str]) -> Any:
        if isinstance(obj, dict):
            return {k: self._render_dict(v, variables) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._render_dict(item, variables) for item in obj]
        elif isinstance(obj, str):
            return self._render_string(obj, variables)
        return obj

    def _render_string(self, text: str, variables: Dict[str, str]) -> str:
        def replace_var(match):
            var_name = match.group(1).strip()
            if var_name in variables:
                return variables[var_name]
            logger.warning(f"Unknown template variable: {{{{{var_name}}}}}")
            return match.group(0)
        return re.sub(r"\{\{(\w+)\}\}", replace_var, text)


# ---------------------------------------------------------------------------
# PTP link ID helper
# ---------------------------------------------------------------------------

def make_ptp_link_id(tower_a: int, tower_b: int) -> str:
    """Generate a canonical PTP link ID from two tower numbers.

    Always orders the smaller tower first so that both sides produce the
    same link ID regardless of which was configured first.
    """
    lo, hi = sorted((tower_a, tower_b))
    return f"tw{lo:02d}-tw{hi:02d}"


# ---------------------------------------------------------------------------
# Global instance (backward-compatible names retained)
# ---------------------------------------------------------------------------

_mode_config_manager: Optional[ModeConfigManager] = None


def get_mode_config_manager() -> ModeConfigManager:
    """Get the global mode config manager instance."""
    if _mode_config_manager is None:
        raise RuntimeError("Mode config manager not initialized")
    return _mode_config_manager


# Backward-compatible alias
get_ap_config_manager = get_mode_config_manager


def init_mode_config_manager(templates_path: str) -> ModeConfigManager:
    """Initialize the global mode config manager."""
    global _mode_config_manager
    _mode_config_manager = ModeConfigManager(templates_path)
    return _mode_config_manager


# Backward-compatible alias
init_ap_config_manager = init_mode_config_manager

# Keep old class name importable
APConfigManager = ModeConfigManager
