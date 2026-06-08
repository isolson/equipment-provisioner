"""Configuration management for Network Provisioner."""

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, ClassVar, Optional, Dict

import yaml
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Runtime-mutable device settings overrides (persisted across restarts).
# This file holds the subset of `device_settings.*` that the UI can edit at
# runtime (currently just `tarana.operator_id`). It is overlaid on top of
# `config.device_settings` after the YAML config is loaded, so UI edits
# survive a `systemctl restart provisioner-web`.
#
# Lives under /var/lib/provisioner (runtime state) rather than
# /etc/provisioner (install-time config) so we never round-trip user-edited
# YAML through PyYAML (which would drop comments/formatting). See PR #47.
DEVICE_SETTINGS_OVERRIDES_PATH = Path("/var/lib/provisioner/device-settings.json")


class ManagementNetworkConfig(BaseModel):
    """Management network configuration for switch-to-Pi communication."""
    enabled: bool = True  # Enable management IP on VLAN 1990
    ip: str = "192.168.88.10"  # Pi's management IP on VLAN 1990
    netmask: str = "255.255.255.0"
    switch_ip: Optional[str] = "192.168.88.1"  # Switch's IP on VLAN 1990 (for reference only)
    vlan: Optional[int] = 1990  # Management VLAN (tagged on trunk)


class NetworkConfig(BaseModel):
    """Network interface configuration."""
    interface: str = "eth0"
    mode: str = "vlan"  # "vlan" for multi-port, "simple" for single port DHCP
    scan_delay: int = Field(default=10, ge=1, le=60)
    device_boot_timeout: int = Field(default=90, ge=30, le=300)
    management: ManagementNetworkConfig = Field(default_factory=ManagementNetworkConfig)


class DeviceIPsConfig(BaseModel):
    """Known link-local IPs for device types."""
    cambium: str = "169.254.1.1"
    tachyon: str = "169.254.1.1"
    tarana: str = "169.254.100.1"
    ubiquiti: str = "192.168.1.20"
    mikrotik: str = "192.168.88.1"


class PortsConfig(BaseModel):
    """Port/VLAN configuration for multi-device provisioning."""
    vlan_start: int = Field(default=1991, ge=1, le=4094)
    num_ports: int = Field(default=6, ge=1, le=48)  # 6 ports for 8-port switch (7=WAN, 8=trunk)
    local_ip: str = "169.254.1.2"
    device_ips: DeviceIPsConfig = Field(default_factory=DeviceIPsConfig)


class SimpleModeConfig(BaseModel):
    """Simple mode configuration (single port, no managed switch).

    Used by the no-switch ThinkPad deployment. The base interface is treated
    as port 1 in PortManager; vendor link-local IPs are probed via the same
    DeviceLinkLocalIP.ALL list as multi-port mode, AND `subnet` is ARP-swept
    so already-DHCP'd devices are also discovered.
    """
    subnet: str = "192.168.1.0/24"


class DataConfig(BaseModel):
    """Local data directory configuration for firmware and configs."""
    local_path: str = "/var/lib/provisioner/repo"


class DeviceCredentials(BaseModel):
    """Credentials for a device type."""
    username: str = "admin"
    password: str = ""
    backup_password: str = ""  # Backup password to try if primary fails
    bootstrap_password: str = ""  # Fleet-wide bootstrap password (MikroTik ZTP)
    # Fleet-wide th-ext-join onboarding PSK (MikroTik ZTP). This is the
    # passphrase wireless extenders use to join a gateway's hidden onboarding
    # SSID, so it MUST be identical across the whole fleet (per base-flash.rsc
    # `$onboardingPass`). Defaults to bootstrap_password when unset, matching
    # the canonical bench tool's WIFI_ONBOARDING_PASS fallback.
    onboarding_password: str = ""

    @field_validator(
        "password", "backup_password", "bootstrap_password", "onboarding_password",
        mode="before",
    )
    @classmethod
    def expand_env_var(cls, v: str) -> str:
        """Expand environment variables in password."""
        if v and v.startswith("${") and v.endswith("}"):
            env_var = v[2:-1]
            return os.getenv(env_var, "")
        return v


class CambiumCredentials(DeviceCredentials):
    """Cambium default credentials (admin/admin)."""
    password: str = "admin"


class TachyonCredentials(DeviceCredentials):
    """Tachyon default credentials (root/admin)."""
    username: str = "root"
    password: str = "admin"


class UbiquitiCredentials(DeviceCredentials):
    """Ubiquiti default credentials (ubnt/ubnt)."""
    username: str = "ubnt"
    password: str = "ubnt"


class CredentialsConfig(BaseModel):
    """All device credentials."""
    cambium: DeviceCredentials = Field(default_factory=CambiumCredentials)
    mikrotik: DeviceCredentials = Field(default_factory=DeviceCredentials)
    tarana: DeviceCredentials = Field(default_factory=DeviceCredentials)
    tachyon: DeviceCredentials = Field(default_factory=TachyonCredentials)
    ubiquiti: DeviceCredentials = Field(default_factory=UbiquitiCredentials)


class NotificationsConfig(BaseModel):
    """Notification service configuration."""
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None

    @field_validator("slack_webhook", "discord_webhook", mode="before")
    @classmethod
    def expand_env_var(cls, v: Optional[str]) -> Optional[str]:
        """Expand environment variables."""
        if v and v.startswith("${") and v.endswith("}"):
            env_var = v[2:-1]
            return os.getenv(env_var)
        return v


class GPIOConfig(BaseModel):
    """GPIO pin configuration for LEDs and buzzer."""
    enabled: bool = True
    green_led: int = 7
    red_led: int = 8
    yellow_led: int = 9
    buzzer: int = 10


class DisplayConfig(BaseModel):
    """Display sleep/wake configuration."""
    sleep_timeout: int = Field(default=300, ge=0)  # 0 = disabled
    wake_on_connect: bool = True
    use_dpms: bool = True
    use_backlight: bool = True


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    file: str = "/var/log/provisioner.log"
    db: str = "/var/lib/provisioner/history.db"


class FirmwareSourceConfig(BaseModel):
    """Configuration for a single vendor firmware source."""
    enabled: bool = True
    check_interval: int = Field(default=86400, ge=300, le=604800)  # seconds (default 24h)
    auto_download: bool = False  # False = notify only, True = auto-download
    channel: str = "release"  # Vendor-specific channel (release/beta or long-term/stable/testing)
    include_beta: bool = False  # Deprecated: ignored
    models: list = Field(default_factory=list)  # Empty = all models

    @property
    def effective_channel(self) -> str:
        """Resolve the effective channel."""
        valid_channels = {"release", "beta", "long-term", "stable", "testing"}
        return self.channel if self.channel in valid_channels else "release"


def _default_firmware_sources():
    """Default firmware sources — Tachyon enabled, others stubbed."""
    return {
        "tachyon": FirmwareSourceConfig(enabled=True, auto_download=True),
        "mikrotik": FirmwareSourceConfig(enabled=True, auto_download=True, channel="long-term"),
        "ubiquiti": FirmwareSourceConfig(enabled=False),
        "cambium": FirmwareSourceConfig(enabled=False),
    }


class FirmwareCheckerConfig(BaseModel):
    """Automatic firmware checking configuration."""
    enabled: bool = True  # Enabled by default
    default_check_interval: int = Field(default=86400, ge=300)  # 24 hours
    default_auto_download: bool = False
    sources: Dict[str, FirmwareSourceConfig] = Field(default_factory=_default_firmware_sources)


class FirmwareConfig(BaseModel):
    """Firmware update configuration."""
    dual_bank_update: bool = True
    verify_after_reboot: bool = True
    reboot_wait_timeout: int = Field(default=180, ge=60, le=600)
    checker: FirmwareCheckerConfig = Field(default_factory=FirmwareCheckerConfig)


class FeaturesConfig(BaseModel):
    """Feature flags for untested or incomplete functionality.

    All flags default to False (disabled). Enable as features are tested.
    """
    mode_config: bool = False           # AP/PTP mode config endpoints
    config_backup: bool = False         # Config backup during provisioning
    device_overrides: bool = False      # MAC-based device override provisioning
    apply_config_ubiquiti: bool = False # Ubiquiti config application
    apply_config_tarana: bool = False   # Tarana config application (stub)


class TaranaDeviceConfig(BaseModel):
    """Tarana-specific provisioning settings."""
    operator_id: Optional[int] = None


class MikrotikDeviceConfig(BaseModel):
    """MikroTik-specific provisioning settings."""
    DEFAULT_ZTP_API_URL: ClassVar[str] = "https://wifi.infra.treehouse.mn"

    ztp_api_url: Optional[str] = DEFAULT_ZTP_API_URL  # ZTP API base URL (wifi-api ZTP service)
    ztp_api_key: Optional[str] = None  # API key for POST /ztp/mikrotik/register

    @field_validator("ztp_api_url", mode="before")
    @classmethod
    def default_ztp_api_url(cls, v: Optional[str]) -> str:
        """Fall back to the prod URL for blank/None values.

        Preset configs ship `ztp_api_url:` (loads as None), which would
        otherwise override the field default and break registration with
        'ztp_api_url not configured'. Normalize empty → default here.
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            return cls.DEFAULT_ZTP_API_URL
        return v

    @field_validator("ztp_api_key", mode="before")
    @classmethod
    def expand_env_var(cls, v: Optional[str]) -> Optional[str]:
        if v and v.startswith("${") and v.endswith("}"):
            env_var = v[2:-1]
            return os.environ.get(env_var, "")
        return v


class DeviceSettingsConfig(BaseModel):
    """Per-device-type provisioning settings."""
    tarana: TaranaDeviceConfig = Field(default_factory=TaranaDeviceConfig)
    mikrotik: MikrotikDeviceConfig = Field(default_factory=MikrotikDeviceConfig)


class EquipmentRegistryConfig(BaseModel):
    """Equipment registry — POST device metadata after successful provisioning."""
    url: Optional[str] = None
    api_key: Optional[str] = None

    @field_validator("api_key", mode="before")
    @classmethod
    def expand_env_var(cls, v: Optional[str]) -> Optional[str]:
        if v and v.startswith("${") and v.endswith("}"):
            env_var = v[2:-1]
            return os.getenv(env_var)
        return v


class AnalyticsConfig(BaseModel):
    """Analytics/telemetry configuration for central event reporting."""
    enabled: bool = False
    url: Optional[str] = None
    site_id: str = "default"
    api_key: Optional[str] = None

    @field_validator("api_key", mode="before")
    @classmethod
    def expand_env_var(cls, v: Optional[str]) -> Optional[str]:
        """Expand environment variables."""
        if v and v.startswith("${") and v.endswith("}"):
            env_var = v[2:-1]
            return os.getenv(env_var)
        return v


class Config(BaseModel):
    """Main configuration class."""
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    ports: PortsConfig = Field(default_factory=PortsConfig)
    simple_mode: SimpleModeConfig = Field(default_factory=SimpleModeConfig)
    data: DataConfig = Field(default_factory=DataConfig)
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    gpio: GPIOConfig = Field(default_factory=GPIOConfig)
    display: DisplayConfig = Field(default_factory=DisplayConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    firmware: FirmwareConfig = Field(default_factory=FirmwareConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    device_settings: DeviceSettingsConfig = Field(default_factory=DeviceSettingsConfig)
    equipment_registry: EquipmentRegistryConfig = Field(default_factory=EquipmentRegistryConfig)
    analytics: AnalyticsConfig = Field(default_factory=AnalyticsConfig)


def expand_env_vars(obj):
    """Recursively expand environment variables in a dict."""
    if isinstance(obj, dict):
        return {k: expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        pattern = re.compile(r'\$\{([^}]+)\}')
        def replacer(match):
            return os.getenv(match.group(1), match.group(0))
        return pattern.sub(replacer, obj)
    return obj


def _device_settings_overrides_path(path: Optional[Path] = None) -> Path:
    """Resolve the overrides file path, honoring runtime patches.

    Looks up ``DEVICE_SETTINGS_OVERRIDES_PATH`` from the module each call so
    tests can monkeypatch the constant without re-binding all default args.
    """
    if path is not None:
        return path
    import provisioner.config as _module
    return _module.DEVICE_SETTINGS_OVERRIDES_PATH


def load_device_settings_overrides(
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Read the device-settings overrides JSON file.

    Returns an empty dict if the file is missing, unreadable, or malformed —
    the YAML config defaults will be used in that case.
    """
    resolved = _device_settings_overrides_path(path)
    try:
        if not resolved.exists():
            return {}
        with open(resolved, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("device-settings overrides at %s is not a JSON object; ignoring", resolved)
            return {}
        return data
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to read device-settings overrides at %s: %s", resolved, e)
        return {}


def save_device_settings_overrides_dict(
    payload: Dict[str, Any],
    path: Optional[Path] = None,
) -> None:
    """Atomically write a dict to the device-settings overrides file.

    Use this when persisting only the fields the user actually edited
    (avoids snapshotting installer-time secrets that happen to live in the
    same in-memory subtree). Writes via temp file + rename so a crash
    cannot corrupt the file. The file is created with mode 0600.
    """
    resolved = _device_settings_overrides_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        prefix=".device-settings.",
        suffix=".json.tmp",
        dir=str(resolved.parent),
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, resolved)
    except Exception:
        # Best-effort cleanup of the temp file on failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def save_device_settings_overrides(
    settings: "DeviceSettingsConfig",
    path: Optional[Path] = None,
) -> None:
    """Atomically persist the full DeviceSettingsConfig to disk.

    Prefer ``save_device_settings_overrides_dict`` when only some fields
    have been edited — this helper snapshots the entire subtree and will
    shadow any value also set in ``config.yaml``.
    """
    save_device_settings_overrides_dict(settings.model_dump(mode="json"), path)


def apply_device_settings_overrides(
    config: "Config",
    path: Optional[Path] = None,
) -> None:
    """Overlay persisted device-settings overrides onto the in-memory config.

    Only fields present in the JSON file are applied; missing fields keep
    whatever value came from `config.yaml` (or the model default).
    """
    overrides = load_device_settings_overrides(path)
    if not overrides:
        return

    # Merge by re-validating the device_settings subtree. This keeps the
    # overlay schema-aware (unknown fields will be rejected by pydantic).
    current = config.device_settings.model_dump(mode="json")
    merged = _deep_merge_dict(current, overrides)
    try:
        config.device_settings = DeviceSettingsConfig.model_validate(merged)
    except Exception as e:
        logger.warning("Ignoring device-settings overrides — failed to apply: %s", e)


def _deep_merge_dict(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge overlay into base (overlay wins for scalar values)."""
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str = "config.yaml", env_file: str = ".env") -> Config:
    """Load configuration from YAML file and environment variables.

    Args:
        config_path: Path to the YAML configuration file.
        env_file: Path to the .env file for environment variables.

    Returns:
        Config object with all settings.
    """
    # Load environment variables from .env file
    env_path = Path(env_file)
    if env_path.exists():
        load_dotenv(env_path)

    # Load YAML configuration
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_file, "r") as f:
        raw_config = yaml.safe_load(f)

    # Expand environment variables
    expanded_config = expand_env_vars(raw_config)

    config = Config(**expanded_config)

    # Overlay runtime device-settings overrides (UI-editable, persisted).
    apply_device_settings_overrides(config)

    return config


# Global config instance (set by main.py)
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    if _config is None:
        raise RuntimeError("Configuration not loaded. Call load_config() first.")
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
