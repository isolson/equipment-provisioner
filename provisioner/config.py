"""Configuration management for Network Provisioner."""

import os
import re
from pathlib import Path
from typing import Optional, Dict

import yaml
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv


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
    mikrotik: str = "192.168.88.1"


class PortsConfig(BaseModel):
    """Port/VLAN configuration for multi-device provisioning."""
    vlan_start: int = Field(default=1991, ge=1, le=4094)
    num_ports: int = Field(default=6, ge=1, le=48)  # 6 ports for 8-port switch (7=WAN, 8=trunk)
    local_ip: str = "169.254.1.2"
    device_ips: DeviceIPsConfig = Field(default_factory=DeviceIPsConfig)


class SimpleModeConfig(BaseModel):
    """Simple mode configuration (single port, DHCP)."""
    subnet: str = "192.168.1.0/24"


class DataConfig(BaseModel):
    """Local data directory configuration for firmware and configs."""
    local_path: str = "/var/lib/provisioner/repo"


class DeviceCredentials(BaseModel):
    """Credentials for a device type."""
    username: str = "admin"
    password: str = ""
    backup_password: str = ""  # Backup password to try if primary fails

    @field_validator("password", "backup_password", mode="before")
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


class CredentialsConfig(BaseModel):
    """All device credentials."""
    cambium: DeviceCredentials = Field(default_factory=CambiumCredentials)
    mikrotik: DeviceCredentials = Field(default_factory=DeviceCredentials)
    tarana: DeviceCredentials = Field(default_factory=DeviceCredentials)
    tachyon: DeviceCredentials = Field(default_factory=TachyonCredentials)


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


class FirmwareConfig(BaseModel):
    """Firmware update configuration."""
    dual_bank_update: bool = True
    verify_after_reboot: bool = True
    reboot_wait_timeout: int = Field(default=180, ge=60, le=600)


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

    return Config(**expanded_config)


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
