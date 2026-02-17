"""Tests for configuration loading and validation."""

import os
import pytest
import tempfile
from pathlib import Path

from provisioner.config import (
    Config,
    NetworkConfig,
    PortsConfig,
    CredentialsConfig,
    DeviceCredentials,
    FeaturesConfig,
    FirmwareConfig,
    FirmwareCheckerConfig,
    FirmwareSourceConfig,
    load_config,
    expand_env_vars,
)


class TestConfigDefaults:
    """Tests for default configuration values."""

    def test_network_config_defaults(self):
        """Test NetworkConfig has correct defaults."""
        config = NetworkConfig()
        assert config.interface == "eth0"
        assert config.mode == "vlan"
        assert config.scan_delay == 10
        assert config.device_boot_timeout == 90

    def test_ports_config_defaults(self):
        """Test PortsConfig has correct defaults."""
        config = PortsConfig()
        assert config.vlan_start == 1991
        assert config.num_ports == 6
        assert config.local_ip == "169.254.1.2"
        assert config.device_ips.cambium == "169.254.1.1"
        assert config.device_ips.tachyon == "169.254.1.1"
        assert config.device_ips.ubiquiti == "192.168.1.20"
        assert config.device_ips.mikrotik == "192.168.88.1"

    def test_credentials_config_defaults(self):
        """Test CredentialsConfig has correct vendor-specific defaults."""
        config = CredentialsConfig()

        # Cambium: admin/admin
        assert config.cambium.username == "admin"
        assert config.cambium.password == "admin"

        # Tachyon: root/admin
        assert config.tachyon.username == "root"
        assert config.tachyon.password == "admin"

        # Ubiquiti: ubnt/ubnt
        assert config.ubiquiti.username == "ubnt"
        assert config.ubiquiti.password == "ubnt"

        # MikroTik: admin/empty
        assert config.mikrotik.username == "admin"
        assert config.mikrotik.password == ""

    def test_firmware_config_defaults(self):
        """Test FirmwareConfig has correct defaults."""
        config = FirmwareConfig()
        assert config.dual_bank_update is True
        assert config.verify_after_reboot is True
        assert config.reboot_wait_timeout == 180

    def test_firmware_checker_defaults(self):
        """Test FirmwareCheckerConfig has correct defaults."""
        config = FirmwareCheckerConfig()
        assert config.enabled is True
        assert config.default_check_interval == 86400  # 24 hours
        assert config.default_auto_download is False

        # Check default sources
        assert "tachyon" in config.sources
        assert "mikrotik" in config.sources
        assert config.sources["tachyon"].enabled is True
        assert config.sources["tachyon"].auto_download is True
        assert config.sources["mikrotik"].enabled is True
        assert config.sources["mikrotik"].auto_download is True
        assert config.sources["mikrotik"].channel == "long-term"

    def test_full_config_defaults(self):
        """Test full Config can be created with all defaults."""
        config = Config()
        assert config.network.interface == "eth0"
        assert config.ports.num_ports == 6
        assert config.credentials.tachyon.username == "root"
        assert config.firmware.dual_bank_update is True


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_scan_delay_validation(self):
        """Test scan_delay bounds validation."""
        # Valid values
        NetworkConfig(scan_delay=1)
        NetworkConfig(scan_delay=30)
        NetworkConfig(scan_delay=60)

        # Invalid values
        with pytest.raises(ValueError):
            NetworkConfig(scan_delay=0)
        with pytest.raises(ValueError):
            NetworkConfig(scan_delay=61)

    def test_vlan_start_validation(self):
        """Test VLAN start bounds validation."""
        # Valid values
        PortsConfig(vlan_start=1)
        PortsConfig(vlan_start=1991)
        PortsConfig(vlan_start=4094)

        # Invalid values
        with pytest.raises(ValueError):
            PortsConfig(vlan_start=0)
        with pytest.raises(ValueError):
            PortsConfig(vlan_start=4095)

    def test_num_ports_validation(self):
        """Test num_ports bounds validation."""
        # Valid values
        PortsConfig(num_ports=1)
        PortsConfig(num_ports=24)
        PortsConfig(num_ports=48)

        # Invalid values
        with pytest.raises(ValueError):
            PortsConfig(num_ports=0)
        with pytest.raises(ValueError):
            PortsConfig(num_ports=49)

    def test_reboot_wait_timeout_validation(self):
        """Test reboot_wait_timeout bounds validation."""
        # Valid values
        FirmwareConfig(reboot_wait_timeout=60)
        FirmwareConfig(reboot_wait_timeout=300)
        FirmwareConfig(reboot_wait_timeout=600)

        # Invalid values
        with pytest.raises(ValueError):
            FirmwareConfig(reboot_wait_timeout=59)
        with pytest.raises(ValueError):
            FirmwareConfig(reboot_wait_timeout=601)


class TestEnvVarExpansion:
    """Tests for environment variable expansion."""

    def test_expand_simple_env_var(self):
        """Test expanding simple environment variables."""
        os.environ["TEST_VAR"] = "test_value"

        result = expand_env_vars("${TEST_VAR}")
        assert result == "test_value"

        del os.environ["TEST_VAR"]

    def test_expand_env_var_in_dict(self):
        """Test expanding environment variables in dictionaries."""
        os.environ["TEST_PASSWORD"] = "secret123"

        data = {"password": "${TEST_PASSWORD}", "username": "admin"}
        result = expand_env_vars(data)

        assert result["password"] == "secret123"
        assert result["username"] == "admin"

        del os.environ["TEST_PASSWORD"]

    def test_expand_env_var_in_nested_dict(self):
        """Test expanding environment variables in nested structures."""
        os.environ["WEBHOOK_URL"] = "https://example.com/webhook"

        data = {
            "notifications": {
                "slack_webhook": "${WEBHOOK_URL}",
            }
        }
        result = expand_env_vars(data)

        assert result["notifications"]["slack_webhook"] == "https://example.com/webhook"

        del os.environ["WEBHOOK_URL"]

    def test_expand_env_var_in_list(self):
        """Test expanding environment variables in lists."""
        os.environ["ITEM1"] = "value1"
        os.environ["ITEM2"] = "value2"

        data = ["${ITEM1}", "${ITEM2}", "literal"]
        result = expand_env_vars(data)

        assert result == ["value1", "value2", "literal"]

        del os.environ["ITEM1"]
        del os.environ["ITEM2"]

    def test_undefined_env_var_kept_as_is(self):
        """Test that undefined env vars are kept as original string."""
        result = expand_env_vars("${UNDEFINED_VAR_12345}")
        assert result == "${UNDEFINED_VAR_12345}"

    def test_credential_env_var_expansion(self):
        """Test environment variable expansion in credentials."""
        os.environ["DEVICE_PASSWORD"] = "secure_password"

        cred = DeviceCredentials(username="admin", password="${DEVICE_PASSWORD}")
        assert cred.password == "secure_password"

        del os.environ["DEVICE_PASSWORD"]


class TestConfigLoading:
    """Tests for loading configuration from files."""

    def test_load_config_file_not_found(self):
        """Test error when config file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_load_minimal_config(self):
        """Test loading a minimal valid config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("network:\n  interface: eth1\n")
            config_path = f.name

        try:
            config = load_config(config_path)
            assert config.network.interface == "eth1"
            # Defaults should be applied for missing fields
            assert config.ports.num_ports == 6
        finally:
            os.unlink(config_path)

    def test_load_config_with_credentials(self):
        """Test loading config with custom credentials."""
        config_yaml = """
network:
  interface: eth0

credentials:
  tachyon:
    username: custom_user
    password: custom_pass
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            config_path = f.name

        try:
            config = load_config(config_path)
            assert config.credentials.tachyon.username == "custom_user"
            assert config.credentials.tachyon.password == "custom_pass"
        finally:
            os.unlink(config_path)

    def test_load_config_with_env_file(self):
        """Test loading config with .env file."""
        # Create .env file
        env_content = "TEST_API_KEY=my_api_key\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            env_path = f.name

        # Create config file referencing env var
        config_yaml = """
network:
  interface: eth0

analytics:
  enabled: true
  api_key: ${TEST_API_KEY}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            config_path = f.name

        try:
            config = load_config(config_path, env_file=env_path)
            assert config.analytics.api_key == "my_api_key"
        finally:
            os.unlink(config_path)
            os.unlink(env_path)
            # Clean up env var that dotenv loaded
            if "TEST_API_KEY" in os.environ:
                del os.environ["TEST_API_KEY"]


class TestFirmwareSourceConfig:
    """Tests for firmware source configuration."""

    def test_effective_channel_release(self):
        """Test effective channel returns release for valid values."""
        config = FirmwareSourceConfig(channel="release")
        assert config.effective_channel == "release"

    def test_effective_channel_beta(self):
        """Test effective channel returns beta for beta setting."""
        config = FirmwareSourceConfig(channel="beta")
        assert config.effective_channel == "beta"

    def test_effective_channel_long_term(self):
        """Test effective channel supports MikroTik long-term channel."""
        config = FirmwareSourceConfig(channel="long-term")
        assert config.effective_channel == "long-term"

    def test_effective_channel_invalid_defaults_to_release(self):
        """Test effective channel defaults to release for invalid values."""
        config = FirmwareSourceConfig(channel="invalid")
        assert config.effective_channel == "release"

    def test_check_interval_validation(self):
        """Test check_interval bounds validation."""
        # Valid values
        FirmwareSourceConfig(check_interval=300)  # 5 min (minimum)
        FirmwareSourceConfig(check_interval=86400)  # 24 hours
        FirmwareSourceConfig(check_interval=604800)  # 7 days (maximum)

        # Invalid values
        with pytest.raises(ValueError):
            FirmwareSourceConfig(check_interval=299)
        with pytest.raises(ValueError):
            FirmwareSourceConfig(check_interval=604801)


class TestFeaturesConfig:
    """Tests for feature flags configuration."""

    def test_all_flags_default_to_false(self):
        """All feature flags should default to disabled."""
        config = FeaturesConfig()
        assert config.mode_config is False
        assert config.config_backup is False
        assert config.device_overrides is False
        assert config.apply_config_ubiquiti is False
        assert config.apply_config_tarana is False

    def test_flags_can_be_enabled(self):
        """Feature flags can be set to True."""
        config = FeaturesConfig(
            mode_config=True,
            config_backup=True,
            device_overrides=True,
            apply_config_ubiquiti=True,
            apply_config_tarana=True,
        )
        assert config.mode_config is True
        assert config.config_backup is True
        assert config.device_overrides is True
        assert config.apply_config_ubiquiti is True
        assert config.apply_config_tarana is True

    def test_full_config_includes_features(self):
        """Config object should include features with defaults."""
        config = Config()
        assert hasattr(config, "features")
        assert config.features.mode_config is False
        assert config.features.apply_config_ubiquiti is False

    def test_load_config_with_features(self):
        """Features section loads correctly from YAML."""
        config_yaml = """
network:
  interface: eth0

features:
  mode_config: true
  apply_config_ubiquiti: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            config_path = f.name

        try:
            config = load_config(config_path)
            assert config.features.mode_config is True
            assert config.features.apply_config_ubiquiti is True
            # Unset flags should still default to False
            assert config.features.config_backup is False
            assert config.features.device_overrides is False
            assert config.features.apply_config_tarana is False
        finally:
            os.unlink(config_path)

    def test_features_model_dump(self):
        """Features should serialize correctly for API responses."""
        config = FeaturesConfig(mode_config=True)
        dumped = config.model_dump()
        assert dumped == {
            "mode_config": True,
            "config_backup": False,
            "device_overrides": False,
            "apply_config_ubiquiti": False,
            "apply_config_tarana": False,
        }
