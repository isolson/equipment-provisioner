"""Tests for configuration loading and validation."""

import os
import pytest
import tempfile
from pathlib import Path

from provisioner.config import (
    Config,
    DeviceSettingsConfig,
    NetworkConfig,
    PortsConfig,
    DeviceCredentials,
    _default_credentials,
    FeaturesConfig,
    FirmwareConfig,
    FirmwareCheckerConfig,
    FirmwareSourceConfig,
    LabelPrinterConfig,
    apply_device_settings_overrides,
    load_config,
    load_device_settings_overrides,
    save_device_settings_overrides,
    save_device_settings_overrides_dict,
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
        assert config.device_ips.tarana == "169.254.100.1"
        assert config.device_ips.ubiquiti == "192.168.1.20"
        assert config.device_ips.mikrotik == "192.168.88.1"

    def test_device_ips_defaults_derive_from_registry(self):
        """DeviceIPsConfig fields/defaults derive from the vendor-IP registry
        (Story 4 / #74): each vendor's default is its primary registry IP,
        and field/serialization order matches the pre-registry typed class."""
        from provisioner.vendor_ips import VENDOR_LINK_LOCAL_IPS

        config = PortsConfig()
        assert list(type(config.device_ips).model_fields) == [
            "cambium",
            "tachyon",
            "tarana",
            "ubiquiti",
            "mikrotik",
        ]
        assert set(type(config.device_ips).model_fields) == set(
            VENDOR_LINK_LOCAL_IPS
        )
        for vendor, ips in VENDOR_LINK_LOCAL_IPS.items():
            assert getattr(config.device_ips, vendor) == ips[0]

    def test_device_ips_partial_override_keeps_other_defaults(self):
        """Overriding one vendor's IP in config.yaml must not lose the other
        vendors' defaults (pydantic backfills omitted typed fields)."""
        config = PortsConfig(device_ips={"mikrotik": "10.9.8.1"})
        assert config.device_ips.mikrotik == "10.9.8.1"
        assert config.device_ips.cambium == "169.254.1.1"
        assert config.device_ips.tachyon == "169.254.1.1"
        assert config.device_ips.tarana == "169.254.100.1"
        assert config.device_ips.ubiquiti == "192.168.1.20"

    def test_credentials_table_defaults(self):
        """The credentials table has correct vendor-specific defaults."""
        credentials = Config().credentials

        # Cambium: admin/admin
        assert credentials["cambium"].username == "admin"
        assert credentials["cambium"].password == "admin"

        # Tachyon: root/admin
        assert credentials["tachyon"].username == "root"
        assert credentials["tachyon"].password == "admin"

        # Ubiquiti: ubnt/ubnt
        assert credentials["ubiquiti"].username == "ubnt"
        assert credentials["ubiquiti"].password == "ubnt"

        # MikroTik: admin/empty
        assert credentials["mikrotik"].username == "admin"
        assert credentials["mikrotik"].password == ""

        # Tarana: admin/empty
        assert credentials["tarana"].username == "admin"
        assert credentials["tarana"].password == ""

    def test_default_credentials_factory_matches_config_defaults(self):
        """Config() with no credentials block equals the factory table."""
        factory = _default_credentials()
        credentials = Config().credentials
        assert set(credentials) == set(factory)
        for device_type, creds in factory.items():
            assert credentials[device_type] == creds

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
        assert config.credentials["tachyon"].username == "root"
        assert config.firmware.dual_bank_update is True
        assert config.label_printer.enabled is False

    def test_label_printer_config_defaults(self):
        """Label printing is opt-in and defaults to the Brady Web Bluetooth provider."""
        config = LabelPrinterConfig()
        assert config.enabled is False
        assert config.provider == "brady_web_bluetooth"
        assert config.auto_print_mikrotik_netinstall is True
        assert config.copies == 1


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
            assert config.credentials["tachyon"].username == "custom_user"
            assert config.credentials["tachyon"].password == "custom_pass"
            # Backfill: the other vendors keep their factory defaults even
            # though the YAML credentials block only listed tachyon.
            assert config.credentials["cambium"].password == "admin"
            assert config.credentials["ubiquiti"].username == "ubnt"
        finally:
            os.unlink(config_path)

    def test_load_config_with_label_printer(self):
        """Label printer settings load from YAML."""
        config_yaml = """
network:
  interface: eth0

label_printer:
  enabled: true
  provider: brady_web_bluetooth
  auto_print_mikrotik_netinstall: true
  copies: 2
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            config_path = f.name

        try:
            config = load_config(config_path)
            assert config.label_printer.enabled is True
            assert config.label_printer.provider == "brady_web_bluetooth"
            assert config.label_printer.auto_print_mikrotik_netinstall is True
            assert config.label_printer.copies == 2
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


class TestCredentialsBackfill:
    """Tests for the credentials-table backfill validator (Story 3 / #73).

    With a plain Dict field, a partial ``credentials:`` block in a host
    ``config.yaml`` would replace the whole dict and silently drop the other
    vendors' factory defaults. The ``Config`` before-validator deep-merges
    YAML over the ``_default_credentials()`` factory (defaults first, YAML
    wins per field). Only public factory logins appear here.
    """

    def _load(self, tmp_path, yaml_text):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml_text)
        # Point env_file at a nonexistent path so a developer's .env in the
        # working directory can't leak into these tests.
        return load_config(str(config_path), env_file=str(tmp_path / "no.env"))

    def test_partial_vendor_set_keeps_other_vendors_defaults(self, tmp_path):
        """credentials: with only mikrotik must not drop the other vendors."""
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  mikrotik:\n"
            "    username: admin\n"
            "    password: switch-pass\n",
        )
        assert config.credentials["mikrotik"].password == "switch-pass"
        # Factory defaults survive for every vendor the YAML didn't mention.
        assert config.credentials["cambium"].username == "admin"
        assert config.credentials["cambium"].password == "admin"
        assert config.credentials["tachyon"].username == "root"
        assert config.credentials["tachyon"].password == "admin"
        assert config.credentials["ubiquiti"].username == "ubnt"
        assert config.credentials["ubiquiti"].password == "ubnt"
        assert config.credentials["tarana"].username == "admin"

    def test_partial_fields_keep_vendor_defaults(self, tmp_path):
        """tachyon: {password: x} must keep the root username default."""
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  tachyon:\n"
            "    password: fleet-pass\n",
        )
        assert config.credentials["tachyon"].username == "root"
        assert config.credentials["tachyon"].password == "fleet-pass"

    def test_empty_credentials_block_yields_full_defaults(self, tmp_path):
        """A bare `credentials:` key (parses as None) keeps all defaults."""
        config = self._load(tmp_path, "network:\n  interface: eth0\ncredentials:\n")
        assert config.credentials == _default_credentials()

    def test_absent_credentials_block_yields_full_defaults(self, tmp_path):
        config = self._load(tmp_path, "network:\n  interface: eth0\n")
        assert config.credentials == _default_credentials()

    def test_bare_vendor_key_keeps_that_vendors_defaults(self, tmp_path):
        """`tachyon:` with no fields (parses as None) keeps its defaults."""
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  tachyon:\n"
            "  mikrotik:\n"
            "    password: switch-pass\n",
        )
        assert config.credentials["tachyon"].username == "root"
        assert config.credentials["tachyon"].password == "admin"
        assert config.credentials["mikrotik"].password == "switch-pass"

    def test_unknown_extra_vendor_key_is_preserved_harmlessly(self, tmp_path):
        """An unknown vendor key must not crash and must not affect others."""
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  netgear:\n"
            "    username: admin\n"
            "    password: password\n",
        )
        assert config.credentials["netgear"].username == "admin"
        assert config.credentials["netgear"].password == "password"
        # All known vendors are still present with their defaults.
        for device_type, creds in _default_credentials().items():
            assert config.credentials[device_type] == creds

    def test_ztp_extra_fields_survive_partial_merge(self, tmp_path):
        """bootstrap/onboarding/backup fields survive (main.py + api.py read
        them for MikroTik ZTP), and unset ones backfill to empty strings."""
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  mikrotik:\n"
            "    bootstrap_password: boot-pass\n",
        )
        mikrotik = config.credentials["mikrotik"]
        assert mikrotik.bootstrap_password == "boot-pass"
        assert mikrotik.username == "admin"
        assert mikrotik.password == ""
        assert mikrotik.backup_password == ""
        assert mikrotik.onboarding_password == ""

    def test_env_var_expansion_survives_in_table(self, tmp_path, monkeypatch):
        """${VAR} passwords expand inside the table; unset vars become ''."""
        monkeypatch.setenv("TEST_SWITCH_PASSWORD", "expanded-pass")
        monkeypatch.delenv("TEST_UNSET_PASSWORD_12345", raising=False)
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  mikrotik:\n"
            '    password: "${TEST_SWITCH_PASSWORD}"\n'
            "  cambium:\n"
            '    password: "${TEST_UNSET_PASSWORD_12345}"\n',
        )
        assert config.credentials["mikrotik"].password == "expanded-pass"
        # Unset env var: expand_env_vars leaves the literal ${...}, then the
        # DeviceCredentials validator maps it to empty.
        assert config.credentials["cambium"].password == ""

    def test_realistic_host_config_parses_identically(self, tmp_path):
        """A fixture mirroring /etc/provisioner/config.yaml (all vendors,
        env-var passwords) parses to the same shape as before Story 3."""
        config = self._load(
            tmp_path,
            "credentials:\n"
            "  cambium:\n"
            "    username: admin\n"
            '    password: "${CAMBIUM_PASSWORD}"\n'
            '    backup_password: "${CAMBIUM_BACKUP_PASSWORD}"\n'
            "  mikrotik:\n"
            "    username: admin\n"
            '    password: "${MIKROTIK_PASSWORD}"\n'
            '    bootstrap_password: "${MIKROTIK_BOOTSTRAP_PASS}"\n'
            '    onboarding_password: "${MIKROTIK_ONBOARDING_PASS}"\n'
            "  tarana:\n"
            "    username: admin\n"
            '    password: "${TARANA_PASSWORD}"\n'
            "  tachyon:\n"
            "    username: root\n"
            '    password: "${TACHYON_PASSWORD}"\n'
            "  ubiquiti:\n"
            "    username: ubnt\n"
            '    password: "${UBIQUITI_PASSWORD}"\n',
        )
        assert set(config.credentials) == {
            "cambium", "mikrotik", "tachyon", "tarana", "ubiquiti",
        }
        assert config.credentials["cambium"].username == "admin"
        assert config.credentials["mikrotik"].username == "admin"
        assert config.credentials["tachyon"].username == "root"
        assert config.credentials["tarana"].username == "admin"
        assert config.credentials["ubiquiti"].username == "ubnt"
        # With the env vars unset, every ${...} password resolves to empty —
        # same as the pre-Story-3 typed-field model.
        for device_type in ("cambium", "mikrotik", "tarana", "tachyon", "ubiquiti"):
            assert config.credentials[device_type].password == ""
        assert config.credentials["mikrotik"].bootstrap_password == ""

    def test_malformed_credentials_block_still_raises(self, tmp_path):
        """A non-mapping `credentials:` value (e.g. a YAML list) must still
        fail validation loudly, as the pre-Story-3 typed model did — the
        backfill must not silently swallow it into full defaults."""
        with pytest.raises(ValueError):
            self._load(
                tmp_path,
                "credentials:\n"
                "  - mikrotik\n"
                "  - cambium\n",
            )

    def test_getattr_on_credentials_table_returns_none(self):
        """Documents the dict-field failure mode: getattr-style consumers
        (the pre-Story-3 pattern) silently get None instead of credentials.
        Every consumer must use .get()/[] — see setup_tools and main.py."""
        credentials = Config().credentials
        assert getattr(credentials, "mikrotik", None) is None

    def test_programmatic_device_credentials_instances_pass_through(self):
        """Direct construction with DeviceCredentials values still works
        (used by tests and future callers), and other vendors backfill."""
        config = Config(
            credentials={"mikrotik": DeviceCredentials(username="admin", password="x")}
        )
        assert config.credentials["mikrotik"].password == "x"
        assert config.credentials["tachyon"].username == "root"


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


class TestDeviceSettingsOverridesPersistence:
    """Tests for runtime-editable device_settings persistence (PR #47 follow-up)."""

    def test_load_overrides_missing_file_returns_empty(self, tmp_path):
        overrides_path = tmp_path / "missing.json"
        assert load_device_settings_overrides(overrides_path) == {}

    def test_load_overrides_malformed_returns_empty(self, tmp_path):
        overrides_path = tmp_path / "bad.json"
        overrides_path.write_text("{not valid json")
        assert load_device_settings_overrides(overrides_path) == {}

    def test_save_then_load_round_trip(self, tmp_path):
        overrides_path = tmp_path / "device-settings.json"
        settings = DeviceSettingsConfig()
        settings.tarana.operator_id = 12345

        save_device_settings_overrides(settings, overrides_path)

        # File should exist with 0600 permissions and parsable JSON.
        assert overrides_path.exists()
        # On some filesystems mode bits may not stick; only assert if supported.
        mode = overrides_path.stat().st_mode & 0o777
        if mode != 0:
            assert mode == 0o600

        loaded = load_device_settings_overrides(overrides_path)
        assert loaded["tarana"]["operator_id"] == 12345

    def test_save_is_atomic_temp_file_cleaned_up(self, tmp_path):
        overrides_path = tmp_path / "device-settings.json"
        settings = DeviceSettingsConfig()
        settings.tarana.operator_id = 7
        save_device_settings_overrides(settings, overrides_path)
        # No stray .device-settings.*.json.tmp files left behind.
        leftovers = list(tmp_path.glob(".device-settings.*"))
        assert leftovers == []

    def test_apply_overrides_merges_into_config(self, tmp_path):
        overrides_path = tmp_path / "device-settings.json"
        overrides_path.write_text('{"tarana": {"operator_id": 99}}')

        config = Config()
        assert config.device_settings.tarana.operator_id is None
        apply_device_settings_overrides(config, overrides_path)
        assert config.device_settings.tarana.operator_id == 99

    def test_apply_overrides_preserves_unrelated_yaml_fields(self, tmp_path):
        """Overrides for one field must not wipe out adjacent settings."""
        overrides_path = tmp_path / "device-settings.json"
        overrides_path.write_text('{"tarana": {"operator_id": 42}}')

        config = Config()
        # Simulate something set from config.yaml at startup.
        config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"

        apply_device_settings_overrides(config, overrides_path)

        assert config.device_settings.tarana.operator_id == 42
        # Unrelated mikrotik field must survive the merge.
        assert config.device_settings.mikrotik.ztp_api_url == "https://wifi.example.test"

    def test_apply_overrides_missing_file_is_noop(self, tmp_path):
        config = Config()
        config.device_settings.tarana.operator_id = 5
        apply_device_settings_overrides(config, tmp_path / "absent.json")
        assert config.device_settings.tarana.operator_id == 5

    def test_save_dict_writes_only_supplied_fields(self, tmp_path):
        """Dict helper persists exactly what is passed (no shadowing of yaml)."""
        overrides_path = tmp_path / "device-settings.json"
        save_device_settings_overrides_dict(
            {"tarana": {"operator_id": 1}},
            overrides_path,
        )
        loaded = load_device_settings_overrides(overrides_path)
        assert loaded == {"tarana": {"operator_id": 1}}
