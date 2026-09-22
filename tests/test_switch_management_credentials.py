"""The bench switch login is its own secret, apart from the MikroTik device login."""

from provisioner import main
from provisioner.config import Config, ManagementNetworkConfig


def test_dedicated_switch_secret_wins_over_mikrotik_device_login():
    cfg = Config()
    cfg.credentials["mikrotik"].password = "device-login"
    cfg.network.management.switch_username = "bench"
    cfg.network.management.switch_password = "switch-login"
    assert main._switch_management_credentials(cfg) == ("bench", "switch-login")


def test_unset_switch_secret_keeps_mikrotik_fallback():
    cfg = Config()
    cfg.credentials["mikrotik"].username = "admin"
    cfg.credentials["mikrotik"].password = "device-login"
    assert main._switch_management_credentials(cfg) == ("admin", "device-login")


def test_switch_secret_expands_from_environment(monkeypatch):
    monkeypatch.setenv("PROVISIONER_SWITCH_PASSWORD", "from-env")
    mgmt = ManagementNetworkConfig(switch_password="${PROVISIONER_SWITCH_PASSWORD}")
    assert mgmt.switch_password == "from-env"


def test_missing_switch_env_var_falls_back(monkeypatch):
    monkeypatch.delenv("PROVISIONER_SWITCH_PASSWORD", raising=False)
    cfg = Config()
    cfg.network.management = ManagementNetworkConfig(
        switch_password="${PROVISIONER_SWITCH_PASSWORD}"
    )
    cfg.credentials["mikrotik"].password = "device-login"
    assert main._switch_management_credentials(cfg)[1] == "device-login"
