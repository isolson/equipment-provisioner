"""The bench switch login is its own secret, apart from the MikroTik device login."""

import sys
import types

import pytest

from provisioner import main, setup_tools
from provisioner.config import Config, ManagementNetworkConfig


@pytest.fixture(autouse=True)
def _no_host_switch_secret(monkeypatch):
    monkeypatch.delenv("PROVISIONER_SWITCH_PASSWORD", raising=False)


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


def test_unset_env_and_config_means_empty_switch_secret(monkeypatch):
    monkeypatch.delenv("PROVISIONER_SWITCH_PASSWORD", raising=False)
    assert ManagementNetworkConfig().switch_password == ""


def test_switch_secret_defaults_from_env_without_config_line(monkeypatch):
    # Hosts whose config.yaml predates the field still use the env secret.
    monkeypatch.setenv("PROVISIONER_SWITCH_PASSWORD", "from-env")
    cfg = Config()
    cfg.credentials["mikrotik"].password = "device-login"
    assert main._switch_management_credentials(cfg) == ("admin", "from-env")


def test_setup_probe_logs_in_with_switch_secret(monkeypatch):
    attempts = []

    def fake_connect(**kwargs):
        attempts.append((kwargs["username"], kwargs["password"]))
        raise OSError("stop after recording the login")

    monkeypatch.setitem(sys.modules, "librouteros", types.SimpleNamespace(connect=fake_connect))
    monkeypatch.setattr(setup_tools, "_tcp_connect", lambda host, port, timeout=1.5: True)
    cfg = Config()
    cfg.credentials["mikrotik"].password = "device-login"
    cfg.network.management.switch_username = "bench"
    cfg.network.management.switch_password = "switch-login"

    setup_tools.probe_mikrotik_switch(cfg)

    assert attempts[0] == ("bench", "switch-login")
    assert ("bench", "device-login") not in attempts
