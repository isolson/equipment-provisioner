"""The bench switch login is its own secret, apart from the MikroTik device login."""

import subprocess
import sys
import types
from pathlib import Path

import pytest

from provisioner import main, setup_tools
from provisioner.config import Config, ManagementNetworkConfig


@pytest.fixture(autouse=True)
def _no_host_switch_secret(monkeypatch):
    monkeypatch.delenv("PROVISIONER_SWITCH_PASSWORD", raising=False)
    monkeypatch.delenv("PROVISIONER_SWITCH_USERNAME", raising=False)


SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _bash_functions(script, *names):
    """Return the source of the named functions in a bash script."""
    lines = (SCRIPTS / script).read_text().splitlines()
    out = []
    for name in names:
        start = lines.index(name + "() {")
        end = lines.index("}", start)
        out.extend(lines[start:end + 1])
    return "\n".join(out) + "\n"


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


def test_switch_username_defaults_from_environment(monkeypatch):
    monkeypatch.setenv("PROVISIONER_SWITCH_USERNAME", "bench")
    monkeypatch.setenv("PROVISIONER_SWITCH_PASSWORD", "from-env")
    cfg = Config()
    assert main._switch_management_credentials(cfg) == ("bench", "from-env")


def test_switch_username_expands_and_empty_means_admin(monkeypatch):
    monkeypatch.setenv("PROVISIONER_SWITCH_USERNAME", "bench")
    ref = "${PROVISIONER_SWITCH_USERNAME}"
    assert ManagementNetworkConfig(switch_username=ref).switch_username == "bench"
    monkeypatch.delenv("PROVISIONER_SWITCH_USERNAME")
    assert ManagementNetworkConfig(switch_username=ref).switch_username == "admin"
    assert ManagementNetworkConfig().switch_username == "admin"


@pytest.mark.parametrize("existing", [True, False])
def test_setup_switch_saves_username_with_password(tmp_path, existing):
    env_file = tmp_path / "provisioner.env"
    if existing:
        env_file.write_text(
            "PROVISIONER_SWITCH_USERNAME=old\nPROVISIONER_SWITCH_PASSWORD=old\n"
            "MIKROTIK_PASSWORD=device\n"
        )
    script = _bash_functions(
        "setup_switch.sh", "set_env_file_line", "save_password_to_env"
    )
    subprocess.run(
        [
            "bash", "-c",
            "log_info() { :; }\n" + script + 'save_password_to_env "$1" "$2"',
            "bash", "bench", "newpass",
        ],
        env={
            "PATH": "/usr/bin:/bin",
            "CONFIG_DIR": str(tmp_path),
            "ENV_FILE": str(env_file),
        },
        check=True,
        capture_output=True,
    )
    lines = env_file.read_text().splitlines()
    assert lines.count("PROVISIONER_SWITCH_USERNAME=bench") == 1
    assert lines.count("PROVISIONER_SWITCH_PASSWORD=newpass") == 1
    assert not any(line.endswith("=old") for line in lines)
    if existing:
        assert "MIKROTIK_PASSWORD=device" in lines


@pytest.mark.parametrize(
    "line, expected",
    [
        ("KEY=plain", "plain"),
        ("KEY=plain  ", "plain"),
        ("  KEY = spaced", "spaced"),
        ('KEY="pa\\"ss"', 'pa"ss'),
        ('KEY="a\\\\b"', "a\\b"),
        ('KEY="a\\$b\\`c"', "a$b`c"),
        ('KEY="a\\nb"', "a\\nb"),
        ("KEY='pa\\\"ss'", 'pa\\"ss'),
        ("KEY=pa\\\"ss", 'pa"ss'),
        ("KEY=trail\\ ", "trail "),
        ('KEY="quoted "', "quoted "),
        ("KEY=one\\\ntwo", "onetwo"),
        ('KEY="multi\nline"', "multi\nline"),
        ("# KEY=comment", ""),
        ("; KEY=comment", ""),
    ],
)
def test_update_switch_script_reads_systemd_env_syntax(tmp_path, line, expected):
    env_file = tmp_path / "provisioner.env"
    env_file.write_text("OTHER=x\n" + line + "\n")
    script = _bash_functions("update_switch_script.sh", "env_file_value")
    result = subprocess.run(
        ["bash", "-c", script + "env_file_value KEY", "bash"],
        env={"PATH": "/usr/bin:/bin", "ENV_FILE": str(env_file)},
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == expected


def test_update_switch_script_last_assignment_wins(tmp_path):
    env_file = tmp_path / "provisioner.env"
    env_file.write_text("KEY=first\nKEY='second'\n")
    script = _bash_functions("update_switch_script.sh", "env_file_value")
    result = subprocess.run(
        ["bash", "-c", script + "env_file_value KEY", "bash"],
        env={"PATH": "/usr/bin:/bin", "ENV_FILE": str(env_file)},
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == "second"
