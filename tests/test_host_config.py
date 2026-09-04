"""In-place credential edits keep comments and never leak values."""

from pathlib import Path

import pytest
import yaml

from provisioner.host_config import set_credential_values

SAMPLE = """# provisioner host config
network:
  interface: eth0
credentials:
  cambium:
    username: admin
    password: "old-pw"   # bench
    backup_password: ""
  tachyon:
    username: root
    password: "tp"

ports:
  num_ports: 6
"""


def test_replaces_and_appends_keys_in_place(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(SAMPLE)
    changed = set_credential_values(path, "cambium", {"password": "new-pw", "wpa_key": "k1", "snmp_community": "c1"})
    assert sorted(changed) == ["password", "snmp_community", "wpa_key"]
    text = path.read_text()
    assert "# provisioner host config" in text and "# bench" not in text or "old-pw" not in text
    data = yaml.safe_load(text)
    assert data["credentials"]["cambium"] == {"username": "admin", "password": "new-pw", "backup_password": "", "wpa_key": "k1", "snmp_community": "c1"}
    assert data["credentials"]["tachyon"] == {"username": "root", "password": "tp"}
    assert data["ports"]["num_ports"] == 6
    assert list(tmp_path.glob("config.yaml.bak-*-credentials"))
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_adds_a_missing_vendor_block(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(SAMPLE)
    assert set_credential_values(path, "ubiquiti", {"wpa_key": "w"}) == ["wpa_key"]
    data = yaml.safe_load(path.read_text())
    assert data["credentials"]["ubiquiti"] == {"wpa_key": "w"}
    assert data["credentials"]["cambium"]["password"] == "old-pw"


def test_refuses_unknown_keys_and_vendors(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(SAMPLE)
    with pytest.raises(ValueError):
        set_credential_values(path, "cambium", {"api_token": "x"})
    with pytest.raises(ValueError):
        set_credential_values(path, "Cambium;rm", {"password": "x"})
    assert set_credential_values(path, "cambium", {"password": None}) == []
