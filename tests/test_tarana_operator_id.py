"""Check operator ID limits before settings writes or provisioning work."""

import json
import re
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from test_operator_action_api import _client, _status
from test_setup_api import make_client


@pytest.mark.parametrize("operator_id", [-1, 16384, 1.5, "invalid"])
def test_settings_reject_invalid_operator_id(tmp_path, monkeypatch, operator_id):
    path = tmp_path / "device-settings.json"
    original = '{"tarana": {"operator_id": 42}}'
    path.write_text(original)
    monkeypatch.setattr("provisioner.config.DEVICE_SETTINGS_OVERRIDES_PATH", path)
    client, config, _ = make_client(tmp_path)
    config.device_settings.tarana.operator_id = 42

    response = client.put("/api/device-settings", json={"tarana": {"operator_id": operator_id}})

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "tarana", "operator_id"]
    assert config.device_settings.tarana.operator_id == 42
    assert path.read_text() == original


@pytest.mark.parametrize("operator_id", [0, 1, 8192, 16383, None])
def test_settings_accept_operator_id(tmp_path, monkeypatch, operator_id):
    path = tmp_path / "device-settings.json"
    monkeypatch.setattr("provisioner.config.DEVICE_SETTINGS_OVERRIDES_PATH", path)
    client, config, _ = make_client(tmp_path)

    response = client.put("/api/device-settings", json={"tarana": {"operator_id": operator_id}})

    assert response.status_code == 200
    assert config.device_settings.tarana.operator_id == operator_id
    assert json.loads(path.read_text())["tarana"]["operator_id"] == operator_id


@pytest.mark.parametrize("settings", [{}, {"tarana": {}}])
def test_settings_omitted_operator_id_preserves_value(tmp_path, monkeypatch, settings):
    path = tmp_path / "device-settings.json"
    monkeypatch.setattr("provisioner.config.DEVICE_SETTINGS_OVERRIDES_PATH", path)
    client, config, _ = make_client(tmp_path)
    config.device_settings.tarana.operator_id = 42

    assert client.put("/api/device-settings", json=settings).status_code == 200
    assert config.device_settings.tarana.operator_id == 42
    assert not path.exists()


@pytest.mark.parametrize("operator_id", [-1, 16384, 1.5, "invalid"])
def test_provision_rejects_operator_id_before_work(monkeypatch, operator_id):
    client = _client(monkeypatch, _status("tarana", "00:11:22:33:44:55"))
    run = AsyncMock()
    monkeypatch.setattr("provisioner.web.api._run_provisioning", run)

    response = client.post("/api/provision", json={"port_number": 4, "operator_id": operator_id})

    assert response.status_code == 422
    error = response.json()["detail"][0]
    assert error["loc"] == ["body", "operator_id"]
    if operator_id == -1:
        assert "greater than or equal to 0" in error["msg"]
    elif operator_id == 16384:
        assert "less than or equal to 16383" in error["msg"]
    run.assert_not_called()


@pytest.mark.parametrize("override", [{}, {"operator_id": None}, *[
    {"operator_id": value} for value in (0, 1, 8192, 16383)
]])
def test_provision_accepts_operator_id(monkeypatch, override):
    client = _client(monkeypatch, _status("tarana", "00:11:22:33:44:55"))
    run = AsyncMock()
    monkeypatch.setattr("provisioner.web.api._run_provisioning", run)

    response = client.post("/api/provision", json={"port_number": 4, **override})

    assert response.status_code == 200
    run.assert_awaited_once()
    assert run.call_args.args[4].operator_id == override.get("operator_id")


@pytest.mark.parametrize("template,input_id", [
    ("index.html", "operator-id"), ("files.html", "tarana-operator-id"),
])
def test_operator_id_input_limits(template, input_id):
    text = (Path(__file__).parents[1] / "provisioner/web/templates" / template).read_text()
    input_tag = re.search(r'<input\b[^>]*id="' + input_id + r'"[^>]*>', text).group()
    assert 'type="number"' in input_tag
    assert 'min="0"' in input_tag
    assert 'max="16383"' in input_tag
    assert "operatorId < 0 || operatorId > 16383" in text
