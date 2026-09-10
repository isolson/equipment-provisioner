from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from provisioner.web.app import create_app
from provisioner.web import network_modes


def setup_client(monkeypatch, busy=False, qualified=True):
    state = SimpleNamespace(provisioning=busy, provisioning_task=None, device_mac="00:00:00:00:00:01", device_mode=None, mode_config=None)
    status = {"device_detected": True, "device_type": "mikrotik", "device_ip": "192.0.2.1", "device_mac": state.device_mac, "device_model": "hEX S", "provisioning": busy, "needs_credentials": True}
    pm = SimpleNamespace(port_states={1: state}, get_port_status=lambda: {1: dict(status, provisioning=state.provisioning)}, get_interface_for_port=lambda n: "test1", begin_mode_job=lambda *a: "job", update_mode_job=lambda *a: None, finish_mode_job=lambda *a: None)
    pm.update_port_device_info = lambda *a, **kw: None
    pm.set_device_mode = lambda port, mode, config: setattr(state, "device_mode", mode)
    handler = SimpleNamespace(supports_network_modes=True, connect=AsyncMock(return_value=True), disconnect=AsyncMock(), get_info=AsyncMock(return_value=SimpleNamespace(serial_number="TEST-UNIT", firmware_version="7.23.5", model="hEX S")), network_mode_state=AsyncMock(return_value={"model":"hEX S","firmware":"7.23.5","mode":"router"}), validate_network_mode_layout=lambda s: None, network_mode_labels_for_model=lambda model: {"router":"Router","switch":"Switch"}, apply_network_mode=AsyncMock(return_value={"model":"hEX S","firmware":"7.23.5","mode":"switch"}))
    monkeypatch.setattr(network_modes.HandlerManager, "handler_class_for", lambda kind: handler)
    monkeypatch.setattr(network_modes, "qualified_modes", lambda *a: ("router", "switch") if qualified else ())
    monkeypatch.setattr(network_modes, "get_credential_override", lambda n: None)
    p = SimpleNamespace(port_manager=pm, handler_manager=SimpleNamespace(get_handler=lambda *a, **kw: handler))
    return TestClient(create_app(provisioner=p)), handler, state


def test_stale_device_token_refuses_write(monkeypatch):
    client, handler, state = setup_client(monkeypatch)
    response = client.post('/api/network-modes/1',json={"mode":"switch","device_token":"stale"})
    assert response.status_code == 409
    handler.apply_network_mode.assert_not_awaited()
    handler.disconnect.assert_awaited_once()
    assert not state.provisioning


def test_device_identity_change_after_preview_refuses_write(monkeypatch):
    client, handler, state = setup_client(monkeypatch)
    token = client.get('/api/network-modes/1').json()['device_token']
    handler.get_info.return_value = SimpleNamespace(serial_number="OTHER-UNIT", firmware_version="7.23.5", model="hEX S")
    assert client.post('/api/network-modes/1',json={"mode":"switch","device_token":token}).status_code == 409
    handler.apply_network_mode.assert_not_awaited()


def test_busy_port_is_not_contacted(monkeypatch):
    client, handler, state = setup_client(monkeypatch, busy=True)
    assert client.get('/api/network-modes/1').status_code == 409
    handler.connect.assert_not_awaited()
    assert state.provisioning


def test_unqualified_mode_is_not_applied(monkeypatch):
    client, handler, state = setup_client(monkeypatch, qualified=False)
    data = client.get('/api/network-modes/1').json()
    assert not data['choices']
    assert client.post('/api/network-modes/1',json={"mode":"switch","device_token":data['device_token']}).status_code == 409
    handler.apply_network_mode.assert_not_awaited()


def test_verified_mode_and_cleanup(monkeypatch):
    client, handler, state = setup_client(monkeypatch)
    data = client.get('/api/network-modes/1').json()
    response = client.post('/api/network-modes/1',json={"mode":"switch","device_token":data['device_token']})
    assert response.status_code == 200
    assert response.json()['verified']
    assert state.device_mode == 'switch'
    assert state.needs_credentials is False
    assert state.last_result is None
    assert not state.provisioning
    assert state.provisioning_task is None


def test_private_device_error_is_not_returned(monkeypatch):
    client, handler, state = setup_client(monkeypatch)
    data = client.get('/api/network-modes/1').json()
    handler.apply_network_mode.side_effect = RuntimeError('private-device-output')
    response = client.post('/api/network-modes/1',json={"mode":"switch","device_token":data['device_token']})
    assert response.status_code == 502
    assert 'private-device-output' not in response.text
    assert not state.provisioning
    assert handler.disconnect.await_count == 2


def test_page_renders(monkeypatch):
    client, _, _ = setup_client(monkeypatch)
    assert client.get('/network-modes').status_code == 200
