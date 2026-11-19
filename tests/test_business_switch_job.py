"""Tests for the per-port business-switch site and unit job."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from provisioner.handler_manager import HandlerManager
from provisioner.web import api


class _SiteJobHandler:
    needs_site_job = True
    max_hostname_length = 15


def test_site_job_validation_checks_site_and_handler_hostname_limit(monkeypatch):
    monkeypatch.setattr(HandlerManager, "handler_class_for", lambda _kind: _SiteJobHandler)
    assert api._validate_business_switch_job("abc", 9, "fake") == "th.abc.sw09"

    for site in ("A1", "a", "abc-1", "a" * 13):
        with pytest.raises(HTTPException) as error:
            api._validate_business_switch_job(site, 1, "fake")
        assert error.value.status_code == 422

    with pytest.raises(HTTPException, match="hostname limit"):
        api._validate_business_switch_job("abcdefghijk", 99, "fake")


def test_start_validates_and_snapshots_the_opt_in_job(monkeypatch):
    from provisioner.web.app import create_app

    monkeypatch.setattr(HandlerManager, "handler_class_for", lambda _kind: _SiteJobHandler)
    captured = {}
    state = SimpleNamespace(business_switch_job=None)

    class Ports:
        port_states = {4: state}

        def get_port_status(self):
            return {
                4: {
                    "device_detected": True,
                    "device_type": "fake",
                    "device_ip": "192.0.2.4",
                    "device_mac": "aa:bb",
                    "device_serial": None,
                    "provisioning": False,
                }
            }

    async def capture(*args):
        captured["args"] = args

    monkeypatch.setattr(api, "_run_provisioning", capture)
    provisioner = SimpleNamespace(port_manager=Ports(), config=SimpleNamespace())
    client = TestClient(create_app(provisioner=provisioner))

    response = client.post("/api/provision", json={"port_number": 4, "site": "yard", "unit": 7})

    assert response.status_code == 200
    expected = {"site": "yard", "unit": 7, "mac": "aa:bb", "serial": None}
    assert captured["args"][-1] == expected
    assert state.business_switch_job == expected
    invalid = client.post(
        "/api/provision",
        json={"port_number": 4, "site": "invalid-site", "unit": 7},
    )
    assert invalid.status_code == 422
    retry = client.post("/api/provision", json={"port_number": 4})
    assert retry.status_code == 200
    assert captured["args"][-1] == expected


@pytest.mark.asyncio
async def test_provision_runner_keeps_job_for_credential_retry_then_clears():
    job = {"site": "yard", "unit": 7, "mac": "aa:bb", "serial": "SERIAL"}
    state = SimpleNamespace(
        needs_credentials=False,
        provisioning_task=None,
        expecting_reboot=False,
        business_switch_job=job,
    )

    class Ports:
        port_states = {4: state}

        def mark_port_provisioning(self, *_args, **_kwargs):
            return None

    class Provisioner:
        port_manager = Ports()

        async def _provision_port_device(self, *args, **kwargs):
            assert kwargs["business_switch_job"] == job
            state.needs_credentials = True
            return False

    request = api.ProvisionRequest(port_number=4)
    await api._run_provisioning(
        Provisioner(), 4, "fake", "192.0.2.4", request, dict(state.business_switch_job)
    )
    assert state.business_switch_job["site"] == "yard"

    async def successful_run(*_args, **_kwargs):
        state.needs_credentials = False
        return True

    Provisioner._provision_port_device = successful_run
    await api._run_provisioning(
        Provisioner(), 4, "fake", "192.0.2.4", request, dict(state.business_switch_job)
    )
    assert state.business_switch_job is None


def test_handler_without_site_job_trait_keeps_default_behavior(monkeypatch):
    from provisioner.fingerprint import DeviceFingerprint, DeviceType
    from provisioner.handlers.base import ProvisioningResult

    class PlainHandler:
        async def provision(self, **kwargs):
            self.received = kwargs
            return ProvisioningResult(success=True)

    handler = PlainHandler()
    manager = HandlerManager({})
    monkeypatch.setattr(manager, "get_handler", lambda *_args, **_kwargs: handler)
    fingerprint = DeviceFingerprint(device_type=DeviceType.TACHYON)

    result = asyncio.run(
        manager.provision_device(fingerprint=fingerprint, ip="192.0.2.4")
    )

    assert result.success
    assert not hasattr(handler, "business_switch_site")
    assert not hasattr(handler, "business_switch_unit")
    assert "business_switch_site" not in handler.received


def test_device_identity_change_clears_saved_job():
    from provisioner.port_manager import PortManager

    job = {"site": "yard", "unit": 7, "mac": "old-mac", "serial": "OLD-SERIAL"}
    state = SimpleNamespace(
        business_switch_job=job,
        checklist=SimpleNamespace(mac_address=None, serial_number=None),
    )
    manager = PortManager.__new__(PortManager)
    manager.port_states = {1: state}

    manager.update_port_device_info(1, mac="new-mac")

    assert state.business_switch_job is None
