"""Tests for the per-port business-switch site and unit job."""

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


def test_business_switch_job_set_get_and_clear():
    api.clear_business_switch_job(4)
    saved = api.set_business_switch_job(4, "yard", 7, "aa:bb", "SERIAL")
    assert saved == api.get_business_switch_job(4)
    api.clear_business_switch_job(4)
    assert api.get_business_switch_job(4) is None


def test_start_validates_and_snapshots_the_opt_in_job(monkeypatch):
    from provisioner.web.app import create_app

    api.clear_business_switch_job(4)
    monkeypatch.setattr(HandlerManager, "handler_class_for", lambda _kind: _SiteJobHandler)
    captured = {}

    class Ports:
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
    assert captured["args"][-1] == {"site": "yard", "unit": 7, "mac": "aa:bb", "serial": None}
    assert client.get("/api/business-switch-jobs/4").json() == {"site": "yard", "unit": 7}
    invalid = client.post(
        "/api/provision",
        json={"port_number": 4, "site": "invalid-site", "unit": 7},
    )
    assert invalid.status_code == 422
    api.clear_business_switch_job(4)


@pytest.mark.asyncio
async def test_provision_runner_keeps_job_for_credential_retry_then_clears():
    api.set_business_switch_job(4, "yard", 7, "aa:bb", "SERIAL")
    state = SimpleNamespace(needs_credentials=False, provisioning_task=None, expecting_reboot=False)

    class Ports:
        port_states = {4: state}

        def mark_port_provisioning(self, *_args, **_kwargs):
            return None

    class Provisioner:
        port_manager = Ports()

        async def _provision_port_device(self, *args, **kwargs):
            assert kwargs["business_switch_job"] == api.get_business_switch_job(4)
            state.needs_credentials = True
            return False

    request = api.ProvisionRequest(port_number=4)
    snapshot = api.get_business_switch_job(4)
    await api._run_provisioning(
        Provisioner(), 4, "fake", "192.0.2.4", request, snapshot
    )
    assert api.get_business_switch_job(4)["site"] == "yard"

    async def successful_run(*_args, **_kwargs):
        state.needs_credentials = False
        return True

    Provisioner._provision_port_device = successful_run
    snapshot = api.get_business_switch_job(4)
    await api._run_provisioning(
        Provisioner(), 4, "fake", "192.0.2.4", request, snapshot
    )
    assert api.get_business_switch_job(4) is None


def test_non_opt_in_handler_trait_is_off_by_default():
    from provisioner.handlers.base import BaseHandler

    assert BaseHandler.needs_site_job is False
    assert BaseHandler.max_hostname_length is None


def test_device_identity_change_clears_saved_job():
    from provisioner.port_manager import PortManager

    api.set_business_switch_job(1, "yard", 7, "old-mac", "OLD-SERIAL")
    state = SimpleNamespace(checklist=SimpleNamespace(mac_address=None, serial_number=None))
    manager = PortManager.__new__(PortManager)
    manager.port_states = {1: state}

    manager.update_port_device_info(1, mac="new-mac")

    assert api.get_business_switch_job(1) is None
