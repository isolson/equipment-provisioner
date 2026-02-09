"""Tests for MikroTik detection path and checklist fields used by UI."""

import socket

import pytest

from provisioner.fingerprint import DeviceFingerprinter, DeviceType
from provisioner.port_manager import ProvisioningChecklist


class _FakeBoundSocket:
    def __init__(self, open_ports=None, banner=b""):
        self._open_ports = open_ports or set()
        self._banner = banner

    def setsockopt(self, *_args, **_kwargs):
        return None

    def settimeout(self, _timeout):
        return None

    def connect_ex(self, addr):
        return 0 if addr[1] in self._open_ports else 1

    def connect(self, addr):
        if addr[1] not in self._open_ports:
            raise OSError("connection refused")
        return None

    def recv(self, _size):
        return self._banner

    def close(self):
        return None


@pytest.mark.asyncio
async def test_interface_scan_detects_mikrotik_api_port(monkeypatch):
    """When interface binding is used, non-HTTP MikroTik API ports should be detected."""
    fingerprinter = DeviceFingerprinter(interface="eth0.1992")
    fingerprinter.PROBE_PORTS = {8728: "routeros_api"}

    monkeypatch.setattr(
        "provisioner.fingerprint._create_bound_socket",
        lambda _iface, family=socket.AF_INET: _FakeBoundSocket(open_ports={8728}),
    )

    open_ports = await fingerprinter._scan_ports("192.168.88.1")
    assert open_ports == [8728]


@pytest.mark.asyncio
async def test_interface_ssh_banner_probe_identifies_mikrotik(monkeypatch):
    """SSH banner probe should respect interface binding and identify MikroTik."""
    fingerprinter = DeviceFingerprinter(interface="eth0.1992")

    monkeypatch.setattr(
        "provisioner.fingerprint._create_bound_socket",
        lambda _iface, family=socket.AF_INET: _FakeBoundSocket(
            open_ports={22},
            banner=b"SSH-2.0-ROSSSH MikroTik\r\n",
        ),
    )

    result = await fingerprinter._probe_ssh_banner("192.168.88.1")
    assert result is not None
    assert result[0] == DeviceType.MIKROTIK


def test_checklist_includes_config_verify_for_ui():
    """UI relies on config_verify state; ensure checklist serializes it."""
    checklist = ProvisioningChecklist(config_verify="loading")
    data = checklist.to_dict()

    assert "config_verify" in data
    assert data["config_verify"] == "loading"

    checklist.reset()
    assert checklist.config_verify is None
