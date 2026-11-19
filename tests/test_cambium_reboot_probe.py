"""Regression tests for the Cambium post-reboot readiness probes.

Bench, 2026-10-14, port 2: an ePMP 4600 on 5.3.0.43 served HTTP only, so
``connect()`` fell back to ``http://``. After the upgrade to 5.11.1, HTTP
answered the login POST with an empty 307 redirect to HTTPS. The stale
``http://`` base URL made ``_check_login_ready()`` report ``no_response``
until the 360 s reboot wait expired, and the run failed with "Device did not
come back online after reboot" while the radio was up on HTTPS.
"""

import asyncio
from types import SimpleNamespace

from provisioner.handlers.cambium import CambiumHandler

IP = "169.254.1.1"


def _handler(base_url: str) -> CambiumHandler:
    h = CambiumHandler(
        ip=IP,
        credentials={"username": "admin", "password": "admin"},
        interface="enp3s0.1992",
    )
    h._base_url = base_url
    h._cookie_file = "/tmp/does-not-matter"
    return h


def _device(serves_https: bool):
    """Fake curl helpers for a device that serves HTTPS, or HTTP only."""

    async def probe(url):
        if url.startswith("https://"):
            return serves_https
        return True  # HTTP always answers (200 on 5.3, 307 on 5.11)

    async def curl(args, url, form_data=None):
        if url.startswith("https://") and serves_https:
            body = b'{"msg":"auth_failed","success":0}'
        elif url.startswith("http://") and not serves_https:
            body = b'{"stok":"abc","success":1}'
        else:
            body = b""  # 5.11 HTTP: empty 307 redirect body
        return SimpleNamespace(returncode=0), body, b""

    return probe, curl


async def test_web_check_switches_stale_http_base_to_https(monkeypatch):
    h = _handler(f"http://{IP}")
    probe, _ = _device(serves_https=True)
    monkeypatch.setattr(h, "_probe_http_status", probe)

    assert await h._check_web_server() is True
    assert h._base_url == f"https://{IP}"


async def test_web_check_keeps_http_for_http_only_firmware(monkeypatch):
    h = _handler(f"http://{IP}")
    probe, _ = _device(serves_https=False)
    monkeypatch.setattr(h, "_probe_http_status", probe)

    assert await h._check_web_server() is True
    assert h._base_url == f"http://{IP}"


async def test_web_check_down_leaves_base_url(monkeypatch):
    h = _handler(f"http://{IP}")

    async def down(url):
        return False

    monkeypatch.setattr(h, "_probe_http_status", down)

    assert await h._check_web_server() is False
    assert h._base_url == f"http://{IP}"


async def test_wait_for_reboot_after_http_to_https_upgrade(monkeypatch):
    h = _handler(f"http://{IP}")
    probe, curl = _device(serves_https=True)

    async def ping():
        return True

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(h, "_ping_device", ping)
    monkeypatch.setattr(h, "_probe_http_status", probe)
    monkeypatch.setattr(h, "_run_curl_with_stdin_config", curl)
    monkeypatch.setattr(asyncio, "sleep", no_sleep)

    assert await h.wait_for_reboot(timeout=5) is True
    assert h._base_url == f"https://{IP}"
