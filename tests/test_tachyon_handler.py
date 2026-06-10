"""Regression tests for the Tachyon false-success bug.

Production regression: the Tachyon handler reported that it uploaded the config and
firmware (UI showed COMPLETE) when the device had not actually received them.

Root cause: in production, Tachyon devices are reached over a VLAN-isolated ``interface``,
so ``connect()`` takes the curl branch and sets ``_use_curl=True``. Both config-apply and
firmware-upload therefore run through the curl helpers, which call ``curl -s -k`` with no
``-f``/``--fail``. curl exits 0 even on HTTP 4xx/5xx, and on a non-JSON/empty body the
helpers logged and fell through to ``return True`` — reporting success while nothing was
uploaded/applied.

These tests drive the curl helpers with simulated device responses using the repo's
``asyncio.create_subprocess_exec`` mock idiom (see tests/test_setup_api.py). They are RED
against the original handler and GREEN after the fix.

Python 3.9 — no 3.10+ syntax.
"""

from typing import Callable, List, Tuple

import pytest

from provisioner.handlers.tachyon import TachyonHandler


# ---------------------------------------------------------------------------------------
# Mock plumbing: a fake asyncio.create_subprocess_exec driven by a per-test "responder".
# ---------------------------------------------------------------------------------------

# Must match the HTTP-status sentinel the handler appends via ``curl -w`` (see _run_curl).
_STATUS_MARKER = "HTTPSTATUS:"


def mk_stdout(body: str, http_code) -> str:
    """Build curl stdout the way ``curl -w '\\nHTTPSTATUS:%{http_code}'`` would.

    ``http_code=None`` simulates curl producing no status line (e.g. transport failure).
    """
    if http_code is None:
        return body
    return body + "\n" + _STATUS_MARKER + str(http_code)


class DummyProc:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self._stdout = stdout.encode("utf-8")
        self._stderr = stderr.encode("utf-8")

    async def communicate(self):
        return (self._stdout, self._stderr)


def method_of(cmd: List[str]) -> str:
    """Pull the HTTP method out of a curl argv (the value after ``-X``)."""
    if "-X" in cmd:
        return cmd[cmd.index("-X") + 1]
    return "GET"


# Responder: (cmd argv) -> (returncode, stdout_str, stderr_str)
Responder = Callable[[List[str]], Tuple[int, str, str]]


def install_fake_exec(monkeypatch, responder: Responder) -> List[List[str]]:
    """Patch asyncio.create_subprocess_exec; return the list of captured argv lists."""
    captured: List[List[str]] = []

    async def fake_exec(*cmd, **kwargs):
        argv = list(cmd)
        captured.append(argv)
        rc, out, err = responder(argv)
        return DummyProc(rc, out, err)

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    return captured


def make_handler(interface: str = "eth0") -> TachyonHandler:
    """A handler in the production-shaped state: interface-bound, curl mode, logged in."""
    h = TachyonHandler(
        ip="169.254.1.1",
        credentials={"username": "root", "password": "admin"},
        interface=interface,
    )
    h._connected = True
    h._use_curl = True
    h._api_token = "tok-123"
    return h


# A config that carries a hostname so apply_config()'s read-back verification runs.
CONFIG_WITH_HOSTNAME = {"system": {"hostname": "new-host"}}
# A config with no hostname/SSID — read-back is skipped, so the POST response is the only gate.
CONFIG_NO_VERIFY_FIELDS = {"system": {"timezone": "UTC"}}


# ---------------------------------------------------------------------------------------
# Firmware upload — _upload_firmware_curl()
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_firmware_upload_empty_body_is_failure(monkeypatch, tmp_path):
    """Empty 200 body must NOT be reported as a successful upload (the regression)."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout("", 200), ""))

    handler = make_handler()
    assert await handler._upload_firmware_curl(str(fw)) is False


@pytest.mark.asyncio
async def test_firmware_upload_non_json_body_is_failure(monkeypatch, tmp_path):
    """An HTML / auth-redirect page returned with 200 must be a failure, not success."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    body = "<html><body>Session expired, please log in</body></html>"
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout(body, 200), ""))

    handler = make_handler()
    assert await handler._upload_firmware_curl(str(fw)) is False


@pytest.mark.asyncio
async def test_firmware_upload_http_error_is_failure(monkeypatch, tmp_path):
    """curl -s exits 0 on HTTP 5xx; the handler must still treat it as a failure."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout("Internal Server Error", 500), ""))

    handler = make_handler()
    assert await handler._upload_firmware_curl(str(fw)) is False


@pytest.mark.asyncio
async def test_firmware_upload_error_marker_json_is_failure(monkeypatch, tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    body = '{"statusCode":401,"error":{"details":"Authorization Failed"}}'
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout(body, 200), ""))

    handler = make_handler()
    assert await handler._upload_firmware_curl(str(fw)) is False


@pytest.mark.asyncio
async def test_firmware_upload_curl_transport_failure_is_failure(monkeypatch, tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    install_fake_exec(monkeypatch, lambda cmd: (7, "", "curl: (7) Failed to connect"))

    handler = make_handler()
    assert await handler._upload_firmware_curl(str(fw)) is False


@pytest.mark.asyncio
async def test_firmware_upload_documented_success_is_true(monkeypatch, tmp_path):
    """Documented success body {"version":"unknown"} with HTTP 200 -> True. Uses PUT + -F."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    captured = install_fake_exec(
        monkeypatch, lambda cmd: (0, mk_stdout('{"version":"unknown"}', 200), "")
    )

    handler = make_handler()
    assert await handler._upload_firmware_curl(str(fw)) is True

    argv = captured[-1]
    assert method_of(argv) == "PUT"
    assert any(a == "fw=@" + str(fw) for a in argv)


# ---------------------------------------------------------------------------------------
# Config apply — _apply_config_curl()
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_apply_empty_body_is_failure(monkeypatch):
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout("", 200), ""))
    handler = make_handler()
    assert await handler._apply_config_curl(CONFIG_WITH_HOSTNAME) is False


@pytest.mark.asyncio
async def test_config_apply_non_json_body_is_failure(monkeypatch):
    body = "<html>login</html>"
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout(body, 200), ""))
    handler = make_handler()
    assert await handler._apply_config_curl(CONFIG_WITH_HOSTNAME) is False


@pytest.mark.asyncio
async def test_config_apply_http_error_is_failure(monkeypatch):
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout("Forbidden", 403), ""))
    handler = make_handler()
    assert await handler._apply_config_curl(CONFIG_WITH_HOSTNAME) is False


@pytest.mark.asyncio
async def test_config_apply_status_code_error_is_failure(monkeypatch):
    body = '{"statusCode":400,"error":{"details":"bad config"}}'
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout(body, 200), ""))
    handler = make_handler()
    assert await handler._apply_config_curl(CONFIG_WITH_HOSTNAME) is False


@pytest.mark.asyncio
async def test_config_apply_clean_json_is_true(monkeypatch):
    """A clean JSON ack with HTTP 200 -> True. Uses POST."""
    captured = install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout("{}", 200), ""))
    handler = make_handler()
    assert await handler._apply_config_curl(CONFIG_WITH_HOSTNAME) is True
    assert method_of(captured[-1]) == "POST"


# ---------------------------------------------------------------------------------------
# Low-level API request — _api_request_curl() must surface HTTP errors
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_request_curl_raises_on_http_error(monkeypatch):
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout("nope", 502), ""))
    handler = make_handler()
    with pytest.raises(Exception):
        await handler._api_request_curl("GET", handler.API_CONFIG)


@pytest.mark.asyncio
async def test_api_request_curl_returns_parsed_json_on_200(monkeypatch):
    install_fake_exec(monkeypatch, lambda cmd: (0, mk_stdout('{"system":{"hostname":"x"}}', 200), ""))
    handler = make_handler()
    result = await handler._api_request_curl("GET", handler.API_CONFIG)
    assert result["system"]["hostname"] == "x"


# ---------------------------------------------------------------------------------------
# apply_config() end-to-end: read-back verification must be mandatory and fatal
# ---------------------------------------------------------------------------------------

def _post_then_get(post_resp: Tuple[int, str, str], get_resp: Tuple[int, str, str]) -> Responder:
    """Responder that answers POST (config apply) and GET (read-back) differently."""

    def responder(cmd: List[str]) -> Tuple[int, str, str]:
        return post_resp if method_of(cmd) == "POST" else get_resp

    return responder


@pytest.mark.asyncio
async def test_apply_config_fails_when_readback_raises(monkeypatch):
    """POST succeeds but the read-back GET errors -> apply_config must fail (not swallow)."""
    responder = _post_then_get(
        post_resp=(0, mk_stdout("{}", 200), ""),          # POST ok
        get_resp=(7, "", "curl: (7) connection refused"),  # read-back GET fails
    )
    install_fake_exec(monkeypatch, responder)
    handler = make_handler()
    assert await handler.apply_config(CONFIG_WITH_HOSTNAME) is False


@pytest.mark.asyncio
async def test_apply_config_fails_when_readback_hostname_mismatch(monkeypatch):
    responder = _post_then_get(
        post_resp=(0, mk_stdout("{}", 200), ""),
        get_resp=(0, mk_stdout('{"system":{"hostname":"old-host"}}', 200), ""),
    )
    install_fake_exec(monkeypatch, responder)
    handler = make_handler()
    assert await handler.apply_config(CONFIG_WITH_HOSTNAME) is False


@pytest.mark.asyncio
async def test_apply_config_succeeds_when_readback_confirms(monkeypatch):
    responder = _post_then_get(
        post_resp=(0, mk_stdout("{}", 200), ""),
        get_resp=(0, mk_stdout('{"system":{"hostname":"new-host"}}', 200), ""),
    )
    install_fake_exec(monkeypatch, responder)
    handler = make_handler()
    assert await handler.apply_config(CONFIG_WITH_HOSTNAME) is True


# ---------------------------------------------------------------------------------------
# aiohttp (non-curl) branch of apply_config must also reject app-level errors
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_apply_config_aiohttp_branch_rejects_status_code_error(monkeypatch):
    """Non-interface path: a 200 body with statusCode>=400 must fail even with no read-back."""
    from unittest.mock import AsyncMock

    handler = TachyonHandler(ip="169.254.1.1", credentials={"username": "root", "password": "admin"})
    handler._connected = True
    handler._use_curl = False  # aiohttp path
    handler._api_request = AsyncMock(return_value={"statusCode": 400, "error": {"details": "bad"}})

    # No hostname/SSID -> read-back is skipped, so the POST response is the only gate.
    assert await handler.apply_config(CONFIG_NO_VERIFY_FIELDS) is False


# ---------------------------------------------------------------------------------------
# Dispatch: production state (interface bound) routes through the curl helpers
# ---------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_upload_firmware_dispatches_to_curl(monkeypatch, tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware-bytes")
    captured = install_fake_exec(
        monkeypatch, lambda cmd: (0, mk_stdout('{"version":"unknown"}', 200), "")
    )
    handler = make_handler()
    assert await handler.upload_firmware(str(fw)) is True
    # Went through curl (PUT multipart), not aiohttp.
    assert method_of(captured[-1]) == "PUT"
