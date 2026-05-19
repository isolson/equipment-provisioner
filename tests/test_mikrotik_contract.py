"""Contract-compliance tests for the MikroTik ZTP pipeline.

Verifies the four contract-shaped helpers:

  - ``MikrotikHandler.build_import_script``  — prepends ``:local`` parameters
    to the canonical script with correct RouterScript escaping.
  - ``MikrotikHandler.fetch_base_flash``     — GETs the canonical script
    from ``<ztp_api_url>/ztp/mikrotik/base-flash.rsc`` and raises on
    non-200.
  - ``MikrotikHandler.verify_base_flash_applied`` — reads ``/system/note``
    over the live SSH session and returns ``True`` iff it contains the
    canonical ``base_flash_version=universal-v1`` marker.
  - ``equipment_registry.register_mikrotik`` — POSTs the exact contract
    payload to ``<ztp_api_url>/ztp/mikrotik/register`` with an
    ``X-API-Key`` header.

These tests do not contact the network or hardware. ``aiohttp.ClientSession``
is patched with a hand-rolled stub because the project does not depend on
``aioresponses``.
"""

from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from provisioner.equipment_registry import register_mikrotik
from provisioner.handlers.mikrotik import MikrotikHandler


# ---------------------------------------------------------------------------
# aiohttp stub
# ---------------------------------------------------------------------------


class _StubResponse:
    """Stand-in for an aiohttp response inside an ``async with`` block."""

    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _StubSession:
    """Records the request that was made and returns a canned response.

    The instance is used as a context manager (``async with``) and exposes
    ``get`` / ``post`` that also return context managers — matching the
    layout of real ``aiohttp.ClientSession`` calls.
    """

    def __init__(self, response: _StubResponse):
        self._response = response
        self.last_call: Optional[Dict[str, Any]] = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str, **kwargs):
        self.last_call = {"method": "GET", "url": url, **kwargs}
        return self._response

    def post(self, url: str, **kwargs):
        self.last_call = {"method": "POST", "url": url, **kwargs}
        return self._response


def _patch_session(status: int, body: str) -> tuple:
    """Return (patcher, stub_session) for ``aiohttp.ClientSession``.

    Caller is responsible for ``patcher.start()`` / ``stop()``; we expose
    both so assertions can inspect ``stub_session.last_call``.
    """
    response = _StubResponse(status, body)
    stub = _StubSession(response)
    factory = MagicMock(return_value=stub)
    return factory, stub


# ---------------------------------------------------------------------------
# MODE_SCRIPT_BODY (passed to `netinstall-cli -sm`)
# ---------------------------------------------------------------------------


class TestModeScriptBody:
    """The -sm flag (netinstall-cli 7.22+) takes a *file path* to a
    RouterScript that sets device-mode on first boot. Format confirmed
    against the tikoci/netinstall Makefile, which is the reference
    implementation cited by the netinstall-cli 7.22 changelog.
    """

    def test_is_single_line_device_mode_update_advanced(self):
        body = MikrotikHandler.MODE_SCRIPT_BODY
        assert body.strip() == "/system/device-mode update mode=advanced"

    def test_ends_with_newline(self):
        # netinstall-cli reads the file as text — single trailing newline
        # matches the tikoci reference (`printf '%s\n'`).
        assert MikrotikHandler.MODE_SCRIPT_BODY.endswith("\n")

    def test_does_not_use_subcommand_slash_form(self):
        # `/system/device-mode/update` (with a slash before `update`) is the
        # confirmation-required interactive form. The netinstall mode-script
        # context wants the space-separated form so it can bypass
        # confirmation — getting this wrong leaves the device in `home`
        # mode after install.
        assert "/system/device-mode/update" not in MikrotikHandler.MODE_SCRIPT_BODY


# ---------------------------------------------------------------------------
# build_import_script
# ---------------------------------------------------------------------------


class TestBuildImportScript:
    def test_prepends_three_local_declarations(self):
        body = "/system note set note=\"base_flash_version=universal-v1\"\n"
        out = MikrotikHandler.build_import_script(
            serial="HBE3001234",
            bootstrap_pass="secret",
            base_flash_body=body,
        )

        # Per contract: serial, bootstrapPass, onboardingPass in that order.
        assert out.startswith(
            ':local serial "HBE3001234"\n'
            ':local bootstrapPass "secret"\n'
            ':local onboardingPass "secret"\n'
        )
        # Canonical body is concatenated after, unchanged.
        assert out.endswith(body)

    def test_onboarding_pass_defaults_to_bootstrap_pass(self):
        out = MikrotikHandler.build_import_script(
            serial="S", bootstrap_pass="bp", base_flash_body="",
        )
        assert ':local onboardingPass "bp"' in out

    def test_explicit_onboarding_pass_is_used(self):
        out = MikrotikHandler.build_import_script(
            serial="S",
            bootstrap_pass="bp",
            base_flash_body="",
            onboarding_pass="op",
        )
        assert ':local bootstrapPass "bp"' in out
        assert ':local onboardingPass "op"' in out

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ('he said "hi"',  'he said \\"hi\\"'),    # double quote
            ("back\\slash",   "back\\\\slash"),         # backslash
            ("a$VAR b",       "a\\$VAR b"),             # var substitution char
            ("a[cmd] b",      "a\\[cmd] b"),            # cmd substitution char
            ('mix "$x[y]\\z', 'mix \\"\\$x\\[y]\\\\z'),  # combined
        ],
    )
    def test_special_chars_in_bootstrap_pass_are_escaped(self, raw, expected):
        out = MikrotikHandler.build_import_script(
            serial="S", bootstrap_pass=raw, base_flash_body="",
        )
        assert f':local bootstrapPass "{expected}"' in out

    def test_special_chars_in_serial_are_escaped(self):
        # Real serials never contain these, but defense-in-depth — the
        # canonical script consumes $serial in places that would mis-parse
        # an unescaped `"` or `[`.
        out = MikrotikHandler.build_import_script(
            serial='HBE"INJECT', bootstrap_pass="bp", base_flash_body="",
        )
        assert ':local serial "HBE\\"INJECT"' in out


# ---------------------------------------------------------------------------
# fetch_base_flash
# ---------------------------------------------------------------------------


class TestFetchBaseFlash:
    async def test_returns_body_on_200(self):
        factory, stub = _patch_session(
            200, "# canonical base-flash\nbase_flash_version=universal-v1\n",
        )
        with patch("provisioner.handlers.mikrotik.aiohttp.ClientSession", factory):
            body = await MikrotikHandler.fetch_base_flash("https://api.example.com")

        assert "base_flash_version=universal-v1" in body
        assert stub.last_call["method"] == "GET"
        assert stub.last_call["url"] == "https://api.example.com/ztp/mikrotik/base-flash.rsc"

    async def test_strips_trailing_slash(self):
        factory, stub = _patch_session(200, "ok")
        with patch("provisioner.handlers.mikrotik.aiohttp.ClientSession", factory):
            await MikrotikHandler.fetch_base_flash("https://api.example.com/")

        assert stub.last_call["url"] == "https://api.example.com/ztp/mikrotik/base-flash.rsc"

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 502])
    async def test_raises_on_non_200(self, status):
        factory, _ = _patch_session(status, "error body")
        with patch("provisioner.handlers.mikrotik.aiohttp.ClientSession", factory):
            with pytest.raises(RuntimeError, match=str(status)):
                await MikrotikHandler.fetch_base_flash("https://api.example.com")


# ---------------------------------------------------------------------------
# verify_base_flash_applied
# ---------------------------------------------------------------------------


def _handler() -> MikrotikHandler:
    return MikrotikHandler(
        ip="192.168.88.1",
        credentials={"username": "fleet-bootstrap", "password": "x"},
    )


class TestVerifyBaseFlashApplied:
    async def test_true_when_marker_present(self):
        h = _handler()
        h._run_command = AsyncMock(
            return_value=(
                "show-at-login: yes\n"
                "note: base_flash_version=universal-v1 serial=HBE0001\n"
            )
        )
        assert await h.verify_base_flash_applied() is True

    async def test_false_when_marker_absent(self):
        h = _handler()
        h._run_command = AsyncMock(return_value="note: something else entirely")
        assert await h.verify_base_flash_applied() is False

    async def test_false_when_note_empty(self):
        h = _handler()
        h._run_command = AsyncMock(return_value="")
        assert await h.verify_base_flash_applied() is False

    async def test_false_on_wrong_version_marker(self):
        h = _handler()
        # An older universal version must NOT be accepted as compliant.
        h._run_command = AsyncMock(return_value="base_flash_version=universal-v0")
        assert await h.verify_base_flash_applied() is False


class TestWaitForBaseFlashApplied:
    async def test_waits_until_marker_is_visible(self):
        h = _handler()
        h.verify_base_flash_applied = AsyncMock(side_effect=[False, False, True])

        with patch("asyncio.sleep", new=AsyncMock()) as sleep:
            assert await h.wait_for_base_flash_applied(timeout=30, interval=2) is True

        assert h.verify_base_flash_applied.await_count == 3
        sleep.assert_awaited()

    async def test_allows_slow_hap_ax_s_marker_visibility(self):
        h = _handler()
        h.verify_base_flash_applied = AsyncMock(side_effect=([False] * 130) + [True])

        with patch("asyncio.sleep", new=AsyncMock()) as sleep:
            assert await h.wait_for_base_flash_applied(timeout=360, interval=2) is True

        assert h.verify_base_flash_applied.await_count == 131
        assert sleep.await_count == 130

    async def test_false_after_timeout(self):
        h = _handler()
        h.verify_base_flash_applied = AsyncMock(return_value=False)

        assert await h.wait_for_base_flash_applied(timeout=0, interval=0) is False
        h.verify_base_flash_applied.assert_awaited_once()


# ---------------------------------------------------------------------------
# verify_ztp_ready
# ---------------------------------------------------------------------------


class TestVerifyZtpReady:
    def _mock_ztp_ready_commands(
        self,
        *,
        device_mode: str = "mode: advanced\nfetch: yes\nscheduler: yes\n",
        note: str = "base_flash_version=universal-v1 serial=HBE0001",
        identity: str = "fleet-init-HBE0001",
        phone_home: str = "1",
        boot_scheduler: str = "1",
        adaptive_scheduler: str = "1",
        dhcp_probes: str = "5",
    ):
        async def run(command: str, allow_failure: bool = False) -> str:
            if command == "/system/device-mode/print":
                return device_mode
            if command == "/system/note/get note":
                return note
            if command == ":put [/system/identity/get name]":
                return identity
            if "script/find name=phone-home" in command:
                return phone_home
            if "scheduler/find name=phone-home-boot" in command:
                return boot_scheduler
            if "scheduler/find name=phone-home-adaptive" in command:
                return adaptive_scheduler
            if "dhcp-client/find comment=th-wan-probe" in command:
                return dhcp_probes
            return ""

        return AsyncMock(side_effect=run)

    async def test_true_when_device_can_phone_home_after_handoff(self):
        h = _handler()
        h._run_command = self._mock_ztp_ready_commands()

        ok, detail = await h.verify_ztp_ready("HBE0001")

        assert ok is True
        assert "ZTP-ready" in detail

    async def test_allows_identity_after_role_self_detection(self):
        h = _handler()
        h._run_command = self._mock_ztp_ready_commands(
            identity="fleet-gw-HBE0001",
        )

        ok, detail = await h.verify_ztp_ready("HBE0001")

        assert ok is True
        assert "ZTP-ready" in detail

    async def test_false_when_device_mode_blocks_fetch_or_scheduler(self):
        h = _handler()
        h._run_command = self._mock_ztp_ready_commands(
            device_mode="mode: home\nfetch: no\nscheduler: no\n",
        )

        ok, detail = await h.verify_ztp_ready("HBE0001")

        assert ok is False
        assert "device-mode blocks ZTP" in detail

    async def test_false_when_phone_home_scheduler_missing(self):
        h = _handler()
        h._run_command = self._mock_ztp_ready_commands(
            adaptive_scheduler="0",
        )

        ok, detail = await h.verify_ztp_ready("HBE0001")

        assert ok is False
        assert detail == "missing phone-home scheduler"

    async def test_false_when_identity_does_not_match_serial(self):
        h = _handler()
        h._run_command = self._mock_ztp_ready_commands(
            identity="MikroTik",
        )

        ok, detail = await h.verify_ztp_ready("HBE0001")

        assert ok is False
        assert "unexpected identity" in detail


# ---------------------------------------------------------------------------
# register_mikrotik
# ---------------------------------------------------------------------------


class TestRegisterMikrotik:
    async def test_posts_exact_contract_payload(self):
        factory, stub = _patch_session(200, "{}")
        with patch("provisioner.equipment_registry.aiohttp.ClientSession", factory):
            ok = await register_mikrotik(
                ztp_api_url="https://api.example.com",
                api_key="sekret",
                serial="HBE3001234",
                mac="04:f4:1c:c2:06:80",
                model="hap-ax2-s",
                firmware_version="7.22.2",
                base_flash_version="universal-v1",
            )

        assert ok is True
        call = stub.last_call
        assert call["method"] == "POST"
        assert call["url"] == "https://api.example.com/ztp/mikrotik/register"
        # Contract payload — exact field set, no extras.
        assert call["json"] == {
            "serial": "HBE3001234",
            "mac": "04:f4:1c:c2:06:80",
            "model": "hap-ax2-s",
            "firmware_version": "7.22.2",
            "base_flash_version": "universal-v1",
        }
        # `role` is forbidden by contract — device self-detects.
        assert "role" not in call["json"]
        # Contract auth scheme.
        assert call["headers"]["X-API-Key"] == "sekret"

    async def test_omits_api_key_header_when_unset(self):
        factory, stub = _patch_session(200, "{}")
        with patch("provisioner.equipment_registry.aiohttp.ClientSession", factory):
            await register_mikrotik(
                ztp_api_url="https://api.example.com",
                api_key=None,
                serial="S", mac="M", model="hap-ax2-s",
                firmware_version="7.22.2", base_flash_version="universal-v1",
            )

        assert "X-API-Key" not in stub.last_call["headers"]

    @pytest.mark.parametrize("status", [400, 401, 403, 422, 500])
    async def test_raises_on_non_2xx(self, status):
        factory, _ = _patch_session(status, "bad")
        with patch("provisioner.equipment_registry.aiohttp.ClientSession", factory):
            with pytest.raises(RuntimeError, match=str(status)):
                await register_mikrotik(
                    ztp_api_url="https://api.example.com",
                    api_key=None,
                    serial="S", mac="M", model="hap-ax2-s",
                    firmware_version="7.22.2", base_flash_version="universal-v1",
                )

    async def test_strips_trailing_slash(self):
        factory, stub = _patch_session(200, "{}")
        with patch("provisioner.equipment_registry.aiohttp.ClientSession", factory):
            await register_mikrotik(
                ztp_api_url="https://api.example.com/",
                api_key=None,
                serial="S", mac="M", model="hap-ax2-s",
                firmware_version="7.22.2", base_flash_version="universal-v1",
            )

        assert stub.last_call["url"] == "https://api.example.com/ztp/mikrotik/register"
