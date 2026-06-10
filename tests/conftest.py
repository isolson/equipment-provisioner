"""Shared fixtures for the test suite.

The :class:`SpyHandler` is a :class:`BaseHandler` subclass that records every
method call ``provision()`` makes on it, so flow-control tests can assert the
exact sequence of phases that ran for a given combination of handler
properties.
"""

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import pytest

# Ensure this directory is importable so sibling test helpers (``stubs``) resolve
# regardless of pytest's import mode / invocation cwd.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from provisioner.handlers.base import BaseHandler, DeviceInfo
from stubs import FakeCurl, StubSession


class SpyHandler(BaseHandler):
    """Records every call provision() makes, with controllable property values.

    Models a minimal but realistic device: ``get_firmware_banks`` returns
    versions that update as ``update_firmware(bank=N)`` is called, so the flow
    naturally passes its own verification checks regardless of which property
    branches are being exercised.
    """

    def __init__(
        self,
        *,
        supports_dual_bank: bool = False,
        update_triggers_reboot: bool = False,
        verify_active_bank: bool = False,
        config_after_all_firmware: bool = False,
        fw2_skips_reboot: bool = False,
        active_bank: int = 1,
        initial_bank1: str = "old",
        initial_bank2: str = "old",
    ):
        super().__init__(ip="10.0.0.1", credentials={"username": "x", "password": "y"})
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self._props = {
            "supports_dual_bank": supports_dual_bank,
            "update_triggers_reboot": update_triggers_reboot,
            "verify_active_bank": verify_active_bank,
            "config_after_all_firmware": config_after_all_firmware,
            "fw2_skips_reboot": fw2_skips_reboot,
        }
        self._bank1 = initial_bank1
        self._bank2 = initial_bank2
        self._active = active_bank

    @property
    def device_type(self) -> str:
        return "spy"

    @property
    def supports_dual_bank(self) -> bool:
        return self._props["supports_dual_bank"]

    @property
    def update_triggers_reboot(self) -> bool:
        return self._props["update_triggers_reboot"]

    @property
    def verify_active_bank(self) -> bool:
        return self._props["verify_active_bank"]

    @property
    def config_after_all_firmware(self) -> bool:
        return self._props["config_after_all_firmware"]

    @property
    def fw2_skips_reboot(self) -> bool:
        return self._props["fw2_skips_reboot"]

    def _record(self, name: str, **kwargs: Any) -> None:
        self.calls.append((name, kwargs))

    @property
    def call_names(self) -> List[str]:
        return [name for name, _ in self.calls]

    async def connect(self) -> bool:
        self._record("connect")
        self._connected = True
        return True

    async def disconnect(self) -> None:
        self._record("disconnect")
        self._connected = False

    async def get_info(self) -> DeviceInfo:
        self._record("get_info")
        return DeviceInfo(
            device_type="spy",
            model="SPY-MODEL",
            mac_address="aa:bb:cc:dd:ee:ff",
            serial_number="SN0001",
            firmware_version=self._bank1,
        )

    async def backup_config(self) -> bytes:
        self._record("backup_config")
        return b""

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        self._record("apply_config", config=config)
        return True

    async def apply_config_file(self, config_path: str) -> bool:
        self._record("apply_config_file", path=config_path)
        return True

    async def verify_config(self, expected_values: Optional[Dict[str, Any]] = None) -> bool:
        self._record("verify_config")
        return True

    async def upload_firmware(self, firmware_path: str, bank: Optional[int] = None) -> bool:
        self._record("upload_firmware", path=firmware_path, bank=bank)
        return True

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        self._record("update_firmware", bank=bank)
        target = bank if bank is not None else 1
        if target == 1:
            self._bank1 = "new"
        else:
            self._bank2 = "new"
        return True

    async def reboot(self) -> bool:
        self._record("reboot")
        return True

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        self._record("wait_for_reboot")
        return True

    async def get_firmware_version(self) -> str:
        self._record("get_firmware_version")
        return self._bank1

    async def get_firmware_banks(self) -> Dict[str, Any]:
        self._record("get_firmware_banks")
        return {
            "bank1": self._bank1,
            "bank2": self._bank2,
            "bank1_display": self._bank1,
            "bank2_display": self._bank2,
            "active": self._active,
        }


@pytest.fixture
def spy_handler_factory():
    """Return a builder for :class:`SpyHandler` with property overrides."""

    def _make(**overrides: Any) -> SpyHandler:
        return SpyHandler(**overrides)

    return _make


@pytest.fixture
def stub_aiohttp():
    """Build a :class:`StubSession` for handlers that use ``aiohttp``.

    Usage::

        session = stub_aiohttp(router=lambda method, url, kw: StubResponse(...))
        monkeypatch.setattr(handler, "_get_session", lambda: session)
    """

    def _make(router=None, default=None) -> StubSession:
        return StubSession(router=router, default=default)

    return _make


@pytest.fixture
def fake_curl(monkeypatch):
    """Intercept ``asyncio.create_subprocess_exec`` for curl-based handler paths.

    Returns a :class:`FakeCurl`; register responses with ``set_handler`` or
    ``route_by_method``. Patches the attribute on the ``asyncio`` module, which
    is what both the module-level and function-local ``import asyncio`` in the
    handlers resolve to at call time.
    """
    fc = FakeCurl()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fc)
    return fc


@pytest.fixture
def fast_sleep(monkeypatch):
    """Make ``asyncio.sleep`` return immediately so retry/settle delays don't
    slow the suite. Handlers use sleeps only for pacing, never for ordering."""

    async def _noop(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop)
