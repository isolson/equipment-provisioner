"""Characterization tests for the firmware-lookup model key (Story #71).

``provision()`` picks the key it hands to ``firmware_lookup_callback`` when it
has to re-look-up a firmware file. Today that choice lives in an inner closure
in ``base.py`` that branches on ``device_type == "mikrotik"``; Story #71 moves
it to a ``BaseHandler.firmware_lookup_key()`` override. These tests pin the
*observable* behavior through ``provision()`` so they pass identically before
and after that refactor.

The load-bearing detail: **Cambium and Ubiquiti populate ``hardware_version``
today** (``cambium.py`` ``hardwareVersion``, ``ubiquiti.py`` ``hwversion``),
but must still be looked up by ``model``. A base default of
``hardware_version or model`` would key Cambium off a ``"V1.0"``-style string
and miss every ``MODEL_FIRMWARE_PATTERNS`` entry — failing only on real
hardware. The per-vendor cases below exist to catch exactly that.
"""

from provisioner.handlers.base import DeviceInfo
from provisioner.handlers.mikrotik import MikrotikHandler

from conftest import SpyHandler


async def _run(handler, **kwargs):
    """Drive provision() with a recording firmware-lookup callback.

    ``firmware_path=None`` forces the re-lookup path. The callback returns
    ``(None, None)`` so provisioning stops right after the lookup — we only
    care which key it was asked for.
    """
    seen = []

    def callback(device_type, model):
        seen.append((device_type, model))
        return (None, None)

    await handler.provision(firmware_lookup_callback=callback, **kwargs)
    return seen


class TestFirmwareLookupKeyPerVendor:
    """One case per vendor, using the realistic model/hardware_version pair
    that vendor's ``get_info()`` actually produces."""

    async def test_cambium_ignores_its_hardware_version(self, spy_handler_factory):
        # cambium.py:968 populates hardwareVersion, but MODEL_FIRMWARE_PATTERNS
        # is keyed on "epmp 4600". Keying off hardware_version breaks lookup.
        handler = spy_handler_factory(
            device_type="cambium", model="ePMP 4600", hardware_version="V1.0"
        )
        assert await _run(handler) == [("cambium", "ePMP 4600")]

    async def test_ubiquiti_ignores_its_hardware_version(self, spy_handler_factory):
        # ubiquiti.py:552 populates hwversion; patterns are keyed on "wave-pro".
        handler = spy_handler_factory(
            device_type="ubiquiti", model="Wave-Pro", hardware_version="1.0"
        )
        assert await _run(handler) == [("ubiquiti", "Wave-Pro")]

    async def test_tachyon_uses_model(self, spy_handler_factory):
        handler = spy_handler_factory(device_type="tachyon", model="TNA-301")
        assert await _run(handler) == [("tachyon", "TNA-301")]

    async def test_tarana_uses_model(self, spy_handler_factory):
        handler = spy_handler_factory(device_type="tarana", model="G1 Remote Node")
        assert await _run(handler) == [("tarana", "G1 Remote Node")]


class TestMikrotikOverride:
    """MikroTik is the one vendor that keys off something other than model.

    Before #71 this was a ``device_type == "mikrotik"`` string check inside
    ``provision()``, so *any* handler reporting that device_type got the
    behavior. It is now keyed on the handler class, which is the intended
    semantics — the arch preference is a property of the RouterOS package
    naming scheme, not of a string.
    """

    def _handler(self):
        return MikrotikHandler(
            ip="10.0.0.1", credentials={"username": "admin", "password": ""}
        )

    def test_prefers_hardware_version(self):
        # mikrotik.py:152-154 — board-name "hEX PoE", architecture-name "mipsbe".
        # The .npk filename carries the arch, not the board, so the arch wins.
        info = DeviceInfo(
            device_type="mikrotik", model="hEX PoE", hardware_version="mipsbe"
        )
        assert self._handler().firmware_lookup_key(info) == "mipsbe"

    def test_falls_back_to_model_without_hardware_version(self):
        info = DeviceInfo(device_type="mikrotik", model="hEX PoE")
        assert self._handler().firmware_lookup_key(info) == "hEX PoE"

    def test_falls_back_to_model_on_empty_hardware_version(self):
        # Empty string is falsy — must behave like None, not key off "".
        info = DeviceInfo(
            device_type="mikrotik", model="hEX PoE", hardware_version=""
        )
        assert self._handler().firmware_lookup_key(info) == "hEX PoE"

    def test_handles_missing_device_info(self):
        assert self._handler().firmware_lookup_key(None) is None

    async def test_provision_routes_through_the_override(self):
        """The override must actually be consulted by provision(), at the
        call site that has no truthiness guard."""

        class _ArchSpy(SpyHandler):
            def firmware_lookup_key(self, device_info):
                return "OVERRIDDEN"

        assert await _run(_ArchSpy()) == [("spy", "OVERRIDDEN")]


class TestFirmwareLookupKeyEdgeCases:
    async def test_no_model_skips_lookup_entirely(self, spy_handler_factory):
        # base.py guards the first call site on a truthy key, so a model-less
        # device must not reach the callback at all.
        handler = spy_handler_factory(device_type="cambium", model=None)
        assert await _run(handler) == []

    async def test_non_mikrotik_hardware_version_never_substitutes_for_missing_model(
        self, spy_handler_factory
    ):
        handler = spy_handler_factory(
            device_type="ubiquiti", model=None, hardware_version="1.0"
        )
        assert await _run(handler) == []
