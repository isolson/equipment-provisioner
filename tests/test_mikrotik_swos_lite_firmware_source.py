import pytest

from provisioner.firmware_sources.mikrotik_swos_lite import (
    MikrotikSwosLiteFirmwareSource,
)


@pytest.mark.asyncio
async def test_swos_lite_source_uses_major_minor_from_latest_value(monkeypatch):
    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def text(self):
            return "2.21.1766066090"

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, _url):
            return Response()

    monkeypatch.setattr(
        "provisioner.firmware_sources.mikrotik_swos_lite.aiohttp.ClientSession",
        lambda timeout: Session(),
    )
    source = MikrotikSwosLiteFirmwareSource({})

    updates = await source.check_for_updates()

    assert len(updates) == 1
    assert updates[0].version == "2.21"
    assert updates[0].filename == "swos-gpen21-2.21.bin"
