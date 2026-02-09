"""Tests for MikroTik handler helper behavior."""

import pytest

from provisioner.handlers.base import DeviceInfo
from provisioner.handlers.mikrotik import MikrotikHandler


class TestMikrotikCredentialSelection:
    """Credential fallback order should match other handlers."""

    def test_custom_credentials_are_tried_first(self):
        handler = MikrotikHandler(
            ip="192.168.88.1",
            credentials={"username": "admin", "password": "custom-pass"},
            alternate_credentials=[{"username": "admin", "password": "alt-pass"}],
        )

        candidates = handler._credential_candidates()

        assert candidates[0] == {"username": "admin", "password": "custom-pass"}
        assert {"username": "admin", "password": "admin"} in candidates
        assert {"username": "admin", "password": ""} in candidates
        assert {"username": "admin", "password": "alt-pass"} in candidates

    def test_default_credentials_are_present(self):
        handler = MikrotikHandler(
            ip="192.168.88.1",
            credentials={"username": "admin", "password": ""},
        )

        candidates = handler._credential_candidates()

        assert candidates[0] == {"username": "admin", "password": "admin"}
        assert candidates[1] == {"username": "admin", "password": ""}


class TestMikrotikParsingAndValidation:
    """Lightweight parser/validator tests without network access."""

    def test_parse_kv_output_handles_as_value_and_colon_formats(self):
        output = (
            'version=7.21.2 board-name="hEX PoE" architecture-name=mipsbe\n'
            "current-firmware: 7.21.2\n"
        )

        parsed = MikrotikHandler._parse_kv_output(output)

        assert parsed["version"] == "7.21.2"
        assert parsed["board-name"] == "hEX PoE"
        assert parsed["architecture-name"] == "mipsbe"
        assert parsed["current-firmware"] == "7.21.2"

    def test_validate_firmware_checks_extension_and_architecture(self):
        handler = MikrotikHandler(
            ip="192.168.88.1",
            credentials={"username": "admin", "password": "admin"},
        )
        handler._device_info = DeviceInfo(
            device_type="mikrotik",
            hardware_version="mipsbe",
        )

        assert handler.validate_firmware_for_model("routeros-mipsbe-7.21.2.npk", "RB960PGS")[0]
        assert not handler.validate_firmware_for_model("routeros-arm-7.21.2.npk", "RB960PGS")[0]
        assert not handler.validate_firmware_for_model("routeros-mipsbe-7.21.2.bin", "RB960PGS")[0]


@pytest.mark.asyncio
async def test_get_info_falls_back_to_direct_getters_when_as_value_parse_is_empty():
    handler = MikrotikHandler(
        ip="192.168.88.1",
        credentials={"username": "admin", "password": ""},
    )

    responses = {
        "/system resource print as-value": "",
        "/system identity print as-value": "",
        "/system routerboard print as-value": "serial-number=ABC123",
        ":put [/system resource get architecture-name]": "mipsbe",
        ":put [/system resource get version]": "7.20.8",
        ":put [/system resource get board-name]": "hEX PoE",
        ":put [/system identity get name]": "mikrotik-hex",
        ":put [/interface ethernet get [find default-name=ether1] mac-address]": "00:11:22:33:44:55",
    }

    async def fake_run(command: str, allow_failure: bool = False) -> str:
        return responses.get(command, "")

    handler._run_command = fake_run  # type: ignore[method-assign]

    info = await handler.get_info()

    assert info.model == "hEX PoE"
    assert info.hardware_version == "mipsbe"
    assert info.firmware_version == "7.20.8"
    assert info.hostname == "mikrotik-hex"
    assert info.serial_number == "ABC123"
    assert info.mac_address == "00:11:22:33:44:55"


@pytest.mark.asyncio
async def test_get_firmware_banks_falls_back_to_direct_version_getter():
    handler = MikrotikHandler(
        ip="192.168.88.1",
        credentials={"username": "admin", "password": ""},
    )

    responses = {
        "/system resource print as-value": "",
        "/system routerboard print as-value": "current-firmware=7.20.8 upgrade-firmware=7.20.8",
        ":put [/system resource get version]": "7.20.8",
    }

    async def fake_run(command: str, allow_failure: bool = False) -> str:
        return responses.get(command, "")

    handler._run_command = fake_run  # type: ignore[method-assign]

    banks = await handler.get_firmware_banks()

    assert banks["bank1"] == "7.20.8"
    assert banks["bank2"] == "7.20.8"


@pytest.mark.asyncio
async def test_version_normalization_strips_channel_suffix_for_verification():
    handler = MikrotikHandler(
        ip="192.168.88.1",
        credentials={"username": "admin", "password": ""},
    )

    responses = {
        "/system resource print as-value": 'version="7.20.8 (long-term)"',
        "/system identity print as-value": "name=hex",
        "/system routerboard print as-value": "current-firmware=7.20.8 upgrade-firmware=7.20.8",
        ":put [/interface ethernet get [find default-name=ether1] mac-address]": "00:11:22:33:44:55",
    }

    async def fake_run(command: str, allow_failure: bool = False) -> str:
        return responses.get(command, "")

    handler._run_command = fake_run  # type: ignore[method-assign]

    info = await handler.get_info()
    banks = await handler.get_firmware_banks()

    assert info.firmware_version == "7.20.8"
    assert banks["bank1"] == "7.20.8"
    assert banks["bank1_display"] == "7.20.8 (long-term)"
