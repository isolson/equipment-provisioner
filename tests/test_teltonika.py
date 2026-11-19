"""Local checks for TSW202 registration and its safe pre-login path."""

import asyncio

from provisioner.fingerprint import DeviceFingerprinter, DeviceType
from provisioner.firmware_sources.teltonika import TeltonikaFirmwareSource
from provisioner.handlers.teltonika import FIRMWARE, TeltonikaHandler


def test_tsw202_oui_routes_to_handler_for_namespace_model_check():
    result = asyncio.run(DeviceFingerprinter().fingerprint("192.168.1.2", "20:97:27:00:00:01"))

    assert result.device_type is DeviceType.TELTONIKA
    assert result.model is None


def test_tsw202_missing_label_password_requests_credentials():
    handler = TeltonikaHandler("192.168.1.2", {"username": "admin", "password": ""})
    handler.business_switch_site = "lakeview"
    handler.business_switch_unit = 2

    result = asyncio.run(handler.provision())

    assert not result.success
    assert result.needs_credentials
    assert "label credentials" in result.error_message


def test_tsw202_firmware_source_matches_profile():
    entries = asyncio.run(TeltonikaFirmwareSource({}).check_for_updates())

    assert len(entries) == 1
    assert entries[0].version == FIRMWARE["version"]
    assert entries[0].filename == FIRMWARE["filename"]
    assert entries[0].download_url == FIRMWARE["url"]
    assert entries[0].extra["md5"] == FIRMWARE["md5"]
