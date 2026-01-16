"""Tests for device fingerprinting."""

import pytest
from provisioner.fingerprint import DeviceFingerprinter, DeviceType


class TestDeviceFingerprinter:
    """Tests for DeviceFingerprinter class."""

    def test_analyze_mikrotik_response(self):
        """Test identification of MikroTik from HTTP response."""
        fingerprinter = DeviceFingerprinter()

        headers = {"Server": "RouterOS"}
        body = '<html><title>RouterOS v7.13</title></html>'

        result = fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.MIKROTIK
        assert result.confidence > 0.5

    def test_analyze_cambium_response(self):
        """Test identification of Cambium from HTTP response."""
        fingerprinter = DeviceFingerprinter()

        headers = {}
        body = '<html><title>Cambium ePMP</title></html>'

        result = fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.CAMBIUM

    def test_analyze_unknown_response(self):
        """Test handling of unknown device response."""
        fingerprinter = DeviceFingerprinter()

        headers = {}
        body = '<html><title>Generic Device</title></html>'

        result = fingerprinter._analyze_http_response(headers, body)

        assert result is None

    def test_extract_mikrotik_version(self):
        """Test extraction of MikroTik firmware version."""
        fingerprinter = DeviceFingerprinter()
        from provisioner.fingerprint import DeviceFingerprint

        fingerprint = DeviceFingerprint(device_type=DeviceType.MIKROTIK)
        body = 'RouterOS v7.13.2 on hAP ac2'

        fingerprinter._extract_device_details(body, fingerprint)

        assert fingerprint.firmware_version == "7.13.2"


class TestVersionExtraction:
    """Tests for version extraction from filenames."""

    def test_extract_version_from_filename(self):
        """Test version extraction from various filename formats."""
        from provisioner.firmware import FirmwareManager

        manager = FirmwareManager("/tmp")

        assert manager._extract_version_from_filename("firmware-v1.2.3.bin") == "1.2.3"
        assert manager._extract_version_from_filename("device_1.2.3.img") == "1.2.3"
        assert manager._extract_version_from_filename("routeros-7.13-arm.npk") == "7.13"


class TestVersionComparison:
    """Tests for firmware version comparison."""

    def test_compare_versions(self):
        """Test version comparison logic."""
        from provisioner.firmware import FirmwareManager

        manager = FirmwareManager("/tmp")

        # v1 > v2 returns 1
        assert manager._compare_versions("2.0.0", "1.0.0") == 1
        assert manager._compare_versions("1.1.0", "1.0.0") == 1
        assert manager._compare_versions("1.0.1", "1.0.0") == 1

        # v1 < v2 returns -1
        assert manager._compare_versions("1.0.0", "2.0.0") == -1
        assert manager._compare_versions("1.0.0", "1.1.0") == -1

        # v1 == v2 returns 0
        assert manager._compare_versions("1.0.0", "1.0.0") == 0
        assert manager._compare_versions("v1.0.0", "1.0.0") == 0
