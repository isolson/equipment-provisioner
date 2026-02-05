"""Tests for device fingerprinting."""

import pytest
from provisioner.fingerprint import DeviceFingerprinter, DeviceType, DeviceFingerprint


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

        fingerprint = DeviceFingerprint(device_type=DeviceType.MIKROTIK)
        body = 'RouterOS v7.13.2 on hAP ac2'

        fingerprinter._extract_device_details(body, fingerprint)

        assert fingerprint.firmware_version == "7.13.2"


class TestHTTPSignatureMatching:
    """Tests for HTTP signature-based device identification."""

    def setup_method(self):
        """Create a fingerprinter for testing."""
        self.fingerprinter = DeviceFingerprinter()

    def test_tachyon_detection_xavante(self):
        """Test Tachyon detection via Xavante server header."""
        headers = {"Server": "Xavante 2.4.0"}
        body = '<html>Login Page</html>'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.TACHYON
        # Xavante is a strong indicator (weight 5)
        assert result.confidence >= 0.9

    def test_tachyon_detection_cgi_lua(self):
        """Test Tachyon detection via cgi.lua in response."""
        headers = {}
        body = '{"redirect": "/cgi.lua/dashboard"}'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.TACHYON

    def test_tachyon_detection_8devices(self):
        """Test Tachyon detection via 8DEVICES manufacturer."""
        headers = {}
        body = '<html>8DEVICES Network Device</html>'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.TACHYON

    def test_ubiquiti_detection_airos(self):
        """Test Ubiquiti detection via AirOS signature."""
        headers = {}
        body = '<html><title>airOS</title></html>'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.UBIQUITI
        # AirOS is a strong indicator (weight 5)
        assert result.confidence >= 0.9

    def test_ubiquiti_detection_login_cgi(self):
        """Test Ubiquiti detection via login.cgi endpoint."""
        headers = {}
        body = '<form action="login.cgi" method="POST">'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.UBIQUITI

    def test_cambium_detection_server_header(self):
        """Test Cambium detection via server header."""
        headers = {"Server": "Cambium HTTP Server"}
        body = '<html>Device Management</html>'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.CAMBIUM
        # Strong indicator (weight 5)
        assert result.confidence >= 0.9

    def test_cambium_detection_epmp_model(self):
        """Test Cambium detection via ePMP model in response."""
        headers = {}
        body = '<html><title>ePMP 4525 Management</title></html>'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.CAMBIUM

    def test_tarana_detection(self):
        """Test Tarana detection via G1 Node signature."""
        headers = {}
        body = '<html>Tarana Wireless G1 Node Configuration</html>'

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.TARANA

    def test_weighted_scoring_prefers_stronger_match(self):
        """Test that weighted scoring correctly identifies ambiguous responses."""
        # Response with both Ubiquiti and generic patterns
        headers = {"Server": "lighttpd"}  # Ubiquiti uses lighttpd (weight 2)
        body = '<html>UBNT Device login.cgi</html>'  # UBNT (4) + login.cgi (4)

        result = self.fingerprinter._analyze_http_response(headers, body)

        assert result is not None
        assert result.device_type == DeviceType.UBIQUITI


class TestDeviceDetailsExtraction:
    """Tests for extracting device details from HTTP responses."""

    def setup_method(self):
        """Create a fingerprinter for testing."""
        self.fingerprinter = DeviceFingerprinter()

    def test_extract_mikrotik_details(self):
        """Test extraction of MikroTik model and version."""
        fingerprint = DeviceFingerprint(device_type=DeviceType.MIKROTIK)
        body = '''
        RouterOS v7.13.2
        board: "hAP ac2"
        '''

        self.fingerprinter._extract_device_details(body, fingerprint)

        assert fingerprint.firmware_version == "7.13.2"
        assert fingerprint.model == "hAP ac2"

    def test_extract_cambium_version(self):
        """Test extraction of Cambium firmware version."""
        fingerprint = DeviceFingerprint(device_type=DeviceType.CAMBIUM)
        body = 'firmware: "4.8.1"'

        self.fingerprinter._extract_device_details(body, fingerprint)

        assert fingerprint.firmware_version == "4.8.1"

    def test_extract_ubiquiti_wave_model(self):
        """Test extraction of Ubiquiti Wave model names."""
        fingerprint = DeviceFingerprint(device_type=DeviceType.UBIQUITI)
        body = '<html>Wave-Nano Configuration</html>'

        self.fingerprinter._extract_device_details(body, fingerprint)

        assert fingerprint.model is not None
        assert "Wave" in fingerprint.model

    def test_extract_ubiquiti_rocket_model(self):
        """Test extraction of Ubiquiti Rocket model."""
        fingerprint = DeviceFingerprint(device_type=DeviceType.UBIQUITI)
        body = '<html>Rocket M5 Management</html>'

        self.fingerprinter._extract_device_details(body, fingerprint)

        assert fingerprint.model is not None
        assert "Rocket" in fingerprint.model


class TestDeviceTypeEnum:
    """Tests for DeviceType enum values."""

    def test_device_type_values(self):
        """Test that all device types have correct string values."""
        assert DeviceType.MIKROTIK.value == "mikrotik"
        assert DeviceType.CAMBIUM.value == "cambium"
        assert DeviceType.TACHYON.value == "tachyon"
        assert DeviceType.TARANA.value == "tarana"
        assert DeviceType.UBIQUITI.value == "ubiquiti"
        assert DeviceType.UNKNOWN.value == "unknown"

    def test_device_type_is_string_enum(self):
        """Test that DeviceType inherits from str."""
        assert isinstance(DeviceType.MIKROTIK, str)
        assert DeviceType.MIKROTIK == "mikrotik"


class TestDeviceFingerprint:
    """Tests for DeviceFingerprint dataclass."""

    def test_fingerprint_defaults(self):
        """Test DeviceFingerprint default values."""
        fp = DeviceFingerprint(device_type=DeviceType.UNKNOWN)

        assert fp.device_type == DeviceType.UNKNOWN
        assert fp.model is None
        assert fp.firmware_version is None
        assert fp.hostname is None
        assert fp.mac_address is None
        assert fp.confidence == 0.0

    def test_fingerprint_with_values(self):
        """Test DeviceFingerprint with all values set."""
        fp = DeviceFingerprint(
            device_type=DeviceType.TACHYON,
            model="TNA-303X",
            firmware_version="1.12.3",
            hostname="radio-001",
            mac_address="AA:BB:CC:DD:EE:FF",
            confidence=0.95,
        )

        assert fp.device_type == DeviceType.TACHYON
        assert fp.model == "TNA-303X"
        assert fp.firmware_version == "1.12.3"
        assert fp.hostname == "radio-001"
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.confidence == 0.95


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
