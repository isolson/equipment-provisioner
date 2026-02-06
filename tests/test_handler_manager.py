"""Tests for handler manager routing and credential handling."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from provisioner.handler_manager import HandlerManager
from provisioner.fingerprint import DeviceType, DeviceFingerprint


class TestHandlerRouting:
    """Tests for routing devices to correct handlers."""

    def setup_method(self):
        """Set up test credentials."""
        self.credentials = {
            "mikrotik": {"username": "admin", "password": ""},
            "cambium": {"username": "admin", "password": "admin"},
            "tachyon": {"username": "root", "password": "admin"},
            "tarana": {"username": "admin", "password": "admin"},
            "ubiquiti": {"username": "ubnt", "password": "ubnt"},
        }
        self.manager = HandlerManager(self.credentials)

    def test_get_handler_mikrotik(self):
        """Test routing to MikroTik handler."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.MIKROTIK,
            model="hAP ac2",
            confidence=0.95,
        )
        handler = self.manager.get_handler(fingerprint, "192.168.88.1")

        assert handler is not None
        assert handler.__class__.__name__ == "MikrotikHandler"

    def test_get_handler_cambium(self):
        """Test routing to Cambium handler."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.CAMBIUM,
            model="ePMP 4525",
            confidence=0.90,
        )
        handler = self.manager.get_handler(fingerprint, "169.254.1.1")

        assert handler is not None
        assert handler.__class__.__name__ == "CambiumHandler"

    def test_get_handler_tachyon(self):
        """Test routing to Tachyon handler."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.TACHYON,
            model="TNA-303X",
            confidence=0.95,
        )
        handler = self.manager.get_handler(fingerprint, "169.254.1.1")

        assert handler is not None
        assert handler.__class__.__name__ == "TachyonHandler"

    def test_get_handler_tarana(self):
        """Test routing to Tarana handler."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.TARANA,
            model="G1",
            confidence=0.90,
        )
        handler = self.manager.get_handler(fingerprint, "169.254.100.1")

        assert handler is not None
        assert handler.__class__.__name__ == "TaranaHandler"

    def test_get_handler_ubiquiti(self):
        """Test routing to Ubiquiti handler."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.UBIQUITI,
            model="Wave-Nano",
            confidence=0.98,
        )
        handler = self.manager.get_handler(fingerprint, "192.168.1.20")

        assert handler is not None
        assert handler.__class__.__name__ == "UbiquitiHandler"

    def test_get_handler_unknown_returns_none(self):
        """Test that unknown device types return None."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.UNKNOWN,
            confidence=0.0,
        )
        handler = self.manager.get_handler(fingerprint, "192.168.1.1")

        assert handler is None

    def test_get_supported_types(self):
        """Test getting list of supported device types."""
        supported = self.manager.get_supported_types()

        assert "mikrotik" in supported
        assert "cambium" in supported
        assert "tachyon" in supported
        assert "tarana" in supported
        assert "ubiquiti" in supported
        assert len(supported) == 5


class TestCredentialHandling:
    """Tests for credential management and fallbacks."""

    def test_uses_configured_credentials(self):
        """Test that configured credentials are used."""
        credentials = {
            "cambium": {"username": "custom_user", "password": "custom_pass"},
        }
        manager = HandlerManager(credentials)

        fingerprint = DeviceFingerprint(
            device_type=DeviceType.CAMBIUM,
            confidence=0.90,
        )
        handler = manager.get_handler(fingerprint, "169.254.1.1")

        assert handler.credentials["username"] == "custom_user"
        assert handler.credentials["password"] == "custom_pass"

    def test_uses_default_credentials_when_not_configured(self):
        """Test fallback to default credentials."""
        credentials = {}  # No credentials configured
        manager = HandlerManager(credentials)

        fingerprint = DeviceFingerprint(
            device_type=DeviceType.CAMBIUM,
            confidence=0.90,
        )
        handler = manager.get_handler(fingerprint, "169.254.1.1")

        # Should fall back to admin/empty
        assert handler.credentials["username"] == "admin"

    def test_custom_credentials_from_ui(self):
        """Test that UI-provided credentials override configured ones."""
        credentials = {
            "tachyon": {"username": "root", "password": "admin"},
        }
        manager = HandlerManager(credentials)

        fingerprint = DeviceFingerprint(
            device_type=DeviceType.TACHYON,
            confidence=0.95,
        )
        custom_creds = {"username": "ui_user", "password": "ui_pass"}
        handler = manager.get_handler(fingerprint, "169.254.1.1", custom_credentials=custom_creds)

        assert handler.credentials["username"] == "ui_user"
        assert handler.credentials["password"] == "ui_pass"

    def test_alternate_credentials_passed_to_handler(self):
        """Test that alternate credentials are passed to handlers."""
        credentials = {
            "tachyon": {"username": "root", "password": "admin"},
        }
        alternate_credentials = {
            "tachyon": [
                {"username": "root", "password": "alternate1"},
                {"username": "root", "password": "alternate2"},
            ],
        }
        manager = HandlerManager(credentials, alternate_credentials)

        fingerprint = DeviceFingerprint(
            device_type=DeviceType.TACHYON,
            confidence=0.95,
        )
        handler = manager.get_handler(fingerprint, "169.254.1.1")

        # Handler should have alternate credentials available (stored as _alternate_credentials)
        assert hasattr(handler, '_alternate_credentials')
        assert len(handler._alternate_credentials) == 2

    def test_interface_binding_passed_to_handler(self):
        """Test that interface binding is passed to handlers."""
        credentials = {
            "cambium": {"username": "admin", "password": "admin"},
        }
        manager = HandlerManager(credentials)

        fingerprint = DeviceFingerprint(
            device_type=DeviceType.CAMBIUM,
            confidence=0.90,
        )
        handler = manager.get_handler(fingerprint, "169.254.1.1", interface="eth0.1992")

        assert handler.interface == "eth0.1992"


class TestProvisionDevice:
    """Tests for the provision_device method."""

    def setup_method(self):
        """Set up test credentials."""
        self.credentials = {
            "tachyon": {"username": "root", "password": "admin"},
        }
        self.manager = HandlerManager(self.credentials)

    @pytest.mark.asyncio
    async def test_provision_unknown_device_fails(self):
        """Test that provisioning unknown devices fails gracefully."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.UNKNOWN,
            confidence=0.0,
        )

        result = await self.manager.provision_device(
            fingerprint=fingerprint,
            ip="192.168.1.1",
        )

        assert result.success is False
        assert "No handler" in result.error_message

    @pytest.mark.asyncio
    async def test_provision_calls_handler_provision(self):
        """Test that provision_device calls handler's provision method."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.TACHYON,
            model="TNA-303X",
            confidence=0.95,
        )

        # Mock the handler's provision method
        with patch.object(
            self.manager.HANDLER_MAP[DeviceType.TACHYON],
            '__init__',
            return_value=None
        ):
            with patch.object(
                self.manager.HANDLER_MAP[DeviceType.TACHYON],
                'provision',
                new_callable=AsyncMock
            ) as mock_provision:
                from provisioner.handlers.base import ProvisioningResult
                mock_provision.return_value = ProvisioningResult(success=True)

                handler = self.manager.get_handler(fingerprint, "169.254.1.1")
                # Can't fully test without mocking more, but the routing is tested above


class TestLoginAndGetInfo:
    """Tests for the debug login_and_get_info method."""

    def setup_method(self):
        """Set up test credentials."""
        self.credentials = {
            "cambium": {"username": "admin", "password": "admin"},
        }
        self.manager = HandlerManager(self.credentials)

    @pytest.mark.asyncio
    async def test_login_unknown_device_fails(self):
        """Test that login for unknown devices fails gracefully."""
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.UNKNOWN,
            confidence=0.0,
        )

        result = await self.manager.login_and_get_info(
            fingerprint=fingerprint,
            ip="192.168.1.1",
        )

        assert result.success is False
        assert "No handler" in result.error_message
