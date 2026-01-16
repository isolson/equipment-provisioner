"""Mock device handler for testing without real hardware."""

import asyncio
import json
import logging
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


class MockHandler(BaseHandler):
    """Mock handler for testing provisioning workflow without real devices.

    Simulates device behavior including:
    - Connection delays
    - Configuration application
    - Firmware updates with reboot
    - Realistic device information

    Usage:
        handler = MockHandler(
            ip="192.168.1.100",
            credentials={"username": "admin", "password": ""},
            device_type="cambium",  # or mikrotik, tachyon, tarana
            simulate_failures=False,
            delay_range=(0.1, 0.5),
        )
    """

    # Simulated device data by type
    DEVICE_DATA = {
        "cambium": {
            "models": ["ePMP 3000", "ePMP Force 400", "ePMP 2000", "ePMP 1000"],
            "firmware_versions": ["4.6.1", "4.7.0", "4.7.1"],
            "config_template": {
                "system": {"deviceName": "Mock-Cambium"},
                "wireless": {"mode": "sta", "channelBandwidth": 20},
            },
        },
        "mikrotik": {
            "models": ["hAP ac2", "RB4011", "hEX S", "CCR1009"],
            "firmware_versions": ["7.11", "7.12", "7.13"],
            "config_template": {
                "identity": {"name": "Mock-MikroTik"},
                "ip": {"dhcp-client": {"interface": "ether1"}},
            },
        },
        "tachyon": {
            "models": ["301", "302", "303L", "30X"],
            "firmware_versions": ["2.3.0", "2.4.0", "2.5.0"],
            "config_template": {
                "system": {"hostname": "Mock-Tachyon"},
                "wireless": {"mode": "auto"},
            },
        },
        "tarana": {
            "models": ["G1 RN", "G1 BN"],
            "firmware_versions": ["3.0.0", "3.1.0", "3.2.0"],
            "config_template": {
                "system": {"device_name": "Mock-Tarana"},
                "radio": {"mode": "remote_node"},
            },
        },
    }

    def __init__(
        self,
        ip: str,
        credentials: Dict[str, str],
        device_type: str = "cambium",
        simulate_failures: bool = False,
        failure_rate: float = 0.1,
        delay_range: tuple = (0.1, 0.5),
        reboot_time: float = 5.0,
    ):
        super().__init__(ip, credentials)
        self._mock_device_type = device_type.lower()
        self._simulate_failures = simulate_failures
        self._failure_rate = failure_rate
        self._delay_range = delay_range
        self._reboot_time = reboot_time

        # Initialize mock device state
        self._state = self._init_device_state()
        self._config_backup: Optional[bytes] = None

    def _init_device_state(self) -> Dict[str, Any]:
        """Initialize mock device state."""
        device_data = self.DEVICE_DATA.get(self._mock_device_type, self.DEVICE_DATA["cambium"])

        return {
            "model": random.choice(device_data["models"]),
            "serial": self._generate_serial(),
            "mac": self._generate_mac(),
            "firmware": device_data["firmware_versions"][0],  # Start with oldest
            "hostname": f"Mock-{self._mock_device_type.title()}-{random.randint(1, 999):03d}",
            "uptime": random.randint(3600, 864000),  # 1 hour to 10 days
            "config": device_data["config_template"].copy(),
            "active_bank": 1,
            "rebooting": False,
        }

    def _generate_serial(self) -> str:
        """Generate a realistic serial number."""
        prefix = {
            "cambium": "CM",
            "mikrotik": "MK",
            "tachyon": "TN",
            "tarana": "TR",
        }.get(self._mock_device_type, "XX")
        return f"{prefix}{random.randint(1000000, 9999999)}"

    def _generate_mac(self) -> str:
        """Generate a realistic MAC address."""
        oui = {
            "cambium": "58:C1:7A",
            "mikrotik": "DC:2C:6E",
            "tachyon": "00:1A:2B",
            "tarana": "00:26:5A",
        }.get(self._mock_device_type, "00:00:00")
        suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
        return f"{oui}:{suffix}"

    async def _simulate_delay(self, factor: float = 1.0) -> None:
        """Simulate network/processing delay."""
        delay = random.uniform(*self._delay_range) * factor
        await asyncio.sleep(delay)

    def _should_fail(self) -> bool:
        """Determine if this operation should simulate a failure."""
        return self._simulate_failures and random.random() < self._failure_rate

    @property
    def device_type(self) -> str:
        return self._mock_device_type

    @property
    def supports_dual_bank(self) -> bool:
        return self._mock_device_type in ("cambium", "tachyon", "tarana")

    async def connect(self) -> bool:
        """Simulate connecting to the device."""
        logger.info(f"[MOCK] Connecting to {self._mock_device_type} at {self.ip}")
        await self._simulate_delay()

        if self._should_fail():
            logger.error(f"[MOCK] Simulated connection failure")
            return False

        if self._state["rebooting"]:
            logger.warning(f"[MOCK] Device is rebooting")
            return False

        self._connected = True
        logger.info(f"[MOCK] Connected to {self._state['model']}")
        return True

    async def disconnect(self) -> None:
        """Simulate disconnecting from the device."""
        await self._simulate_delay(0.5)
        self._connected = False
        logger.info(f"[MOCK] Disconnected from {self.ip}")

    async def get_info(self) -> DeviceInfo:
        """Return simulated device information."""
        await self._simulate_delay()

        info = DeviceInfo(
            device_type=self._mock_device_type,
            model=self._state["model"],
            serial_number=self._state["serial"],
            mac_address=self._state["mac"],
            hostname=self._state["hostname"],
            firmware_version=self._state["firmware"],
            ip_address=self.ip,
            uptime=self._state["uptime"],
            extra={
                "active_bank": self._state["active_bank"],
                "mock": True,
            },
        )

        self._device_info = info
        return info

    async def backup_config(self) -> bytes:
        """Simulate config backup."""
        await self._simulate_delay()

        if self._should_fail():
            raise RuntimeError("[MOCK] Simulated backup failure")

        config_json = json.dumps(self._state["config"], indent=2)
        self._config_backup = config_json.encode("utf-8")

        logger.info(f"[MOCK] Config backed up ({len(self._config_backup)} bytes)")
        return self._config_backup

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Simulate applying configuration."""
        await self._simulate_delay(2.0)

        if self._should_fail():
            logger.error(f"[MOCK] Simulated config apply failure")
            return False

        # Merge config
        self._state["config"].update(config)

        # Update hostname if in config
        if "system" in config:
            if "deviceName" in config["system"]:
                self._state["hostname"] = config["system"]["deviceName"]
            elif "device_name" in config["system"]:
                self._state["hostname"] = config["system"]["device_name"]
            elif "hostname" in config["system"]:
                self._state["hostname"] = config["system"]["hostname"]

        logger.info(f"[MOCK] Configuration applied")
        return True

    async def apply_config_file(self, config_path: str) -> bool:
        """Simulate applying configuration from file."""
        config_file = Path(config_path)
        if not config_file.exists():
            logger.error(f"[MOCK] Config file not found: {config_path}")
            return False

        with open(config_file, "r") as f:
            config = json.load(f)

        return await self.apply_config(config)

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Simulate firmware upload."""
        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            logger.error(f"[MOCK] Firmware file not found: {firmware_path}")
            return False

        file_size = firmware_file.stat().st_size

        logger.info(f"[MOCK] Uploading firmware ({file_size / 1024 / 1024:.1f} MB)...")

        # Simulate upload time based on file size (1MB per second)
        upload_time = max(1.0, file_size / (1024 * 1024))
        await asyncio.sleep(min(upload_time, 5.0))  # Cap at 5 seconds for testing

        if self._should_fail():
            logger.error(f"[MOCK] Simulated firmware upload failure")
            return False

        logger.info(f"[MOCK] Firmware uploaded successfully")
        return True

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Simulate firmware update."""
        await self._simulate_delay()

        if self._should_fail():
            logger.error(f"[MOCK] Simulated firmware update failure")
            return False

        # Update to latest firmware version
        device_data = self.DEVICE_DATA.get(self._mock_device_type, self.DEVICE_DATA["cambium"])
        new_firmware = device_data["firmware_versions"][-1]

        target_bank = bank or (2 if self._state["active_bank"] == 1 else 1)

        logger.info(f"[MOCK] Firmware update scheduled (bank {target_bank})")
        logger.info(f"[MOCK] Will update to version {new_firmware}")

        # Store pending update
        self._state["pending_firmware"] = new_firmware
        self._state["target_bank"] = target_bank

        return True

    async def reboot(self) -> bool:
        """Simulate device reboot."""
        await self._simulate_delay()

        logger.info(f"[MOCK] Rebooting device...")
        self._state["rebooting"] = True
        self._connected = False

        # Apply pending firmware update
        if "pending_firmware" in self._state:
            self._state["firmware"] = self._state.pop("pending_firmware")
            if "target_bank" in self._state:
                self._state["active_bank"] = self._state.pop("target_bank")
            logger.info(f"[MOCK] Applied firmware update")

        # Reset uptime
        self._state["uptime"] = 0

        return True

    async def get_firmware_version(self) -> str:
        """Return simulated firmware version."""
        return self._state["firmware"]

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Simulate waiting for device reboot."""
        logger.info(f"[MOCK] Waiting for device to come back online...")

        # Simulate reboot time
        await asyncio.sleep(self._reboot_time)

        self._state["rebooting"] = False
        logger.info(f"[MOCK] Device is back online")

        return True

    async def get_active_bank(self) -> int:
        """Return simulated active firmware bank."""
        return self._state["active_bank"]

    async def get_inactive_bank(self) -> int:
        """Return simulated inactive firmware bank."""
        return 2 if self._state["active_bank"] == 1 else 1

    # Additional mock-specific methods

    def set_firmware_version(self, version: str) -> None:
        """Set the mock device's firmware version (for testing)."""
        self._state["firmware"] = version

    def set_device_model(self, model: str) -> None:
        """Set the mock device's model (for testing)."""
        self._state["model"] = model

    def enable_failures(self, rate: float = 0.2) -> None:
        """Enable simulated failures at the given rate."""
        self._simulate_failures = True
        self._failure_rate = rate

    def disable_failures(self) -> None:
        """Disable simulated failures."""
        self._simulate_failures = False

    def get_state(self) -> Dict[str, Any]:
        """Return the current mock device state (for testing)."""
        return self._state.copy()
