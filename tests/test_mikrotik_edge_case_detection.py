"""Tests for MikroTik detection edge cases and handler safety."""

import asyncio

from provisioner.port_manager import PortManager


def test_default_vendor_detection_regression_ubiquiti() -> None:
    """Guardrail: existing non-MikroTik detection should keep working."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    async def fake_ping(_iface: str, ip: str) -> bool:
        return ip == "192.168.1.20"

    async def fake_identify(_iface: str, _ip: str, _possible_types: list[str]) -> str:
        return "ubiquiti"

    manager._ping_device = fake_ping  # type: ignore[method-assign]
    manager._identify_device_type = fake_identify  # type: ignore[method-assign]

    asyncio.run(manager._detect_device_on_port(1))
    state = manager.port_states[1]

    assert state.device_detected is True
    assert state.device_type == "ubiquiti"
    assert state.device_ip == "192.168.1.20"


def test_default_vendor_detection_regression_cambium() -> None:
    """Guardrail: MikroTik fallbacks should not break Cambium detection path."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    async def fake_ping(_iface: str, ip: str) -> bool:
        return ip == "169.254.1.1"

    async def fake_identify(_iface: str, _ip: str, _possible_types: list[str]) -> str:
        return "cambium"

    manager._ping_device = fake_ping  # type: ignore[method-assign]
    manager._identify_device_type = fake_identify  # type: ignore[method-assign]

    asyncio.run(manager._detect_device_on_port(1))
    state = manager.port_states[1]

    assert state.device_detected is True
    assert state.device_type == "cambium"
    assert state.device_ip == "169.254.1.1"


def test_mikrotik_fallback_detects_non_default_ip() -> None:
    """Expected behavior (currently missing): detect MikroTik on non-default subnets."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    ping_attempts: list[str] = []

    async def fake_ping(_iface: str, ip: str) -> bool:
        ping_attempts.append(ip)
        return ip == "192.168.0.1"

    async def fake_identify(_iface: str, ip: str, _possible_types: list[str]) -> str | None:
        if ip == "192.168.0.1":
            return "mikrotik"
        return None

    manager._ping_device = fake_ping  # type: ignore[method-assign]
    manager._identify_device_type = fake_identify  # type: ignore[method-assign]

    asyncio.run(manager._detect_device_on_port(1))
    state = manager.port_states[1]

    # This is the target behavior we want to implement next.
    assert "192.168.0.1" in ping_attempts
    assert state.device_detected is True
    assert state.device_type == "mikrotik"
    assert state.device_ip == "192.168.0.1"
