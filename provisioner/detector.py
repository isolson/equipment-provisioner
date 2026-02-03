"""Network device detection via link-state monitoring and ARP scanning."""

import asyncio
import logging
import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import AsyncIterator, Optional, Set, Callable, Awaitable

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    """Represents a discovered network device."""
    ip_address: str
    mac_address: str
    interface: str


class DeviceDetector:
    """Detects new network devices via link-state changes and ARP scanning."""

    def __init__(
        self,
        interface: str = "eth0",
        subnet: str = "192.168.1.0/24",
        scan_delay: int = 10,
        device_boot_timeout: int = 90,
    ):
        self.interface = interface
        self.subnet = IPv4Network(subnet, strict=False)
        self.scan_delay = scan_delay
        self.device_boot_timeout = device_boot_timeout
        self._known_devices: Set[str] = set()
        self._running = False
        self._callbacks: list[Callable[[DiscoveredDevice], Awaitable[None]]] = []
        # Dedicated executor for blocking ARP operations (limit threads)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="arp")

    def on_device_discovered(self, callback: Callable[[DiscoveredDevice], Awaitable[None]]) -> None:
        """Register a callback for when a new device is discovered."""
        self._callbacks.append(callback)

    async def _notify_callbacks(self, device: DiscoveredDevice) -> None:
        """Notify all registered callbacks of a discovered device."""
        for callback in self._callbacks:
            try:
                await callback(device)
            except Exception as e:
                logger.error(f"Callback error for device {device.ip_address}: {e}")

    async def start(self) -> None:
        """Start monitoring for new devices."""
        self._running = True
        logger.info(f"Starting device detector on {self.interface} ({self.subnet})")

        # Start link state monitor and periodic scanner concurrently
        await asyncio.gather(
            self._monitor_link_state(),
            self._periodic_scan(),
        )

    def stop(self) -> None:
        """Stop monitoring for devices."""
        self._running = False
        self._executor.shutdown(wait=False)
        logger.info("Device detector stopped")

    async def _monitor_link_state(self) -> None:
        """Monitor ethernet link state changes using netlink."""
        try:
            from pyroute2 import IPRoute
        except ImportError:
            logger.warning("pyroute2 not available, using fallback link monitoring")
            await self._monitor_link_state_fallback()
            return

        logger.info("Starting link state monitor with pyroute2")

        with IPRoute() as ipr:
            # Get interface index
            links = ipr.link_lookup(ifname=self.interface)
            if not links:
                logger.error(f"Interface {self.interface} not found")
                return

            idx = links[0]

            # Bind to netlink for events
            ipr.bind()

            while self._running:
                try:
                    # Non-blocking check for events with timeout
                    messages = ipr.get()
                    for msg in messages:
                        if msg.get("index") == idx and msg.get("event") == "RTM_NEWLINK":
                            state = msg.get("state", "")
                            if "UP" in state:
                                logger.info(f"Link UP detected on {self.interface}")
                                await self._on_link_up()
                except Exception as e:
                    if "Timeout" not in str(e):
                        logger.debug(f"Link monitor: {e}")

                await asyncio.sleep(0.5)

    async def _monitor_link_state_fallback(self) -> None:
        """Fallback link state monitor using /sys filesystem."""
        operstate_path = f"/sys/class/net/{self.interface}/operstate"
        carrier_path = f"/sys/class/net/{self.interface}/carrier"

        last_state = None

        while self._running:
            try:
                # Try carrier first (more reliable)
                try:
                    with open(carrier_path, "r") as f:
                        current_state = f.read().strip() == "1"
                except (FileNotFoundError, OSError):
                    # Fall back to operstate
                    with open(operstate_path, "r") as f:
                        current_state = f.read().strip() == "up"

                if current_state and last_state == False:
                    logger.info(f"Link UP detected on {self.interface}")
                    await self._on_link_up()

                last_state = current_state

            except FileNotFoundError:
                logger.error(f"Cannot monitor interface {self.interface}")
                break
            except Exception as e:
                logger.debug(f"Link state check error: {e}")

            await asyncio.sleep(1)

    async def _on_link_up(self) -> None:
        """Handle link up event - wait for device boot then scan."""
        logger.info(f"Waiting {self.scan_delay}s for device to boot...")
        await asyncio.sleep(self.scan_delay)

        # Scan for new devices
        await self._scan_network()

    async def _periodic_scan(self) -> None:
        """Periodically scan for new devices (backup to link monitoring)."""
        while self._running:
            await asyncio.sleep(30)  # Scan every 30 seconds as backup
            await self._scan_network()

    async def _scan_network(self) -> None:
        """Scan the network for devices using ARP."""
        logger.info(f"Scanning network {self.subnet}")

        discovered = await self._arp_scan()

        for device in discovered:
            if device.mac_address not in self._known_devices:
                logger.info(f"New device discovered: {device.ip_address} ({device.mac_address})")
                self._known_devices.add(device.mac_address)
                await self._notify_callbacks(device)

    async def _arp_scan(self) -> list[DiscoveredDevice]:
        """Perform ARP scan using scapy."""
        try:
            from scapy.all import ARP, Ether, srp, conf
        except ImportError:
            logger.warning("scapy not available, using fallback ARP scan")
            return await self._arp_scan_fallback()

        conf.verb = 0  # Suppress scapy output

        devices = []

        try:
            # Create ARP request packet
            arp = ARP(pdst=str(self.subnet))
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send and receive using dedicated executor to avoid thread pool exhaustion
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    self._executor,
                    lambda: srp(packet, timeout=3, iface=self.interface, verbose=False)[0]
                ),
                timeout=15,
            )

            for sent, received in result:
                devices.append(DiscoveredDevice(
                    ip_address=received.psrc,
                    mac_address=received.hwsrc.upper(),
                    interface=self.interface,
                ))

        except Exception as e:
            logger.error(f"ARP scan failed: {e}")

        return devices

    async def _arp_scan_fallback(self) -> list[DiscoveredDevice]:
        """Fallback ARP scan using system commands and ARP cache."""
        devices = []

        # Ping sweep to populate ARP cache
        try:
            # Limit concurrent pings to avoid spawning too many processes
            semaphore = asyncio.Semaphore(50)

            async def limited_ping(host: str) -> bool:
                async with semaphore:
                    return await self._ping_host(host)

            await asyncio.gather(
                *[limited_ping(str(host)) for host in list(self.subnet.hosts())[:254]],
                return_exceptions=True
            )

        except Exception as e:
            logger.debug(f"Ping sweep error: {e}")

        # Read ARP cache
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            for line in stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "lladdr":
                    ip = parts[0]
                    mac = parts[4].upper()
                    if self._is_in_subnet(ip):
                        devices.append(DiscoveredDevice(
                            ip_address=ip,
                            mac_address=mac,
                            interface=self.interface,
                        ))

        except Exception as e:
            logger.error(f"Failed to read ARP cache: {e}")

        return devices

    async def _ping_host(self, ip: str) -> bool:
        """Ping a single host."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            return proc.returncode == 0
        except (asyncio.TimeoutError, Exception):
            return False

    def _is_in_subnet(self, ip: str) -> bool:
        """Check if an IP is in the configured subnet."""
        try:
            from ipaddress import IPv4Address
            return IPv4Address(ip) in self.subnet
        except ValueError:
            return False

    def clear_known_devices(self) -> None:
        """Clear the list of known devices to re-detect them."""
        self._known_devices.clear()
        logger.info("Cleared known devices list")

    def forget_device(self, mac_address: str) -> None:
        """Remove a device from the known list so it can be re-detected."""
        mac_upper = mac_address.upper()
        self._known_devices.discard(mac_upper)
        logger.info(f"Forgot device {mac_upper}")


async def scan_subnet_once(
    interface: str,
    subnet: str,
) -> list[DiscoveredDevice]:
    """Perform a one-time scan of the subnet."""
    detector = DeviceDetector(interface=interface, subnet=subnet)
    return await detector._arp_scan()
