"""Port and VLAN management for multi-device provisioning.

Architecture:
- Each switch port is assigned a unique VLAN (e.g., port 1 = VLAN 101)
- OrangePi connects via trunk port with access to all VLANs
- VLAN subinterfaces created on OrangePi (e.g., eth0.101, eth0.102)
- Each VLAN interface gets a link-local IP (169.254.1.x) for device access
- Devices respond on their default link-local addresses:
  - Cambium ePMP: 169.254.1.1
  - Tachyon: 169.254.1.1
  - Tarana: 169.254.100.1
  - Ubiquiti AirMax/Wave: 192.168.1.20
  - Mikrotik: Various (often 192.168.88.1 or DHCP)
"""

import asyncio
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Awaitable, Union

logger = logging.getLogger(__name__)


@dataclass
class ProvisioningChecklist:
    """Tracks the status of each provisioning step.

    Each step can be:
    - None: Not started/not applicable
    - True: Success
    - False: Failed
    - "loading": In progress
    - "skipped": Intentionally skipped by user
    """
    login: Optional[Union[bool, str]] = None
    model_confirmed: Optional[str] = None  # Stores model name on success, None if not done
    config_upload: Optional[Union[bool, str]] = None
    firmware_banks: Optional[str] = None  # "bank1:5.10.4|bank2:5.10.4|active:1" - both bank versions
    firmware_update_1: Optional[Union[bool, str]] = None  # First firmware update: None/loading/True/False
    firmware_update_2: Optional[Union[bool, str]] = None  # Second firmware update: None/loading/True/False
    reboot: Optional[Union[bool, str]] = None
    verify: Optional[Union[bool, str]] = None

    # Device identifiers discovered during provisioning
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None

    # Track which device this checklist belongs to (to detect device changes)
    _device_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "login": self.login,
            "model_confirmed": self.model_confirmed,
            "config_upload": self.config_upload,
            "firmware_banks": self.firmware_banks,
            "firmware_update_1": self.firmware_update_1,
            "firmware_update_2": self.firmware_update_2,
            "reboot": self.reboot,
            "verify": self.verify,
            "mac_address": self.mac_address,
            "serial_number": self.serial_number,
        }

    def reset(self):
        """Reset all steps to None (for new provisioning attempt or device change)."""
        self.login = None
        self.model_confirmed = None
        self.config_upload = None
        self.firmware_banks = None
        self.firmware_update_1 = None
        self.firmware_update_2 = None
        self.reboot = None
        self.verify = None
        self.mac_address = None
        self.serial_number = None
        self._device_fingerprint = None


class DeviceLinkLocalIP:
    """Known link-local/default IPs for device types."""
    CAMBIUM = "169.254.1.1"
    TACHYON = "169.254.1.1"
    TACHYON_ALT = "192.168.1.1"  # Some Tachyon devices use this
    TARANA = "169.254.100.1"
    MIKROTIK = "192.168.88.1"  # Mikrotik default, but often uses DHCP
    UBIQUITI = "192.168.1.20"  # Ubiquiti AirMax and Wave default

    # All IPs to probe when detecting device type
    ALL = [
        ("169.254.1.1", ["cambium", "tachyon"]),
        ("192.168.1.1", ["tachyon"]),  # Tachyon alternate IP
        ("192.168.1.20", ["ubiquiti"]),  # Ubiquiti AirMax/Wave default
        ("169.254.100.1", ["tarana"]),
        ("192.168.88.1", ["mikrotik"]),
    ]


@dataclass
class PortConfig:
    """Configuration for a single switch port."""
    port_number: int
    vlan_id: int
    interface_name: str  # e.g., "eth0.101"
    local_ip: str  # OrangePi's IP on this VLAN (e.g., "169.254.1.2")
    netmask: str = "255.255.255.0"
    secondary_ips: Optional[List[str]] = None  # Additional IPs for other device types (e.g., Tarana at 169.254.100.x)
    enabled: bool = True


@dataclass
class PortState:
    """Current state of a port."""
    port_number: int
    vlan_id: int
    link_up: bool = False
    device_detected: bool = False
    device_type: Optional[str] = None
    device_ip: Optional[str] = None
    device_mac: Optional[str] = None  # MAC address (retrieved during provisioning)
    device_serial: Optional[str] = None  # Serial number (retrieved during provisioning)
    device_model: Optional[str] = None  # Device model (retrieved during fingerprint/provisioning)
    provisioning: bool = False
    last_seen: Optional[float] = None
    provisioning_ended: Optional[float] = None  # When provisioning finished (for grace period)
    ping_failures: int = 0  # Consecutive ping failures
    link_speed: Optional[str] = None  # Negotiated link speed (e.g., "1Gbps", "100Mbps")
    waiting_for_boot: bool = False  # True while waiting for device to boot
    boot_wait_until: Optional[float] = None  # Timestamp when boot wait ends
    boot_ping_responded: bool = False  # True once device responds to ping during boot
    last_result: Optional[str] = None  # "success" or "failed"
    last_error: Optional[str] = None  # Error message if failed
    checklist: ProvisioningChecklist = field(default_factory=ProvisioningChecklist)  # Step-by-step progress
    provision_attempted: bool = False  # True once provisioning has been attempted (prevents re-trigger)
    expecting_reboot: bool = False  # True during planned reboots (firmware updates)
    provisioning_task: Optional[asyncio.Task] = None  # Reference to active provisioning task for cancellation

    # Post-provisioning mode (None = SM default, "ap", "ptp-a", "ptp-b")
    device_mode: Optional[str] = None
    mode_config: Optional[Dict[str, Any]] = None  # Naming params used to configure mode
    ptp_link_id: Optional[str] = None  # Canonical PTP link ID, e.g. "tw05-tw12"


@dataclass
class ManagementConfig:
    """Management network configuration for switch-to-Pi communication."""
    enabled: bool = True
    ip: str = "192.168.88.10"  # Pi's management IP on VLAN 1990
    netmask: str = "255.255.255.0"
    switch_ip: Optional[str] = "192.168.88.1"  # Switch's IP on VLAN 1990 (for reference only)
    vlan: Optional[int] = 1990  # Management VLAN (tagged on trunk)


class PortManager:
    """Manages switch ports, VLANs, and device detection.

    Typical setup with 8-port managed switch:
    - Ports 1-6: Access ports, each in unique VLAN (1991-1996)
    - Port 7: WAN/Internet uplink
    - Port 8: Trunk port to OrangePi with all VLANs

    OrangePi creates VLAN interfaces:
    - eth0.1990 -> 192.168.88.10/24 (management, for switch webhooks)
    - eth0.1991 -> 169.254.1.2/24 (for ether1)
    - eth0.1992 -> 169.254.1.2/24 (for ether2)
    - ...etc

    Switch has IP 192.168.88.1 on VLAN 1990 and sends port status
    webhooks to Pi at 192.168.88.10:8080/api/switch/port-event
    """

    def __init__(
        self,
        base_interface: str = "eth0",
        vlan_start: int = 1991,
        num_ports: int = 6,
        local_ip_base: str = "169.254.1.2",
        management: Optional[ManagementConfig] = None,
    ):
        """Initialize port manager.

        Args:
            base_interface: Base ethernet interface (e.g., "eth0")
            vlan_start: Starting VLAN ID for ports
            num_ports: Number of provisioning ports
            local_ip_base: Local IP address for OrangePi on each VLAN
            management: Management network configuration for switch communication
        """
        self.base_interface = base_interface
        self.vlan_start = vlan_start
        self.num_ports = num_ports
        self.local_ip_base = local_ip_base
        self.management = management or ManagementConfig()

        # Port configurations
        self.ports: Dict[int, PortConfig] = {}
        self.port_states: Dict[int, PortState] = {}

        # Callbacks
        self._on_device_detected: List[Callable[[int, str, str], Awaitable[None]]] = []

        self._running = False
        self._initialized = False

    def _generate_port_configs(self) -> None:
        """Generate port configurations."""
        for i in range(self.num_ports):
            port_num = i + 1
            vlan_id = self.vlan_start + i
            interface_name = f"{self.base_interface}.{vlan_id}"

            port_config = PortConfig(
                port_number=port_num,
                vlan_id=vlan_id,
                interface_name=interface_name,
                local_ip=self.local_ip_base,
                secondary_ips=["169.254.100.2/24", "192.168.1.2/24"],  # Tarana at 169.254.100.1, Ubiquiti/Tachyon at 192.168.1.x
            )
            self.ports[port_num] = port_config
            logger.debug(f"Port {port_num} config: {interface_name}, IPs: {self.local_ip_base}, secondary: {port_config.secondary_ips}")

            self.port_states[port_num] = PortState(
                port_number=port_num,
                vlan_id=vlan_id,
            )

    async def setup(self) -> bool:
        """Setup management and VLAN interfaces on the OrangePi."""
        self._generate_port_configs()

        # Setup management interface first (for switch communication)
        if self.management.enabled:
            try:
                await self._setup_management_interface()
                logger.info(f"Management interface configured: {self.management.ip}")
            except Exception as e:
                logger.error(f"Failed to setup management interface: {e}")
                # Continue anyway - management might be configured externally

        logger.info(f"Setting up {self.num_ports} VLAN interfaces...")

        failed_ports = []
        for port_num, config in self.ports.items():
            if not config.enabled:
                continue

            try:
                # Create VLAN interface
                await self._create_vlan_interface(config)
                logger.info(f"Created {config.interface_name} for port {port_num}")

            except Exception as e:
                logger.error(f"Failed to setup port {port_num}: {e}")
                failed_ports.append(port_num)
                # Continue to set up remaining ports instead of failing entirely

        if failed_ports:
            logger.warning(f"Failed to setup ports: {failed_ports}")

        self._initialized = True
        return len(failed_ports) == 0

    async def _setup_management_interface(self) -> None:
        """Setup management network interface for switch communication.

        This configures the base interface (or a VLAN subinterface) with
        a management IP that the MikroTik switch can reach to send webhooks.
        """
        mgmt = self.management

        if mgmt.vlan:
            # Use a VLAN subinterface for management
            interface = f"{self.base_interface}.{mgmt.vlan}"
            # Create VLAN interface if needed
            if not Path(f"/sys/class/net/{interface}").exists():
                cmd = ["ip", "link", "add", "link", self.base_interface,
                       "name", interface, "type", "vlan", "id", str(mgmt.vlan)]
                await self._run_cmd(cmd)
            await self._run_cmd(["ip", "link", "set", interface, "up"])
        else:
            # Use base interface directly (native/untagged traffic)
            interface = self.base_interface
            # Ensure base interface is up
            await self._run_cmd(["ip", "link", "set", interface, "up"], check=False)

        # Assign management IP
        cidr = self._netmask_to_cidr(mgmt.netmask)
        await self._run_cmd([
            "ip", "addr", "replace",
            f"{mgmt.ip}/{cidr}",
            "dev", interface
        ])
        logger.info(f"Configured management IP {mgmt.ip}/{cidr} on {interface}")

        # Note: We don't set a default route here. The management VLAN is only
        # for switch-to-Pi communication. Internet access comes via DHCP on
        # the base interface (native VLAN).

    async def _create_vlan_interface(self, config: PortConfig) -> None:
        """Create a VLAN subinterface."""
        interface = config.interface_name
        vlan_id = config.vlan_id

        # Check if interface already exists
        if Path(f"/sys/class/net/{interface}").exists():
            logger.debug(f"Interface {interface} already exists")
        else:
            # Create VLAN interface
            cmd = ["ip", "link", "add", "link", self.base_interface,
                   "name", interface, "type", "vlan", "id", str(vlan_id)]
            await self._run_cmd(cmd)

        # Bring interface up
        await self._run_cmd(["ip", "link", "set", interface, "up"])

        # Assign IP address - use "replace" to handle existing addresses
        # This avoids the "File exists" error when IP is already assigned
        await self._run_cmd([
            "ip", "addr", "replace",
            f"{config.local_ip}/{self._netmask_to_cidr(config.netmask)}",
            "dev", interface
        ])

        # Add secondary IPs for other device types (e.g., Tarana at 169.254.100.x)
        if config.secondary_ips:
            logger.info(f"Adding {len(config.secondary_ips)} secondary IPs to {interface}")
            for secondary_ip in config.secondary_ips:
                try:
                    await self._run_cmd([
                        "ip", "addr", "replace",
                        secondary_ip,
                        "dev", interface
                    ])
                    logger.info(f"Added secondary IP {secondary_ip} to {interface}")
                except Exception as e:
                    logger.error(f"Failed to add secondary IP {secondary_ip} to {interface}: {e}")

    async def _run_cmd(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a shell command."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if check and proc.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr.decode()}")

        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)

    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert netmask to CIDR notation."""
        return sum(bin(int(x)).count('1') for x in netmask.split('.'))

    async def cleanup(self) -> None:
        """Stop monitoring. VLAN interfaces are left in place to avoid a race
        condition where the old process deletes interfaces after a new process
        has already recreated them during a service restart.  setup() handles
        existing interfaces idempotently via 'ip addr replace'."""
        self._running = False

    def on_device_detected(
        self,
        callback: Callable[[int, str, str], Awaitable[None]]
    ) -> None:
        """Register callback for device detection.

        Callback receives: (port_number, device_type, device_ip)
        """
        self._on_device_detected.append(callback)

    async def start_monitoring(self) -> None:
        """Start monitoring ports for new devices."""
        if not self._initialized:
            await self.setup()

        self._running = True
        logger.info("Starting port monitoring...")

        while self._running:
            await self._check_all_ports_parallel()
            await asyncio.sleep(2)

    async def stop_monitoring(self) -> None:
        """Stop port monitoring."""
        self._running = False

    # Grace period after provisioning before marking device as disconnected (seconds)
    PROVISIONING_GRACE_PERIOD = 180  # 3 minutes for firmware updates
    # Number of consecutive ping failures before marking device disconnected
    PING_FAILURE_THRESHOLD = 3
    # Maximum time to wait after link-up for device boot (seconds)
    BOOT_WAIT_MAX_SECONDS = 120
    # Time to wait after device responds to ping before detection (seconds)
    # Allows web server to fully initialize after device is reachable
    BOOT_WAIT_AFTER_PING = 10

    async def _check_all_ports_parallel(self) -> None:
        """Check all ports for link status and devices in parallel."""
        import time
        current_time = time.time()

        # Collect ports to check and their states
        ports_to_ping = []
        ports_to_detect = []
        ports_to_boot_ping = []  # Ports waiting for boot that need ping check

        for port_num, config in self.ports.items():
            if not config.enabled:
                continue

            state = self.port_states[port_num]

            # Skip ports currently being provisioned
            if state.provisioning:
                continue

            # Check if waiting for device boot
            if state.waiting_for_boot:
                if state.boot_wait_until and current_time >= state.boot_wait_until:
                    # Boot wait is over, ready to detect
                    logger.info(f"Port {port_num} boot wait complete, starting detection")
                    state.waiting_for_boot = False
                    state.boot_wait_until = None
                    state.boot_ping_responded = False
                    ports_to_detect.append((port_num, config))
                elif not state.boot_ping_responded:
                    # Still waiting - ping to check if device is up
                    ports_to_boot_ping.append((port_num, config, state))
                    remaining = int(state.boot_wait_until - current_time) if state.boot_wait_until else 0
                    logger.debug(f"Port {port_num} waiting for boot, {remaining}s remaining")
                else:
                    # Ping responded, just waiting for web server init
                    remaining = int(state.boot_wait_until - current_time) if state.boot_wait_until else 0
                    logger.debug(f"Port {port_num} ping OK, waiting {remaining}s for web init")
                continue

            # Check if in grace period after provisioning
            in_grace_period = (
                state.provisioning_ended is not None and
                current_time - state.provisioning_ended < self.PROVISIONING_GRACE_PERIOD
            )

            if state.device_detected and state.device_ip:
                # Device was detected - ping to verify it's still there
                if not in_grace_period:
                    ports_to_ping.append((port_num, config, state))
            else:
                # No device detected - try to detect
                ports_to_detect.append((port_num, config))

        # Ping detected devices in parallel
        if ports_to_ping:
            async def ping_check(port_num: int, config: PortConfig, state: PortState) -> None:
                """Ping a device and update state."""
                if await self._ping_device(config.interface_name, state.device_ip):
                    # Device responded - reset failure counter
                    state.ping_failures = 0
                    state.last_seen = time.time()
                else:
                    # Device didn't respond
                    state.ping_failures += 1
                    if state.ping_failures >= self.PING_FAILURE_THRESHOLD:
                        logger.info(f"Port {port_num} device disconnected (no ping response)")
                        state.link_up = False
                        state.device_detected = False
                        state.device_type = None
                        state.device_ip = None
                        state.ping_failures = 0
                        state.provision_attempted = False  # Reset for next detection
                        self.clear_device_mode(port_num)

            ping_tasks = [
                ping_check(port_num, config, state)
                for port_num, config, state in ports_to_ping
            ]
            await asyncio.gather(*ping_tasks, return_exceptions=True)

        # Ping devices during boot wait to detect when they're responsive
        if ports_to_boot_ping:
            logger.info(f"Boot-pinging ports: {[p[0] for p in ports_to_boot_ping]}")

            async def boot_ping_check(port_num: int, config: PortConfig, state: PortState) -> None:
                """Ping device during boot wait to detect when it's up."""
                # Try known device IPs for boot detection
                ips_to_try = [
                    DeviceLinkLocalIP.CAMBIUM,   # 169.254.1.1
                    DeviceLinkLocalIP.UBIQUITI,  # 192.168.1.20
                    DeviceLinkLocalIP.MIKROTIK,  # 192.168.88.1
                    DeviceLinkLocalIP.TARANA,    # 169.254.100.1
                ]
                for ip in ips_to_try:
                    if await self._ping_device(config.interface_name, ip):
                        # Device responded! Set timer for web server init
                        state.boot_ping_responded = True
                        state.boot_wait_until = time.time() + self.BOOT_WAIT_AFTER_PING
                        remaining = int(state.boot_wait_until - time.time())
                        logger.info(f"Port {port_num} device responded to ping at {ip}, waiting {remaining}s for web server")
                        break

            boot_ping_tasks = [
                boot_ping_check(port_num, config, state)
                for port_num, config, state in ports_to_boot_ping
            ]
            await asyncio.gather(*boot_ping_tasks, return_exceptions=True)

        # Detect devices on ports without detected devices
        if ports_to_detect:
            detection_tasks = [
                self._detect_device_on_port(port_num)
                for port_num, config in ports_to_detect
            ]
            await asyncio.gather(*detection_tasks, return_exceptions=True)

    async def _check_link_status(self, interface: str) -> bool:
        """Check if interface has link."""
        carrier_path = f"/sys/class/net/{interface}/carrier"
        try:
            with open(carrier_path, "r") as f:
                return f.read().strip() == "1"
        except (FileNotFoundError, OSError):
            return False

    async def _detect_device_on_port(self, port_num: int) -> None:
        """Detect what device is connected to a port."""
        config = self.ports[port_num]
        state = self.port_states[port_num]

        ips_to_try = [ip for ip, _ in DeviceLinkLocalIP.ALL]
        logger.info(f"Detecting device on port {port_num} ({config.interface_name}), trying IPs: {ips_to_try}")

        # Try each known device IP
        for device_ip, possible_types in DeviceLinkLocalIP.ALL:
            ping_result = await self._ping_device(config.interface_name, device_ip)
            if ping_result:
                logger.info(f"Device responding at {device_ip} on port {port_num}")

                # Identify exact type by probing
                device_type = await self._identify_device_type(
                    config.interface_name,
                    device_ip,
                    possible_types
                )

                if device_type:
                    state.link_up = True
                    state.device_detected = True
                    state.device_type = device_type
                    state.device_ip = device_ip
                    state.last_seen = asyncio.get_event_loop().time()

                    logger.info(f"Detected {device_type} on port {port_num}")

                    # Notify callbacks only if provisioning hasn't been attempted yet
                    if not state.provision_attempted:
                        state.provision_attempted = True
                        for callback in self._on_device_detected:
                            try:
                                await callback(port_num, device_type, device_ip)
                            except Exception as e:
                                logger.error(f"Callback error: {e}")
                    else:
                        logger.debug(f"Port {port_num} provisioning already attempted, skipping callback")

                    return

        logger.warning(f"No known device detected on port {port_num}")

    async def _ping_device(self, interface: str, ip: str) -> bool:
        """Ping a device through a specific interface."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", "-I", interface, ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def _identify_device_type(
        self,
        interface: str,
        ip: str,
        possible_types: List[str]
    ) -> Optional[str]:
        """Identify the exact device type by probing."""
        import aiohttp

        # If only one possible type, return it
        if len(possible_types) == 1:
            return possible_types[0]

        # Need to probe to distinguish (e.g., Cambium vs Tachyon at 169.254.1.1)
        # Use fingerprint module for proper weighted scoring
        try:
            from .fingerprint import identify_device, DeviceType
            fingerprint = await identify_device(ip, timeout=5.0, interface=interface)
            if fingerprint.device_type != DeviceType.UNKNOWN:
                detected = fingerprint.device_type.value
                logger.debug(f"Fingerprint identified {detected} at {ip} via {interface} "
                            f"(confidence: {fingerprint.confidence:.0%})")
                return detected
        except Exception as e:
            logger.debug(f"Fingerprint identification failed: {e}")

        # Fallback: simple HTTP probe with correct priority using curl (interface-bound)
        try:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{ip}/"
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-k", "-L", "-m", "5",  # -L follows redirects
                        "--interface", interface,
                        "-i",  # Include headers to see Server header
                        url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()

                    if proc.returncode == 0 and stdout:
                        text = stdout.decode("utf-8", errors="ignore")
                        text_lower = text.lower()

                        # Check Tachyon FIRST (more specific patterns)
                        if any(x in text_lower for x in ["tachyon", "tn30", "tn-30", "xavante"]):
                            return "tachyon"

                        # Check Cambium (but require specific patterns, not just "pmp")
                        if any(x in text_lower for x in ["cambium", "epmp"]):
                            return "cambium"

                        # Check Tarana
                        if any(x in text_lower for x in ["tarana", "g1 node", "g1 base"]):
                            return "tarana"

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Device identification error: {e}")

        # Default to first possible type
        return possible_types[0] if possible_types else None

    def get_interface_for_port(self, port_num: int) -> Optional[str]:
        """Get the VLAN interface name for a port."""
        config = self.ports.get(port_num)
        return config.interface_name if config else None

    def get_device_ip_for_port(self, port_num: int) -> Optional[str]:
        """Get the detected device IP for a port."""
        state = self.port_states.get(port_num)
        return state.device_ip if state else None

    def get_available_ports(self) -> List[int]:
        """Get list of ports with devices ready for provisioning."""
        return [
            port_num for port_num, state in self.port_states.items()
            if state.device_detected and not state.provisioning
        ]

    def mark_port_provisioning(
        self,
        port_num: int,
        provisioning: bool = True,
        success: bool = False,
        error: Optional[str] = None,
    ) -> None:
        """Mark a port as currently being provisioned.

        Args:
            port_num: Port number
            provisioning: True if starting, False if ending
            success: If ending, whether provisioning succeeded (for grace period)
            error: Error message if failed
        """
        import time
        if port_num in self.port_states:
            state = self.port_states[port_num]
            state.provisioning = provisioning
            if not provisioning:
                # Only start grace period for successful provisioning (firmware updates need reboot time)
                if success:
                    state.provisioning_ended = time.time()
                    state.last_result = "success"
                    state.last_error = None
                else:
                    state.provisioning_ended = None  # No grace period for failures
                    state.last_result = "failed"
                    state.last_error = error
                state.ping_failures = 0  # Reset ping failures

    def set_expecting_reboot(self, port_num: int, expecting: bool) -> None:
        """Set whether a port is expecting a planned reboot (firmware update).

        When True, link-down events during provisioning are ignored.
        When False, link-down events during provisioning cancel the task.
        """
        if port_num in self.port_states:
            self.port_states[port_num].expecting_reboot = expecting
            logger.debug(f"Port {port_num} expecting_reboot={expecting}")

    def update_port_device_info(
        self,
        port_num: int,
        mac: Optional[str] = None,
        serial: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        """Update device info for a port (called by handlers after login).

        Args:
            port_num: Port number
            mac: Device MAC address
            serial: Device serial number
            model: Device model
        """
        if port_num in self.port_states:
            state = self.port_states[port_num]
            if mac:
                state.device_mac = mac
                state.checklist.mac_address = mac
            if serial:
                state.device_serial = serial
                state.checklist.serial_number = serial
            if model:
                state.device_model = model

    def update_checklist(
        self,
        port_num: int,
        step: str,
        status: Optional[Union[bool, str]],
    ) -> None:
        """Update a specific checklist step for a port.

        Args:
            port_num: Port number
            step: Step name (login, model_confirmed, config_upload, firmware_upload, firmware_update, reboot, verify)
            status: True for success, False for failure, "skipped" for skipped, or model name for model_confirmed
        """
        if port_num in self.port_states:
            state = self.port_states[port_num]
            if hasattr(state.checklist, step):
                setattr(state.checklist, step, status)
                logger.debug(f"Port {port_num} checklist: {step} = {status}")

    def reset_checklist(self, port_num: int) -> None:
        """Reset the checklist for a port (for new device or re-provisioning).

        Args:
            port_num: Port number
        """
        if port_num in self.port_states:
            state = self.port_states[port_num]
            state.checklist.reset()
            logger.debug(f"Port {port_num} checklist reset")

    def get_port_status(self) -> Dict[int, Dict]:
        """Get status of all ports."""
        import time
        current_time = time.time()
        return {
            port_num: {
                "vlan_id": state.vlan_id,
                "link_up": state.link_up,
                "device_detected": state.device_detected,
                "device_type": state.device_type,
                "device_ip": state.device_ip,
                "device_mac": state.device_mac,
                "device_serial": state.device_serial,
                "device_model": state.device_model,
                "provisioning": state.provisioning,
                "link_speed": state.link_speed,
                "waiting_for_boot": state.waiting_for_boot,
                "boot_wait_remaining": max(0, int(state.boot_wait_until - current_time)) if state.boot_wait_until else None,
                "last_result": state.last_result,
                "last_error": state.last_error,
                "checklist": state.checklist.to_dict(),
                "device_mode": state.device_mode,
                "mode_config": state.mode_config,
                "ptp_link_id": state.ptp_link_id,
            }
            for port_num, state in self.port_states.items()
        }

    def _get_single_port_status(self, port_num: int) -> Dict:
        """Get status of a single port for WebSocket notifications."""
        import time
        current_time = time.time()
        state = self.port_states.get(port_num)
        if not state:
            return {}
        return {
            "vlan_id": state.vlan_id,
            "link_up": state.link_up,
            "device_detected": state.device_detected,
            "device_type": state.device_type,
            "device_ip": state.device_ip,
            "device_mac": state.device_mac,
            "device_serial": state.device_serial,
            "device_model": state.device_model,
            "provisioning": state.provisioning,
            "link_speed": state.link_speed,
            "waiting_for_boot": state.waiting_for_boot,
            "boot_wait_remaining": max(0, int(state.boot_wait_until - current_time)) if state.boot_wait_until else None,
            "last_result": state.last_result,
            "last_error": state.last_error,
            "checklist": state.checklist.to_dict(),
            "device_mode": state.device_mode,
            "mode_config": state.mode_config,
            "ptp_link_id": state.ptp_link_id,
        }

    def _map_switch_port_to_port_num(self, switch_port: str) -> Optional[int]:
        """Map MikroTik switch port name to our port number.

        MikroTik uses names like 'ether1', 'ether2', etc.
        We map ether1 -> port 1, ether2 -> port 2, etc.
        """
        if switch_port.startswith("ether"):
            try:
                return int(switch_port[5:])
            except ValueError:
                pass
        # Also support "port1", "port2" format
        if switch_port.startswith("port"):
            try:
                return int(switch_port[4:])
            except ValueError:
                pass
        return None

    async def handle_switch_port_event(
        self,
        switch_port: str,
        link_up: bool,
        speed: Optional[str] = None,
    ) -> bool:
        """Handle a port status event from the MikroTik switch.

        Called via webhook when the switch detects link changes.
        This is faster than polling and allows immediate device detection.

        Args:
            switch_port: MikroTik port name (e.g., 'ether1', 'ether2')
            link_up: Whether the port has link
            speed: Optional link speed info

        Returns:
            True if the event was handled, False if port not found
        """
        port_num = self._map_switch_port_to_port_num(switch_port)
        if port_num is None or port_num not in self.port_states:
            logger.warning(f"Unknown switch port in event: {switch_port}")
            return False

        state = self.port_states[port_num]
        config = self.ports[port_num]

        speed_info = f" at {speed}" if speed else ""
        logger.info(f"Switch event: port {port_num} ({switch_port}) link {'up' if link_up else 'down'}{speed_info}")

        import time

        if link_up:
            # Link came up - mark link up and start boot wait
            state.link_up = True
            state.ping_failures = 0
            state.link_speed = speed

            # Only start boot wait if not currently provisioning, no device detected, and not already waiting
            if not state.provisioning and not state.device_detected and not state.waiting_for_boot:
                # Start boot wait timer - will ping until device responds, then wait for web init
                state.waiting_for_boot = True
                state.boot_ping_responded = False
                state.boot_wait_until = time.time() + self.BOOT_WAIT_MAX_SECONDS
                logger.info(f"Port {port_num} link up, waiting for device to boot (max {self.BOOT_WAIT_MAX_SECONDS}s)")
            elif state.waiting_for_boot:
                logger.debug(f"Port {port_num} link flap during boot wait, ignoring")

        else:
            # Link went down - only clear state if not provisioning and not waiting for boot
            # During provisioning or boot wait, devices may cause link flaps
            if state.provisioning:
                if state.expecting_reboot:
                    logger.debug(f"Ignoring link down on port {port_num} during expected reboot")
                else:
                    # Unexpected link loss during provisioning — device was likely unplugged
                    logger.warning(f"Unexpected link down on port {port_num} during provisioning — cancelling and resetting")
                    if state.provisioning_task and not state.provisioning_task.done():
                        state.provisioning_task.cancel()
                    state.provisioning = False
                    state.provisioning_task = None
                    state.expecting_reboot = False
                    state.link_up = False
                    state.device_detected = False
                    state.device_type = None
                    state.device_ip = None
                    state.device_mac = None
                    state.device_serial = None
                    state.device_model = None
                    state.ping_failures = 0
                    state.link_speed = None
                    state.waiting_for_boot = False
                    state.boot_wait_until = None
                    state.boot_ping_responded = False
                    state.last_result = None
                    state.last_error = None
                    state.provision_attempted = False
                    state.provisioning_ended = None
                    state.checklist.reset()
                    self.clear_device_mode(port_num)
                    logger.info(f"Port {port_num} fully reset after unexpected unplug")
            elif state.waiting_for_boot:
                logger.debug(f"Ignoring link down on port {port_num} during boot wait")
            else:
                state.link_up = False
                state.device_detected = False
                state.device_type = None
                state.device_ip = None
                state.device_mac = None
                state.device_serial = None
                state.device_model = None
                state.ping_failures = 0
                state.link_speed = None
                state.waiting_for_boot = False
                state.boot_wait_until = None
                state.boot_ping_responded = False
                state.last_result = None
                state.last_error = None
                state.provision_attempted = False  # Reset for next link cycle
                state.checklist.reset()  # Reset checklist when device disconnects
                self.clear_device_mode(port_num)
                logger.info(f"Port {port_num} device disconnected (link down)")

        # Immediately broadcast port update via WebSocket
        try:
            from provisioner.web.websocket import notify_port_change
            port_status = self._get_single_port_status(port_num)
            asyncio.create_task(notify_port_change(port_num, port_status))
        except Exception as e:
            logger.debug(f"Failed to broadcast port update: {e}")

        return True

    # ------------------------------------------------------------------
    # Device mode & PTP link tracking
    # ------------------------------------------------------------------

    # In-memory PTP link registry.
    # Maps link_id (e.g. "tw05-tw12") -> {
    #   "side_a_port": int | None,
    #   "side_b_port": int | None,
    #   "device_type": str,
    #   "my_tower": int,
    #   "remote_tower": int,
    # }
    _ptp_links: Dict[str, Dict[str, Any]] = {}

    def set_device_mode(
        self,
        port_num: int,
        mode: str,
        mode_config: Dict[str, Any],
        ptp_link_id: Optional[str] = None,
    ) -> None:
        """Set the device mode for a port after mode config is applied.

        Args:
            port_num: Port number.
            mode: One of "ap", "ptp-a", "ptp-b".
            mode_config: Naming parameters used (tower, direction, etc.).
            ptp_link_id: Canonical PTP link ID (required for PTP modes).
        """
        state = self.port_states.get(port_num)
        if not state:
            return

        state.device_mode = mode
        state.mode_config = mode_config
        state.ptp_link_id = ptp_link_id

        # Update PTP link registry
        if ptp_link_id and mode in ("ptp-a", "ptp-b"):
            link = self._ptp_links.setdefault(ptp_link_id, {
                "side_a_port": None,
                "side_b_port": None,
                "device_type": state.device_type,
                "my_tower": mode_config.get("my_tower"),
                "remote_tower": mode_config.get("remote_tower"),
            })
            if mode == "ptp-a":
                link["side_a_port"] = port_num
            else:
                link["side_b_port"] = port_num

        logger.info(f"Port {port_num} mode set to {mode}"
                     + (f" (link {ptp_link_id})" if ptp_link_id else ""))

    def clear_device_mode(self, port_num: int) -> None:
        """Clear mode info for a port (called on disconnect)."""
        state = self.port_states.get(port_num)
        if not state:
            return

        # Clean up PTP link registry
        if state.ptp_link_id and state.ptp_link_id in self._ptp_links:
            link = self._ptp_links[state.ptp_link_id]
            if link.get("side_a_port") == port_num:
                link["side_a_port"] = None
            if link.get("side_b_port") == port_num:
                link["side_b_port"] = None
            # Remove link entry if both sides are gone
            if link.get("side_a_port") is None and link.get("side_b_port") is None:
                del self._ptp_links[state.ptp_link_id]

        state.device_mode = None
        state.mode_config = None
        state.ptp_link_id = None

    def get_ptp_link(self, link_id: str) -> Optional[Dict[str, Any]]:
        """Get PTP link info by link ID."""
        return self._ptp_links.get(link_id)

    def get_ptp_links(self) -> Dict[str, Dict[str, Any]]:
        """Get all active PTP links."""
        return dict(self._ptp_links)

    def get_available_ptp_side(
        self, my_tower: int, remote_tower: int
    ) -> str:
        """Determine which PTP side to assign (auto A or B).

        Returns "a" if no existing link, or "a" side is unoccupied.
        Returns "b" if side A is already taken for this link.
        """
        from .mode_config import make_ptp_link_id
        link_id = make_ptp_link_id(my_tower, remote_tower)
        link = self._ptp_links.get(link_id)
        if link is None or link.get("side_a_port") is None:
            return "a"
        return "b"

    def get_switch_port_mapping(self) -> Dict[str, int]:
        """Get mapping of MikroTik port names to our port numbers.

        Used by the switch config script.
        """
        return {
            f"ether{port_num}": port_num
            for port_num in self.ports.keys()
        }


# Global port manager instance
_port_manager: Optional[PortManager] = None


def get_port_manager() -> PortManager:
    """Get the global port manager instance."""
    if _port_manager is None:
        raise RuntimeError("Port manager not initialized")
    return _port_manager


def init_port_manager(
    base_interface: str = "eth0",
    vlan_start: int = 1991,
    num_ports: int = 6,
    local_ip_base: str = "169.254.1.2",
    management: Optional[ManagementConfig] = None,
) -> PortManager:
    """Initialize the global port manager.

    Args:
        base_interface: Base ethernet interface (e.g., "eth0")
        vlan_start: Starting VLAN ID for ports
        num_ports: Number of provisioning ports
        local_ip_base: Local IP address for OrangePi on each VLAN
        management: Management network config for switch webhook communication
    """
    global _port_manager
    _port_manager = PortManager(
        base_interface=base_interface,
        vlan_start=vlan_start,
        num_ports=num_ports,
        local_ip_base=local_ip_base,
        management=management,
    )
    return _port_manager
