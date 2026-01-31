"""Device fingerprinting and identification."""

import asyncio
import logging
import re
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


def _create_bound_socket(interface: str, family: int = socket.AF_INET) -> socket.socket:
    """Create a socket bound to a specific network interface.

    Args:
        interface: Network interface name (e.g., 'eth0.1992')
        family: Socket family (AF_INET or AF_INET6)

    Returns:
        Socket bound to the interface
    """
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # SO_BINDTODEVICE requires root/CAP_NET_RAW
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
    except PermissionError:
        logger.warning(f"Cannot bind to interface {interface} - need root or CAP_NET_RAW")
    return sock


class DeviceType(str, Enum):
    """Supported device types."""
    MIKROTIK = "mikrotik"
    CAMBIUM = "cambium"
    TACHYON = "tachyon"
    TARANA = "tarana"
    UBIQUITI = "ubiquiti"
    UNKNOWN = "unknown"


@dataclass
class DeviceFingerprint:
    """Result of device fingerprinting."""
    device_type: DeviceType
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    confidence: float = 0.0


class DeviceFingerprinter:
    """Identifies network devices by probing common ports and services."""

    # Known HTTP response signatures (more specific patterns first)
    # Patterns are weighted - more specific patterns have higher weight
    HTTP_SIGNATURES = {
        DeviceType.MIKROTIK: [
            (r"RouterOS", 3),
            (r"MikroTik", 3),
            (r"mikrotik", 2),
            (r"webfig", 2),
        ],
        DeviceType.CAMBIUM: [
            (r"Cambium\s*Networks", 3),
            (r"Cambium HTTP Server", 5),  # Strong indicator from Server header
            (r"cambium", 2),
            (r"Cambium", 2),
            (r"ePMP\s*\d+", 3),  # ePMP followed by model number
            (r"ePMP", 2),
            (r"PMP\s*\d+", 2),  # PMP followed by model number (e.g., PMP 450)
            (r"cnPilot", 2),
        ],
        DeviceType.TACHYON: [
            (r"Tachyon\s*Networks", 3),
            (r"tachyon", 2),
            (r"Tachyon", 2),
            (r"TN-?30", 3),  # TN30 or TN-30
            (r"30[123]L?", 1),  # Tachyon model numbers
            (r"cgi\.lua", 4),  # Tachyon REST API uses cgi.lua
            (r"apiv1", 4),  # Tachyon REST API version
            (r"Xavante", 5),  # Tachyon uses Xavante web server (strong indicator)
            (r"8DEVICES", 5),  # Tachyon manufacturer (8DEVICES UAB)
        ],
        DeviceType.TARANA: [
            (r"Tarana\s*Wireless", 3),
            (r"tarana", 2),
            (r"Tarana", 2),
            (r"G1\s*(?:Node|Base)", 3),  # G1 Node or G1 Base
        ],
        DeviceType.UBIQUITI: [
            (r"AirOS", 5),
            (r"airOS", 5),
            (r"UBNT", 4),
            (r"ubnt", 3),
            (r"Ubiquiti", 3),
            (r"ui\.com", 2),
            (r"AirMax", 3),
            (r"airmax", 3),
            (r"lighttpd", 2),        # Common Ubiquiti web server
            (r"Wave", 2),
            (r"login\.cgi", 4),      # airOS login endpoint
        ],
    }

    # Default ports to probe
    PROBE_PORTS = {
        80: "http",
        443: "https",
        22: "ssh",
        8728: "routeros_api",  # MikroTik API
        8729: "routeros_api_ssl",
        161: "snmp",
    }

    def __init__(self, timeout: float = 5.0, interface: Optional[str] = None):
        self.timeout = timeout
        self.interface = interface

    async def fingerprint(self, ip: str, mac: Optional[str] = None) -> DeviceFingerprint:
        """Fingerprint a device at the given IP address."""
        if self.interface:
            logger.info(f"Fingerprinting device at {ip} via {self.interface}")
        else:
            logger.info(f"Fingerprinting device at {ip}")

        # Probe open ports
        open_ports = await self._scan_ports(ip)
        logger.debug(f"Open ports on {ip}: {open_ports}")

        # Try different identification methods based on open ports
        fingerprint = DeviceFingerprint(
            device_type=DeviceType.UNKNOWN,
            mac_address=mac,
        )

        # MikroTik API port is a strong indicator
        if 8728 in open_ports or 8729 in open_ports:
            fingerprint.device_type = DeviceType.MIKROTIK
            fingerprint.confidence = 0.95
            await self._get_mikrotik_info(ip, fingerprint)
            return fingerprint

        # Try Tachyon API probe first (most specific)
        if 80 in open_ports or 443 in open_ports:
            tachyon_result = await self._probe_tachyon_api(ip, 443 in open_ports)
            if tachyon_result:
                tachyon_result.mac_address = mac
                return tachyon_result

        # Try HTTP identification
        if 80 in open_ports or 443 in open_ports:
            http_result = await self._probe_http(ip, 443 in open_ports)
            if http_result:
                fingerprint = http_result
                fingerprint.mac_address = mac

                # For Cambium, fetch SKU file to get exact model and firmware
                if fingerprint.device_type == DeviceType.CAMBIUM:
                    await self._fetch_cambium_sku(ip, fingerprint)

        # Try SSH banner if HTTP didn't identify
        if fingerprint.device_type == DeviceType.UNKNOWN and 22 in open_ports:
            ssh_result = await self._probe_ssh_banner(ip)
            if ssh_result:
                fingerprint.device_type = ssh_result[0]
                fingerprint.model = ssh_result[1]
                fingerprint.confidence = 0.7

        # Try SNMP as last resort
        if fingerprint.device_type == DeviceType.UNKNOWN and 161 in open_ports:
            snmp_result = await self._probe_snmp(ip)
            if snmp_result:
                fingerprint.device_type = snmp_result[0]
                fingerprint.model = snmp_result[1]
                fingerprint.confidence = 0.6

        logger.info(f"Fingerprint result for {ip}: {fingerprint.device_type.value} "
                    f"(confidence: {fingerprint.confidence:.0%})")
        return fingerprint

    async def _scan_ports(self, ip: str) -> list[int]:
        """Scan common ports to determine which services are available."""
        open_ports = []

        async def check_port(port: int) -> Optional[int]:
            try:
                if self.interface:
                    # Use curl to check port when interface binding is needed
                    # SO_BINDTODEVICE doesn't work reliably for link-local addresses
                    scheme = "https" if port == 443 else "http"
                    if port in (80, 443):
                        url = f"{scheme}://{ip}:{port}/"
                    else:
                        # For non-HTTP ports, try TCP connect via curl's telnet
                        # Just check if we can reach port 80/443 and infer others
                        return None

                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-k", "-m", "2",
                        "--interface", self.interface,
                        "-o", "/dev/null",
                        "-w", "%{http_code}",
                        url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    # Any HTTP response (even 4xx/5xx) means port is open
                    if proc.returncode == 0 or stdout:
                        return port
                    return None
                else:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        tasks = [check_port(port) for port in self.PROBE_PORTS.keys()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, int):
                open_ports.append(result)

        logger.debug(f"Port scan for {ip} via {self.interface or 'default'}: {open_ports}")
        return open_ports

    async def _probe_http(self, ip: str, try_https: bool = True) -> Optional[DeviceFingerprint]:
        """Probe HTTP/HTTPS for device identification."""
        schemes = ["https", "http"] if try_https else ["http"]

        for scheme in schemes:
            try:
                url = f"{scheme}://{ip}/"
                timeout = aiohttp.ClientTimeout(total=self.timeout)

                # Create connector - bind to interface if specified
                if self.interface:
                    # Use a custom connector that binds to the interface
                    connector = aiohttp.TCPConnector(
                        ssl=False,
                        family=socket.AF_INET,
                    )
                    # We need to use a workaround since aiohttp doesn't directly support SO_BINDTODEVICE
                    # Use curl as fallback for interface-bound requests
                    result = await self._curl_probe(url)
                    if result:
                        return result
                    continue
                else:
                    connector = aiohttp.TCPConnector(ssl=False)

                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    async with session.get(
                        url,
                        ssl=False,  # Don't verify SSL
                        allow_redirects=True,
                    ) as response:
                        headers = dict(response.headers)
                        body = await response.text()

                        return self._analyze_http_response(headers, body)

            except Exception as e:
                logger.debug(f"HTTP probe failed for {scheme}://{ip}: {e}")
                continue

        return None

    async def _probe_tachyon_api(self, ip: str, try_https: bool = True) -> Optional[DeviceFingerprint]:
        """Probe for Tachyon REST API at /cgi.lua/apiv1/ and /login."""
        schemes = ["https", "http"] if try_https else ["http"]

        for scheme in schemes:
            # Try /login endpoint first (POST request)
            try:
                login_url = f"{scheme}://{ip}/login"

                if self.interface:
                    # Use curl with interface binding - POST to /login
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-k", "-m", str(int(self.timeout)),
                        "--interface", self.interface,
                        "-X", "POST",
                        "-H", "Content-Type: application/json",
                        "-d", '{"username":"probe","password":"probe"}',
                        login_url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()

                    if proc.returncode == 0 and stdout:
                        response = stdout.decode("utf-8", errors="ignore")
                        logger.debug(f"Tachyon /login probe response from {ip}: {response[:200]}")
                        # Tachyon /login returns JSON with specific error format
                        # May also return "redirect" on HTTPS endpoints
                        if any(x in response for x in ["Authorization Failed", "Invalid credentials", "statusCode", "cgi.lua", '"redirect"']):
                            logger.info(f"Detected Tachyon via /login endpoint at {ip}")
                            return DeviceFingerprint(
                                device_type=DeviceType.TACHYON,
                                confidence=0.95,
                            )
                    else:
                        logger.debug(f"Tachyon /login probe failed for {ip}: rc={proc.returncode}")
                else:
                    # Use aiohttp without interface binding
                    timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
                    async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                        async with session.post(
                            login_url,
                            json={"username": "probe", "password": "probe"},
                            ssl=False
                        ) as response:
                            text = await response.text()
                            if any(x in text for x in ["Authorization Failed", "Invalid credentials", "statusCode", "cgi.lua", '"redirect"']):
                                logger.info(f"Detected Tachyon via /login endpoint at {ip}")
                                return DeviceFingerprint(
                                    device_type=DeviceType.TACHYON,
                                    confidence=0.95,
                                )

            except Exception as e:
                logger.debug(f"Tachyon /login probe failed for {scheme}://{ip}: {e}")

            # Try /cgi.lua/apiv1/ endpoint (GET request)
            try:
                url = f"{scheme}://{ip}/cgi.lua/apiv1/"
                logger.debug(f"Probing Tachyon API at {url} via {self.interface}")

                if self.interface:
                    # Use curl with interface binding
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-k", "-m", str(int(self.timeout)),
                        "--interface", self.interface,
                        url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    logger.debug(f"Tachyon API probe result: rc={proc.returncode}, stdout={stdout[:200] if stdout else None}")

                    if proc.returncode == 0 and stdout:
                        response = stdout.decode("utf-8", errors="ignore")
                        # Tachyon API returns JSON with "cgi.lua" or "apiv1" in path
                        # Even 401 unauthorized confirms it's Tachyon
                        # May also return "redirect" on HTTPS endpoints
                        if any(x in response for x in ["apiv1", "cgi.lua", "Authorization Failed", '"redirect"']):
                            logger.info(f"Detected Tachyon via REST API at {ip}")
                            return DeviceFingerprint(
                                device_type=DeviceType.TACHYON,
                                confidence=0.95,
                            )
                        else:
                            logger.debug(f"Tachyon API probe response didn't match patterns: {response[:100]}")
                else:
                    # Use aiohttp without interface binding
                    timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
                    async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                        async with session.get(url, ssl=False) as response:
                            text = await response.text()
                            if any(x in text for x in ["apiv1", "cgi.lua", "Authorization Failed", '"redirect"']):
                                logger.info(f"Detected Tachyon via REST API at {ip}")
                                return DeviceFingerprint(
                                    device_type=DeviceType.TACHYON,
                                    confidence=0.95,
                                )

            except Exception as e:
                logger.debug(f"Tachyon API probe failed for {scheme}://{ip}: {e}")
                continue

        return None

    async def _curl_probe(self, url: str) -> Optional[DeviceFingerprint]:
        """Use curl to probe HTTP with interface binding."""
        if not self.interface:
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-L",  # -L follows redirects
                "-m", str(int(self.timeout)),
                "--interface", self.interface,
                "-i",  # Include headers
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0 and stdout:
                response = stdout.decode("utf-8", errors="ignore")

                # Split headers and body - handle both \r\n and \n line endings
                if "\r\n\r\n" in response:
                    parts = response.split("\r\n\r\n", 1)
                    line_sep = "\r\n"
                elif "\n\n" in response:
                    parts = response.split("\n\n", 1)
                    line_sep = "\n"
                else:
                    # No clear separator, treat whole thing as body
                    parts = ["", response]
                    line_sep = "\n"

                headers_str = parts[0] if parts else ""
                body = parts[1] if len(parts) > 1 else ""

                # Parse headers into dict
                headers = {}
                for line in headers_str.split(line_sep):
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        headers[key] = value

                logger.debug(f"curl probe {url}: got {len(headers)} headers, {len(body)} bytes body")
                return self._analyze_http_response(headers, body)
            else:
                logger.debug(f"curl probe {url} failed: rc={proc.returncode}, stderr={stderr.decode()}")

        except Exception as e:
            logger.debug(f"curl probe failed for {url}: {e}")

        return None

    def _analyze_http_response(self, headers: dict, body: str) -> Optional[DeviceFingerprint]:
        """Analyze HTTP response to identify device type using weighted scoring."""
        combined = str(headers) + body

        # Score each device type based on pattern matches
        scores: dict[DeviceType, int] = {}
        matches: dict[DeviceType, list[str]] = {}

        for device_type, patterns in self.HTTP_SIGNATURES.items():
            scores[device_type] = 0
            matches[device_type] = []
            for pattern, weight in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    scores[device_type] += weight
                    matches[device_type].append(pattern)

        # Find the device type with highest score
        best_type = max(scores.keys(), key=lambda k: scores[k])
        best_score = scores[best_type]

        if best_score == 0:
            return None

        # Log match details for debugging
        logger.debug(f"Fingerprint scores: {scores}")
        logger.debug(f"Best match: {best_type.value} with patterns: {matches[best_type]}")

        # Calculate confidence based on score (higher score = higher confidence)
        # Base confidence of 0.7, +0.05 per point up to 0.95
        confidence = min(0.95, 0.7 + (best_score * 0.05))

        fingerprint = DeviceFingerprint(
            device_type=best_type,
            confidence=confidence,
        )

        # Try to extract model and version info
        self._extract_device_details(body, fingerprint)
        return fingerprint

    def _extract_device_details(self, body: str, fingerprint: DeviceFingerprint) -> None:
        """Extract model and firmware version from HTTP response body."""
        # MikroTik patterns
        if fingerprint.device_type == DeviceType.MIKROTIK:
            version_match = re.search(r'RouterOS\s+v?(\d+\.\d+(?:\.\d+)?)', body)
            if version_match:
                fingerprint.firmware_version = version_match.group(1)

            model_match = re.search(r'board["\']?\s*:\s*["\']([^"\']+)', body, re.IGNORECASE)
            if model_match:
                fingerprint.model = model_match.group(1)

        # Cambium patterns
        elif fingerprint.device_type == DeviceType.CAMBIUM:
            version_match = re.search(r'(?:firmware|version)["\']?\s*:\s*["\']?(\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
            if version_match:
                fingerprint.firmware_version = version_match.group(1)

            model_match = re.search(r'(ePMP\s*\d+|PMP\s*\d+|cnPilot[^\s"\'<]+)', body, re.IGNORECASE)
            if model_match:
                fingerprint.model = model_match.group(1)

        # Tachyon patterns
        elif fingerprint.device_type == DeviceType.TACHYON:
            version_match = re.search(r'(?:version|firmware)["\']?\s*:\s*["\']?(\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
            if version_match:
                fingerprint.firmware_version = version_match.group(1)

            model_match = re.search(r'(30[123]L?|TN-?\d+)', body, re.IGNORECASE)
            if model_match:
                fingerprint.model = model_match.group(1)

        # Tarana patterns
        elif fingerprint.device_type == DeviceType.TARANA:
            version_match = re.search(r'(?:version|firmware)["\']?\s*:\s*["\']?(\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
            if version_match:
                fingerprint.firmware_version = version_match.group(1)

            model_match = re.search(r'(G1|RN\d*)', body, re.IGNORECASE)
            if model_match:
                fingerprint.model = model_match.group(1)

        # Ubiquiti patterns
        elif fingerprint.device_type == DeviceType.UBIQUITI:
            version_match = re.search(r'(?:version|firmware)["\']?\s*:\s*["\']?v?(\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
            if version_match:
                fingerprint.firmware_version = version_match.group(1)

            model_match = re.search(
                r'(Rocket\s*\w+|NanoStation\s*\w+|LiteBeam\s*\w+|PowerBeam\s*\w+'
                r'|NanoBeam\s*\w+|AirGrid\s*\w+|Bullet\s*\w+'
                r'|Wave\s*(?:AP|Nano|Pico|Pro|LR)\w*)',
                body, re.IGNORECASE
            )
            if model_match:
                fingerprint.model = model_match.group(1)

    async def _fetch_cambium_sku(self, ip: str, fingerprint: DeviceFingerprint) -> None:
        """Fetch Cambium SKU file to get exact model and firmware version.

        The /js/cambium_sku.js file contains:
        - window.sku = 35;  (SKU code)
        - window.cambiumFWVersion = 'Version 4.8.1';  (firmware)
        """
        # Known SKU to model mappings
        sku_to_model = {
            "35": "Force 300-25",
            "38": "Force 300-16",
            "49": "Force 300-19",
            "53544": "ePMP 4518",
            "53545": "ePMP 4525",
            "53264": "ePMP 4600",
            "53561": "ePMP 4625",
        }

        try:
            # Try HTTPS first, fall back to HTTP (some models like ePMP 4525 are HTTP-only)
            content = None
            for scheme in ["https", "http"]:
                url = f"{scheme}://{ip}/js/cambium_sku.js"

                if self.interface:
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-k", "-m", "5",
                        "--interface", self.interface,
                        url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()

                    if proc.returncode == 0 and stdout:
                        content = stdout.decode("utf-8", errors="ignore")
                        break
                else:
                    timeout_obj = aiohttp.ClientTimeout(total=5)
                    try:
                        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                            async with session.get(url, ssl=False) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    break
                    except Exception:
                        continue

            if not content:
                return

            # Extract SKU code: window.sku = 35;
            sku_match = re.search(r'window\.sku\s*=\s*(\d+)', content)
            if sku_match:
                sku_code = sku_match.group(1)
                if sku_code in sku_to_model:
                    fingerprint.model = sku_to_model[sku_code]
                    logger.info(f"Cambium SKU {sku_code} = {fingerprint.model}")
                elif sku_code.startswith("53"):
                    # 53xxx SKUs are ePMP AX series (WiFi 6)
                    fingerprint.model = f"ePMP AX (SKU {sku_code})"
                    logger.info(f"Cambium SKU {sku_code} -> ePMP AX series (53xxx)")
                else:
                    fingerprint.model = f"Cambium (SKU {sku_code})"
                    logger.info(f"Cambium SKU {sku_code} (unknown model)")

            # Extract firmware: window.cambiumFWVersion = 'Version 4.8.1';
            fw_match = re.search(r"cambiumFWVersion\s*=\s*['\"]Version\s*([^'\"]+)['\"]", content)
            if fw_match:
                fingerprint.firmware_version = fw_match.group(1).strip()
                logger.info(f"Cambium firmware: {fingerprint.firmware_version}")

        except Exception as e:
            logger.debug(f"Failed to fetch Cambium SKU: {e}")

    async def _probe_ssh_banner(self, ip: str) -> Optional[Tuple[DeviceType, Optional[str]]]:
        """Get SSH banner for device identification."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 22),
                timeout=self.timeout
            )

            banner = await asyncio.wait_for(reader.read(256), timeout=3.0)
            banner_str = banner.decode("utf-8", errors="ignore")

            writer.close()
            await writer.wait_closed()

            logger.debug(f"SSH banner from {ip}: {banner_str}")

            # Analyze banner
            if "MikroTik" in banner_str or "ROSSSH" in banner_str:
                return (DeviceType.MIKROTIK, None)
            elif "Cambium" in banner_str or "ePMP" in banner_str:
                return (DeviceType.CAMBIUM, None)
            elif "UBNT" in banner_str or "dropbear" in banner_str.lower():
                return (DeviceType.UBIQUITI, None)

        except Exception as e:
            logger.debug(f"SSH probe failed for {ip}: {e}")

        return None

    async def _probe_snmp(self, ip: str) -> Optional[Tuple[DeviceType, Optional[str]]]:
        """Probe SNMP sysDescr for device identification."""
        try:
            from pysnmp.hlapi.asyncio import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
        except ImportError:
            logger.debug("pysnmp not available for SNMP probing")
            return None

        try:
            # Try common community strings
            for community in ["public", "private"]:
                iterator = await getCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, 161), timeout=2, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
                )

                errorIndication, errorStatus, errorIndex, varBinds = iterator

                if not errorIndication and not errorStatus:
                    for varBind in varBinds:
                        sys_descr = str(varBind[1])
                        logger.debug(f"SNMP sysDescr from {ip}: {sys_descr}")

                        if "MikroTik" in sys_descr or "RouterOS" in sys_descr:
                            return (DeviceType.MIKROTIK, None)
                        elif "Cambium" in sys_descr:
                            return (DeviceType.CAMBIUM, None)
                        elif "Tachyon" in sys_descr:
                            return (DeviceType.TACHYON, None)
                        elif "Tarana" in sys_descr:
                            return (DeviceType.TARANA, None)
                        elif "UBNT" in sys_descr or "Ubiquiti" in sys_descr or "AirOS" in sys_descr:
                            return (DeviceType.UBIQUITI, None)

        except Exception as e:
            logger.debug(f"SNMP probe failed for {ip}: {e}")

        return None

    async def _get_mikrotik_info(self, ip: str, fingerprint: DeviceFingerprint) -> None:
        """Get detailed info from MikroTik using RouterOS API."""
        try:
            import librouteros
        except ImportError:
            logger.debug("librouteros not available for MikroTik API")
            return

        try:
            # Try default credentials
            api = librouteros.connect(
                host=ip,
                username="admin",
                password="",
                timeout=5.0,
            )

            # Get system identity
            identity = list(api.path("/system/identity").select())
            if identity:
                fingerprint.hostname = identity[0].get("name")

            # Get system resource info
            resource = list(api.path("/system/resource").select())
            if resource:
                fingerprint.firmware_version = resource[0].get("version")
                fingerprint.model = resource[0].get("board-name")

            api.close()

        except Exception as e:
            logger.debug(f"MikroTik API probe failed for {ip}: {e}")


async def identify_device(
    ip: str,
    mac: Optional[str] = None,
    timeout: float = 5.0,
    interface: Optional[str] = None
) -> DeviceFingerprint:
    """Convenience function to identify a device.

    Args:
        ip: Device IP address
        mac: Optional MAC address
        timeout: Connection timeout
        interface: Network interface to bind to (e.g., 'eth0.1992')
    """
    fingerprinter = DeviceFingerprinter(timeout=timeout, interface=interface)
    return await fingerprinter.fingerprint(ip, mac)
