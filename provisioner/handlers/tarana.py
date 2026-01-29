"""Tarana Wireless G1 device handler using gRPC-web/gNOI protocols."""

import asyncio
import logging
import struct
import io
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


# =============================================================================
# Protobuf Encoding Helpers (manual encoding without protobuf library)
# =============================================================================

class ProtobufEncoder:
    """Simple protobuf encoder for gNMI/gNOI messages."""

    def __init__(self):
        self.buffer = io.BytesIO()

    def write_varint(self, value: int) -> None:
        """Write a varint to the buffer."""
        while value > 127:
            self.buffer.write(bytes([((value & 0x7F) | 0x80)]))
            value >>= 7
        self.buffer.write(bytes([value & 0x7F]))

    def write_tag(self, field_number: int, wire_type: int) -> None:
        """Write a field tag (field number + wire type)."""
        self.write_varint((field_number << 3) | wire_type)

    def write_string(self, field_number: int, value: str) -> None:
        """Write a length-delimited string field."""
        encoded = value.encode('utf-8')
        self.write_tag(field_number, 2)  # wire type 2 = length-delimited
        self.write_varint(len(encoded))
        self.buffer.write(encoded)

    def write_bytes(self, field_number: int, value: bytes) -> None:
        """Write a length-delimited bytes field."""
        self.write_tag(field_number, 2)
        self.write_varint(len(value))
        self.buffer.write(value)

    def write_embedded(self, field_number: int, data: bytes) -> None:
        """Write an embedded message field."""
        self.write_tag(field_number, 2)
        self.write_varint(len(data))
        self.buffer.write(data)

    def write_uint64(self, field_number: int, value: int) -> None:
        """Write a uint64 varint field."""
        self.write_tag(field_number, 0)  # wire type 0 = varint
        self.write_varint(value)

    def write_bool(self, field_number: int, value: bool) -> None:
        """Write a bool field."""
        self.write_tag(field_number, 0)
        self.write_varint(1 if value else 0)

    def get_bytes(self) -> bytes:
        """Get the encoded bytes."""
        return self.buffer.getvalue()


class ProtobufDecoder:
    """Simple protobuf decoder for gNMI/gNOI responses."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_varint(self) -> int:
        """Read a varint from the buffer."""
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise ValueError("Unexpected end of data while reading varint")
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result

    def read_tag(self) -> Tuple[int, int]:
        """Read a field tag, returns (field_number, wire_type)."""
        tag = self.read_varint()
        return (tag >> 3, tag & 0x07)

    def read_length_delimited(self) -> bytes:
        """Read a length-delimited field."""
        length = self.read_varint()
        if self.pos + length > len(self.data):
            raise ValueError("Length exceeds available data")
        result = self.data[self.pos:self.pos + length]
        self.pos += length
        return result

    def read_string(self) -> str:
        """Read a string field."""
        return self.read_length_delimited().decode('utf-8', errors='replace')

    def skip_field(self, wire_type: int) -> None:
        """Skip a field based on its wire type."""
        if wire_type == 0:  # varint
            self.read_varint()
        elif wire_type == 1:  # 64-bit
            self.pos += 8
        elif wire_type == 2:  # length-delimited
            length = self.read_varint()
            self.pos += length
        elif wire_type == 5:  # 32-bit
            self.pos += 4
        else:
            raise ValueError(f"Unknown wire type: {wire_type}")

    def has_more(self) -> bool:
        """Check if there's more data to read."""
        return self.pos < len(self.data)


# =============================================================================
# gNMI Message Builders
# =============================================================================

def build_gnmi_path(path_elements: List[str]) -> bytes:
    """Build a gNMI Path message.

    Path message (per OpenConfig gNMI spec):
      repeated string element = 1;  // deprecated
      string origin = 2;
      repeated PathElem elem = 3;   // <- field 3, not 1!
      string target = 4;

    PathElem message:
      string name = 1;
      map<string, string> key = 2;
    """
    encoder = ProtobufEncoder()
    for elem in path_elements:
        # Build PathElem
        elem_encoder = ProtobufEncoder()
        elem_encoder.write_string(1, elem)  # name field
        encoder.write_embedded(3, elem_encoder.get_bytes())  # elem is field 3!
    return encoder.get_bytes()


def build_gnmi_get_request(paths: List[List[str]]) -> bytes:
    """Build a gNMI GetRequest message.

    GetRequest message (per OpenConfig gNMI spec):
      Path prefix = 1;
      repeated Path path = 2;       // <- field 2, not 1!
      DataType type = 3;
      Encoding encoding = 4;
    """
    encoder = ProtobufEncoder()
    for path_elements in paths:
        path_bytes = build_gnmi_path(path_elements)
        encoder.write_embedded(2, path_bytes)  # path is field 2!
    return encoder.get_bytes()


def build_grpc_web_frame(message: bytes, compressed: bool = False) -> bytes:
    """Build a gRPC-web frame.

    Format:
      1 byte: compression flag (0 = uncompressed, 1 = compressed)
      4 bytes: message length (big-endian)
      N bytes: message data
    """
    flag = 1 if compressed else 0
    return struct.pack('>BI', flag, len(message)) + message


def parse_grpc_web_frame(data: bytes) -> Tuple[bool, bytes]:
    """Parse a gRPC-web frame.

    Returns (is_trailer, message_data).
    """
    if len(data) < 5:
        raise ValueError("Frame too short")

    flag = data[0]
    is_trailer = (flag & 0x80) != 0
    length = struct.unpack('>I', data[1:5])[0]

    if len(data) < 5 + length:
        raise ValueError(f"Frame incomplete: expected {length} bytes, got {len(data) - 5}")

    return is_trailer, data[5:5 + length]


# =============================================================================
# gNMI Response Parser
# =============================================================================

def parse_gnmi_get_response(data: bytes) -> Dict[str, Any]:
    """Parse a gNMI GetResponse message.

    GetResponse message:
      repeated Notification notification = 1;

    Notification message:
      int64 timestamp = 1;
      Path prefix = 2;
      repeated Update update = 4;
      repeated Path delete = 5;

    Update message:
      Path path = 1;
      TypedValue val = 2;
    """
    result = {}

    try:
        decoder = ProtobufDecoder(data)
        while decoder.has_more():
            field_num, wire_type = decoder.read_tag()
            if field_num == 1 and wire_type == 2:  # notification
                notification_data = decoder.read_length_delimited()
                parse_notification(notification_data, result)
            else:
                decoder.skip_field(wire_type)
    except Exception as e:
        logger.debug(f"Error parsing GetResponse: {e}")

    return result


def parse_notification(data: bytes, result: Dict[str, Any]) -> None:
    """Parse a Notification message and extract updates."""
    decoder = ProtobufDecoder(data)
    prefix_path = []

    while decoder.has_more():
        field_num, wire_type = decoder.read_tag()
        if field_num == 2 and wire_type == 2:  # prefix
            prefix_data = decoder.read_length_delimited()
            prefix_path = parse_path(prefix_data)
        elif field_num == 4 and wire_type == 2:  # update
            update_data = decoder.read_length_delimited()
            parse_update(update_data, prefix_path, result)
        else:
            decoder.skip_field(wire_type)


def parse_path(data: bytes) -> List[str]:
    """Parse a Path message and return list of path elements.

    Handles both simple paths like ["system", "state"] and
    keyed paths like ["user", "user[username=admin]", "config"].
    """
    path = []
    decoder = ProtobufDecoder(data)

    while decoder.has_more():
        field_num, wire_type = decoder.read_tag()
        if field_num == 3 and wire_type == 2:  # elem is field 3
            elem_data = decoder.read_length_delimited()
            elem_decoder = ProtobufDecoder(elem_data)
            name = ""
            keys = {}
            while elem_decoder.has_more():
                elem_field, elem_wire = elem_decoder.read_tag()
                if elem_field == 1 and elem_wire == 2:  # name
                    name = elem_decoder.read_string()
                elif elem_field == 2 and elem_wire == 2:  # key (map entry)
                    # Map entries are encoded as repeated messages with key=1, value=2
                    map_data = elem_decoder.read_length_delimited()
                    map_decoder = ProtobufDecoder(map_data)
                    k, v = "", ""
                    while map_decoder.has_more():
                        mf, mw = map_decoder.read_tag()
                        if mf == 1 and mw == 2:
                            k = map_decoder.read_string()
                        elif mf == 2 and mw == 2:
                            v = map_decoder.read_string()
                        else:
                            map_decoder.skip_field(mw)
                    if k:
                        keys[k] = v
                else:
                    elem_decoder.skip_field(elem_wire)

            # Format path element with keys if present
            if keys:
                key_str = ",".join(f"{k}={v}" for k, v in keys.items())
                path.append(f"{name}[{key_str}]")
            elif name:
                path.append(name)
        else:
            decoder.skip_field(wire_type)

    return path


def parse_update(data: bytes, prefix: List[str], result: Dict[str, Any]) -> None:
    """Parse an Update message and add to result dict.

    Update message:
      Path path = 1;
      Value value = 2;  // deprecated
      TypedValue val = 3;  // <- current field for values
    """
    decoder = ProtobufDecoder(data)
    path = []
    value = None

    while decoder.has_more():
        field_num, wire_type = decoder.read_tag()
        if field_num == 1 and wire_type == 2:  # path
            path_data = decoder.read_length_delimited()
            path = parse_path(path_data)
        elif field_num == 3 and wire_type == 2:  # val (TypedValue) - field 3!
            val_data = decoder.read_length_delimited()
            value = parse_typed_value(val_data)
        elif field_num == 2 and wire_type == 2:  # deprecated value field
            val_data = decoder.read_length_delimited()
            if value is None:
                value = parse_typed_value(val_data)
        else:
            decoder.skip_field(wire_type)

    # Build full path and store value
    full_path = prefix + path
    if full_path and value is not None:
        key = "/".join(full_path)
        result[key] = value


def parse_typed_value(data: bytes) -> Any:
    """Parse a TypedValue message.

    TypedValue has oneof value:
      string string_val = 1;
      int64 int_val = 2;
      uint64 uint_val = 3;
      bool bool_val = 4;
      bytes bytes_val = 5;
      float float_val = 6;
      ... and more
    """
    decoder = ProtobufDecoder(data)

    if not decoder.has_more():
        return None

    field_num, wire_type = decoder.read_tag()

    if field_num == 1 and wire_type == 2:  # string_val
        return decoder.read_string()
    elif field_num == 2 and wire_type == 0:  # int_val
        return decoder.read_varint()
    elif field_num == 3 and wire_type == 0:  # uint_val
        return decoder.read_varint()
    elif field_num == 4 and wire_type == 0:  # bool_val
        return decoder.read_varint() != 0
    elif field_num == 5 and wire_type == 2:  # bytes_val
        return decoder.read_length_delimited()
    elif field_num == 7 and wire_type == 2:  # json_val
        return decoder.read_string()
    elif field_num == 8 and wire_type == 2:  # json_ietf_val
        return decoder.read_string()
    else:
        return None


# =============================================================================
# gNOI File/System Message Builders
# =============================================================================

def build_gnoi_put_open(filename: str, permissions: int = 0o644) -> bytes:
    """Build gNOI file.PutRequest with open details.

    PutRequest message:
      oneof request:
        Details open = 1;
        bytes contents = 2;
        bytes hash = 3;

    Details message:
      string remote_file = 1;
      uint32 permissions = 2;
    """
    # Build Details message
    details = ProtobufEncoder()
    details.write_string(1, filename)  # remote_file
    details.write_uint64(2, permissions)  # permissions

    # Build PutRequest with open field
    request = ProtobufEncoder()
    request.write_embedded(1, details.get_bytes())  # open field

    return request.get_bytes()


def build_gnoi_put_contents(chunk: bytes) -> bytes:
    """Build gNOI file.PutRequest with file contents."""
    request = ProtobufEncoder()
    request.write_bytes(2, chunk)  # contents field
    return request.get_bytes()


def build_gnoi_put_hash(hash_type: int, hash_value: bytes) -> bytes:
    """Build gNOI file.PutRequest with hash.

    HashType enum:
      UNSPECIFIED = 0;
      MD5 = 1;
      SHA256 = 2;
      SHA512 = 3;
    """
    # Build HashRequest message
    hash_msg = ProtobufEncoder()
    hash_msg.write_uint64(1, hash_type)  # method
    hash_msg.write_bytes(2, hash_value)  # hash

    # Build PutRequest with hash field
    request = ProtobufEncoder()
    request.write_embedded(3, hash_msg.get_bytes())  # hash field

    return request.get_bytes()


def build_gnoi_set_package(filename: str, version: str = "", activate: bool = True) -> bytes:
    """Build gNOI system.SetPackageRequest.

    SetPackageRequest message:
      Package package = 1;
      string method = 2;

    Package message:
      string filename = 1;
      string version = 2;
      bool activate = 3;
    """
    # Build Package message
    package = ProtobufEncoder()
    package.write_string(1, filename)  # filename
    if version:
        package.write_string(2, version)  # version
    package.write_bool(3, activate)  # activate

    # Build SetPackageRequest
    request = ProtobufEncoder()
    request.write_embedded(1, package.get_bytes())  # package field

    return request.get_bytes()


# =============================================================================
# WebSocket gRPC Frame Helpers
# =============================================================================

def build_ws_grpc_frame(message: bytes) -> bytes:
    """Build a WebSocket gRPC frame (same format as gRPC-web)."""
    return build_grpc_web_frame(message)


def build_grpc_websocket_metadata(credentials: Dict[str, str]) -> str:
    """Build gRPC-websockets metadata as text for the first WebSocket message.

    The grpc-websockets protocol requires metadata to be sent as the first
    WebSocket text message in HTTP header format, not as HTTP headers on
    the upgrade request.
    """
    username = credentials.get("username", "admin")
    password = credentials.get("password", "")
    lines = [
        f"user: {username}",
        f"password: {password}",
        "source: device-ui",
        "content-type: application/grpc-web+proto",
    ]
    return "\r\n".join(lines)


# =============================================================================
# Tarana Handler
# =============================================================================

class TaranaHandler(BaseHandler):
    """Handler for Tarana Wireless G1 Radio Nodes using gRPC-web/gNOI.

    Protocol:
    - gNMI over gRPC-web (HTTP POST) for device queries
    - gNOI over WebSocket for file operations and system commands
    - Authentication via User/Password HTTP headers
    """

    # Tarana uses 169.254.100.1, different from other devices
    DEFAULT_IP = "169.254.100.1"

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None):
        # Use Tarana's default IP if the standard link-local is passed
        if ip == "169.254.1.1":
            ip = self.DEFAULT_IP
        super().__init__(ip, credentials, interface)
        self._session: Optional[aiohttp.ClientSession] = None
        self._base_url = f"http://{ip}"
        self._ws_url = f"ws://{ip}"
        self._device_data: Dict[str, Any] = {}

    @property
    def device_type(self) -> str:
        return "tarana"

    @property
    def supports_dual_bank(self) -> bool:
        return True

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication for gRPC-web requests."""
        return {
            "content-type": "application/grpc-web+proto",
            "Accept": "*/*",
            "user": self.credentials.get("username", "admin"),
            "password": self.credentials.get("password", ""),
            "source": "device-ui",
            "x-grpc-web": "1",
            "Origin": f"http://{self.ip}",
            "Referer": f"http://{self.ip}/",
        }

    async def connect(self) -> bool:
        """Connect to Tarana device and verify authentication."""
        try:
            # Create session with appropriate settings
            timeout = aiohttp.ClientTimeout(total=30)

            # For Tarana at 169.254.100.1, we need to bind to 169.254.100.2
            # to ensure traffic goes through the correct VLAN interface
            local_addr = None
            if self.interface:
                # Use the secondary IP (169.254.100.2) for Tarana
                local_addr = ("169.254.100.2", 0)
                logger.info(f"Tarana: binding to local address {local_addr[0]} for interface {self.interface}")

            connector = aiohttp.TCPConnector(ssl=False, local_addr=local_addr)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )

            logger.info(f"Tarana: attempting gNMI connection to {self.ip}")

            # Test connection with a simple gNMI Get request
            data = await self._gnmi_get([["system"]])

            if data:
                self._connected = True
                self._device_data = data
                logger.info(f"Connected to Tarana at {self.ip}")
                return True
            else:
                logger.warning(f"Connected but got no data from Tarana at {self.ip}")
                # Try curl as diagnostic
                await self._curl_test_gnmi()
                self._connected = True
                return True

        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                self.login_error = "Invalid credentials"
                logger.error(f"Authentication failed for Tarana at {self.ip}")
            else:
                self.login_error = f"HTTP error {e.status}"
                logger.error(f"HTTP error connecting to Tarana at {self.ip}: {e}")
            return False
        except Exception as e:
            self.login_error = str(e)
            logger.error(f"Failed to connect to Tarana at {self.ip}: {e}")
            return False

    async def _curl_test_gnmi(self) -> None:
        """Diagnostic: Test gNMI with curl to compare with aiohttp."""
        import asyncio
        import tempfile

        try:
            # Build request frame
            get_request = build_gnmi_get_request([["system"]])
            frame = build_grpc_web_frame(get_request)

            # Write frame to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
                f.write(frame)
                request_file = f.name

            # Build curl command
            url = f"http://{self.ip}/gnmi.gNMI/Get"
            cmd = [
                "curl", "-s", "-v",
                "--interface", self.interface or "eth0",
                "-X", "POST",
                "-H", "Content-Type: application/grpc-web+proto",
                "-H", "Accept: */*",
                "-H", f"User: {self.credentials.get('username', 'admin')}",
                "-H", f"Password: {self.credentials.get('password', '')}",
                "-H", "Source: device-ui",
                "-H", f"Origin: http://{self.ip}",
                "--data-binary", f"@{request_file}",
                "-o", "-",
                url
            ]

            logger.info(f"Curl test: {' '.join(cmd[:10])}...")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

            logger.info(f"Curl stdout length: {len(stdout)} bytes")
            if stdout:
                logger.info(f"Curl stdout hex: {stdout[:100].hex()}")
            if stderr:
                stderr_text = stderr.decode('utf-8', errors='ignore')
                # Log interesting parts of curl verbose output
                for line in stderr_text.split('\n'):
                    if '< HTTP' in line or 'Content-Length' in line or 'grpc' in line.lower():
                        logger.info(f"Curl: {line.strip()}")

            # Clean up
            import os
            os.unlink(request_file)

        except Exception as e:
            logger.error(f"Curl test failed: {e}")

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._session:
            await self._session.close()
            self._session = None
        self._connected = False
        logger.info(f"Disconnected from Tarana at {self.ip}")

    async def _gnmi_get(self, paths: List[List[str]]) -> Dict[str, Any]:
        """Execute a gNMI Get request.

        Args:
            paths: List of path element lists, e.g. [["system"], ["radios", "radio"]]

        Returns:
            Dictionary of path -> value mappings
        """
        if not self._session:
            raise RuntimeError("Not connected")

        # Build the GetRequest message
        get_request = build_gnmi_get_request(paths)
        frame = build_grpc_web_frame(get_request)

        url = f"{self._base_url}/gnmi.gNMI/Get"

        headers = self._get_auth_headers()
        logger.info(f"gNMI request to {url}")
        logger.debug(f"gNMI request headers: {headers}")
        logger.debug(f"gNMI request frame ({len(frame)} bytes): {frame[:50].hex()}...")

        async with self._session.post(
            url,
            headers=headers,
            data=frame
        ) as response:
            logger.info(f"gNMI Get response status: {response.status}")
            logger.debug(f"gNMI Get response headers: {dict(response.headers)}")

            if response.status != 200:
                error_text = await response.text()
                logger.error(f"gNMI Get failed: {response.status} - {error_text}")
                response.raise_for_status()

            response_data = await response.read()
            logger.info(f"gNMI response length: {len(response_data)} bytes")

            # Debug: show first 100 bytes in hex
            if response_data:
                hex_preview = response_data[:100].hex()
                logger.debug(f"gNMI response hex (first 100 bytes): {hex_preview}")

            # Parse gRPC-web frame
            if len(response_data) < 5:
                logger.warning(f"Empty gNMI response (got {len(response_data)} bytes)")
                return {}

            try:
                is_trailer, message_data = parse_grpc_web_frame(response_data)
                logger.debug(f"gRPC frame: is_trailer={is_trailer}, message_len={len(message_data)}")
            except Exception as e:
                logger.error(f"Failed to parse gRPC-web frame: {e}")
                logger.error(f"Raw response: {response_data[:200].hex()}")
                return {}

            if is_trailer:
                # Check if there's a grpc-status in the trailer
                try:
                    trailer_text = message_data.decode('utf-8', errors='ignore')
                    logger.warning(f"Received trailer instead of response: {trailer_text}")
                except:
                    logger.warning("Received trailer instead of response")
                return {}

            # Parse GetResponse
            result = parse_gnmi_get_response(message_data)
            logger.debug(f"Parsed gNMI response: {len(result)} entries")
            return result

    async def get_info(self) -> DeviceInfo:
        """Get device information from Tarana via gNMI."""
        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        try:
            # Query multiple paths for device info
            data = await self._gnmi_get([
                ["system"],
                ["system", "state"],
                ["system", "config"],
                ["radios"],
            ])

            self._device_data.update(data)

            # Extract info from response
            # The exact paths depend on Tarana's gNMI schema
            for key, value in data.items():
                key_lower = key.lower()
                if "model" in key_lower and not info.model:
                    info.model = str(value)
                elif "serial" in key_lower and not info.serial_number:
                    info.serial_number = str(value)
                elif "mac" in key_lower and not info.mac_address:
                    info.mac_address = str(value).upper()
                elif "hostname" in key_lower or "name" in key_lower:
                    if not info.hostname:
                        info.hostname = str(value)
                elif "version" in key_lower or "firmware" in key_lower or "software" in key_lower:
                    if not info.firmware_version:
                        info.firmware_version = str(value)
                elif "hardware" in key_lower and "version" in key_lower:
                    info.hardware_version = str(value)

            # Store raw data for debugging
            info.extra["gnmi_data"] = data

            logger.info(f"Tarana device info: model={info.model}, "
                       f"fw={info.firmware_version}, serial={info.serial_number}")

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")

        self._device_info = info
        return info

    async def backup_config(self) -> bytes:
        """Backup device configuration via gNMI Get."""
        try:
            # Get full config tree
            data = await self._gnmi_get([["config"]])
            import json
            return json.dumps(data, indent=2).encode('utf-8')
        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
            raise

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration via gNMI Set."""
        # TODO: Implement gNMI Set for config application
        logger.warning("Config application not yet implemented for Tarana")
        return True

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from file."""
        try:
            import json
            config_file = Path(config_path)
            if not config_file.exists():
                logger.error(f"Config file not found: {config_path}")
                return False

            with open(config_file, "r") as f:
                config = json.load(f)

            return await self.apply_config(config)
        except Exception as e:
            logger.error(f"Failed to apply config file: {e}")
            return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware to the device using gNOI File.Put over WebSocket."""
        if not self._session:
            raise RuntimeError("Not connected")

        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            logger.error(f"Firmware file not found: {firmware_path}")
            return False

        file_size = firmware_file.stat().st_size
        logger.info(f"Uploading firmware {firmware_file.name} ({file_size} bytes) to Tarana at {self.ip}")

        try:
            import hashlib

            # Calculate SHA256 hash while reading
            sha256 = hashlib.sha256()

            # Connect WebSocket for gNOI File.Put
            # Note: grpc-websockets protocol sends auth in first text message, not HTTP headers
            ws_url = f"{self._ws_url}/gnoi.file.File/Put"

            async with self._session.ws_connect(
                ws_url,
                protocols=["grpc-websockets"],
            ) as ws:
                # First message: send metadata as text (grpc-websockets protocol)
                metadata = build_grpc_websocket_metadata(self.credentials)
                await ws.send_str(metadata)

                # Send open request with filename
                remote_filename = f"/tmp/{firmware_file.name}"
                open_msg = build_gnoi_put_open(remote_filename)
                await ws.send_bytes(build_ws_grpc_frame(open_msg))

                # Read and send file chunks
                chunk_size = 64 * 1024  # 64KB chunks
                bytes_sent = 0

                with open(firmware_file, "rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break

                        sha256.update(chunk)

                        # Send chunk
                        contents_msg = build_gnoi_put_contents(chunk)
                        await ws.send_bytes(build_ws_grpc_frame(contents_msg))

                        bytes_sent += len(chunk)
                        progress = (bytes_sent / file_size) * 100
                        if bytes_sent % (chunk_size * 10) == 0:
                            logger.info(f"Upload progress: {progress:.1f}%")

                # Send hash to finalize
                hash_msg = build_gnoi_put_hash(2, sha256.digest())  # SHA256 = 2
                await ws.send_bytes(build_ws_grpc_frame(hash_msg))

                # Wait for response
                try:
                    response = await asyncio.wait_for(ws.receive(), timeout=60)
                    if response.type == aiohttp.WSMsgType.BINARY:
                        logger.info(f"Firmware uploaded successfully to {self.ip}")
                    elif response.type == aiohttp.WSMsgType.CLOSE:
                        logger.info(f"Upload completed (connection closed)")
                except asyncio.TimeoutError:
                    logger.info(f"Upload completed (no response, may be OK)")

                self._uploaded_firmware_path = remote_filename
                return True

        except asyncio.TimeoutError:
            logger.error("Firmware upload timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Trigger firmware installation using gNOI System.SetPackage."""
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            # Get the uploaded firmware path
            firmware_path = getattr(self, '_uploaded_firmware_path', None)
            if not firmware_path:
                logger.error("No firmware has been uploaded")
                return False

            logger.info(f"Installing firmware from {firmware_path} on Tarana at {self.ip}")

            # Connect WebSocket for gNOI System.SetPackage
            # Note: grpc-websockets protocol sends auth in first text message
            ws_url = f"{self._ws_url}/gnoi.system.System/SetPackage"

            async with self._session.ws_connect(
                ws_url,
                protocols=["grpc-websockets"],
            ) as ws:
                # First message: send metadata as text (grpc-websockets protocol)
                metadata = build_grpc_websocket_metadata(self.credentials)
                await ws.send_str(metadata)

                # Send SetPackage request
                set_package_msg = build_gnoi_set_package(
                    filename=firmware_path,
                    activate=True
                )
                await ws.send_bytes(build_ws_grpc_frame(set_package_msg))

                # Wait for installation to complete (can take a while)
                logger.info(f"Waiting for firmware installation on {self.ip}...")
                try:
                    # Installation can take several minutes
                    response = await asyncio.wait_for(ws.receive(), timeout=600)
                    if response.type == aiohttp.WSMsgType.BINARY:
                        logger.info(f"Firmware installation completed on {self.ip}")
                    elif response.type == aiohttp.WSMsgType.CLOSE:
                        logger.info(f"Installation completed (connection closed)")
                except asyncio.TimeoutError:
                    logger.warning(f"Installation response timeout (may still be in progress)")

                return True

        except asyncio.TimeoutError:
            logger.error("Firmware installation request timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to initiate firmware installation: {e}")
            return False

    async def reboot(self) -> bool:
        """Reboot the device using gNOI System.Reboot."""
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            # Build Reboot request (simple message with reboot method)
            reboot_msg = ProtobufEncoder()
            reboot_msg.write_uint64(1, 1)  # method = COLD (1)

            ws_url = f"{self._ws_url}/gnoi.system.System/Reboot"

            async with self._session.ws_connect(
                ws_url,
                protocols=["grpc-websockets"],
            ) as ws:
                # First message: send metadata as text (grpc-websockets protocol)
                metadata = build_grpc_websocket_metadata(self.credentials)
                await ws.send_str(metadata)

                # Send reboot request
                await ws.send_bytes(build_ws_grpc_frame(reboot_msg.get_bytes()))

                # Reboot may not respond, connection might drop
                try:
                    response = await asyncio.wait_for(ws.receive(), timeout=5)
                    logger.info(f"Reboot acknowledged by {self.ip}")
                except asyncio.TimeoutError:
                    logger.info(f"Reboot sent to {self.ip} (no ack expected)")

                return True

        except Exception as e:
            # Connection errors are expected during reboot
            logger.info(f"Reboot initiated on {self.ip} (connection closed)")
            return True

    async def get_firmware_version(self) -> str:
        """Get current firmware version."""
        if not self._connected:
            await self.connect()

        info = await self.get_info()
        return info.firmware_version or "unknown"

    async def get_firmware_banks(self) -> Dict[str, Any]:
        """Get firmware bank information.

        Returns dict with:
          - bank1: version string for system1
          - bank2: version string for system2
          - active: which bank is active (1 or 2)
          - current: which bank is currently running (1 or 2)
          - next_install: which bank will receive next install (1 or 2)
        """
        if not self._connected:
            await self.connect()

        try:
            # Query the system path which contains software bank info
            data = await self._gnmi_get([["system"]])

            # The response is a large protobuf, we need to find bank info
            # by searching through the raw response data
            # Store raw data for parsing
            result = {
                "bank1": None,
                "bank2": None,
                "active": None,
                "current": None,
                "next_install": None,
            }

            # Convert data dict values to searchable text
            all_text = str(data)

            # Look for version patterns in the data
            import re

            # Search for bank versions - they appear as software/banks/state/systemN paths
            for key, value in data.items():
                key_lower = key.lower()
                if isinstance(value, str) and value.startswith("SYS.A3."):
                    if "system1" in key_lower:
                        result["bank1"] = value
                    elif "system2" in key_lower:
                        result["bank2"] = value
                elif "active-bank" in key_lower:
                    if "system1" in str(value):
                        result["active"] = 1
                    elif "system2" in str(value):
                        result["active"] = 2
                elif "current-bank" in key_lower:
                    if "system1" in str(value):
                        result["current"] = 1
                    elif "system2" in str(value):
                        result["current"] = 2
                elif "next-install-bank" in key_lower:
                    if "system1" in str(value):
                        result["next_install"] = 1
                    elif "system2" in str(value):
                        result["next_install"] = 2

            logger.info(f"Firmware banks: system1={result['bank1']}, system2={result['bank2']}, "
                       f"active={result['active']}, current={result['current']}")

            return result

        except Exception as e:
            logger.error(f"Failed to get firmware banks: {e}")
            return {}

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to come back online after reboot."""
        logger.info(f"Waiting for Tarana at {self.ip} to come back online...")

        # Initial delay for reboot to start
        await asyncio.sleep(20)

        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                # Try a simple gNMI request
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    url = f"{self._base_url}/gnmi.gNMI/Get"

                    # Build a minimal GetRequest
                    get_request = build_gnmi_get_request([["system"]])
                    frame = build_grpc_web_frame(get_request)

                    async with session.post(
                        url,
                        headers=self._get_auth_headers(),
                        data=frame,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            await asyncio.sleep(5)  # Let it stabilize
                            logger.info(f"Tarana at {self.ip} is back online")
                            return True
            except Exception:
                pass

            await asyncio.sleep(5)

        logger.error(f"Tarana at {self.ip} did not come back online within {timeout}s")
        return False

    async def get_link_status(self) -> Dict[str, Any]:
        """Get current link status and signal quality via gNMI."""
        try:
            data = await self._gnmi_get([
                ["connections"],
                ["radios", "radio"],
            ])
            return data
        except Exception as e:
            logger.error(f"Failed to get link status: {e}")
            return {}
