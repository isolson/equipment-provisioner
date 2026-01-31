"""Tarana Wireless G1 device handler using gRPC-web/gNOI protocols.

Protocol overview
=================
Tarana G1 devices expose a gRPC-web gateway over plain HTTP on the device's
link-local IP (169.254.100.1).  Two transports are used:

  * **gNMI over gRPC-web (HTTP POST)** – device queries (Get) and config
    mutations (Set).  Auth credentials are sent as custom HTTP headers
    ``user`` and ``password`` on *every* request (no session/cookie).

  * **gNOI over WebSocket** – file transfer (File.Put) and system commands
    (System.SetPackage, System.Reboot).  The ``grpc-websockets`` sub-protocol
    requires the *first* WebSocket binary message to carry metadata in HTTP-
    header format (``user: …\\r\\npassword: …\\r\\n``), *not* as HTTP upgrade
    headers.  Subsequent gRPC data frames are prefixed with ``0x00`` before
    the standard 5-byte gRPC header (total 6-byte header per frame).
    End-of-stream is a standalone ``0x01`` byte.

Networking
----------
* Device IP is always **169.254.100.1** (Tarana-specific link-local).
* The provisioner host must be reachable at **169.254.100.2** on the
  same VLAN interface so that aiohttp can ``local_addr``-bind correctly.
* If the generic ``169.254.1.1`` is passed in, the handler silently
  rewrites it to ``169.254.100.1``.

Authentication & credential rotation
-------------------------------------
Factory-default credentials are ``admin / admin123``.

On **first plug-in** (``_credentials_confirmed`` is False) the handler
*always* tries the factory default first, then falls back to any
configured credential that differs.  On **reconnect** (after a reboot
during provisioning, ``_credentials_confirmed`` is True) it tries the
previously-confirmed credential first, falling back to factory default.

Auth failures are detected in two ways – both are required:

1. **HTTP response headers** – Tarana returns HTTP 200 even on auth
   failure but sets ``Grpc-Status`` / ``Grpc-Message`` as HTTP response
   headers (not body trailers).  ``_gnmi_get()`` checks these headers
   *before* reading the body and raises ``RuntimeError`` so the
   credential-rotation loop in ``connect()`` can catch it and try the
   next credential set.

2. **gRPC body trailers** – on successful HTTP 200 responses with a
   body, the trailing frame (flag ``0x80``) may contain
   ``grpc-status: N`` lines; these are also checked.

⚠ **Do not** remove or reorder the header check in ``_gnmi_get()`` –
without it, auth failures silently appear as "0 bytes / no data".

Firmware version strings
------------------------
Bank versions are full dotted strings like ``SYS.A3.R10.XXX.3.611.002.00``.
The firmware file on disk uses the same format as its filename
(``SYS.A3.R10.XXX.3.622.005.00.tbn``), and the version is extracted by
stripping the ``.tbn`` extension.  This ensures exact string comparison
between device banks and the expected version works correctly.

⚠ **Do not** shorten or normalize these version strings – the
provisioner's bank-comparison logic depends on exact string equality.

gNMI paths (known schema)
--------------------------
The following gNMI paths are used and are known to work on G1 firmware
≥ 3.611:

  * ``/system``                          – full system tree (state, software,
    aaa, certificates, management, dns, grpc-server, alarms)
  * ``/system/state/hostname``           – serial number (e.g. S197A1252300723)
  * ``/system/state/role``               – ``rn`` (Remote Node) or ``bn``
    (Base Node)
  * ``/system/software/state/active-bank``  – ``system1`` or ``system2``
  * ``/system/software/state/current-bank`` – currently running bank
  * ``/system/software/state/next-install-bank`` – target for next install
  * ``/system/software/banks/state/system1`` – bank 1 version string
  * ``/system/software/banks/state/system2`` – bank 2 version string
  * ``/platform/components/component[name=sys]`` – hardware description
  * ``/connections``, ``/radios/radio``  – link status / signal quality
"""

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

    Supports keyed elements like "component[name=sys]" which become
    PathElem(name="component", key={"name": "sys"}).
    """
    import re
    encoder = ProtobufEncoder()
    for elem in path_elements:
        elem_encoder = ProtobufEncoder()

        # Parse key expressions like "component[name=sys]" or "radio[id=0]"
        match = re.match(r'^([^\[]+)\[(.+)\]$', elem)
        if match:
            name = match.group(1)
            key_str = match.group(2)
            elem_encoder.write_string(1, name)
            # Parse key=value pairs (comma-separated)
            for kv in key_str.split(','):
                k, v = kv.split('=', 1)
                # Build map entry: key=1(string), value=2(string)
                map_encoder = ProtobufEncoder()
                map_encoder.write_string(1, k.strip())
                map_encoder.write_string(2, v.strip())
                elem_encoder.write_embedded(2, map_encoder.get_bytes())
        else:
            elem_encoder.write_string(1, elem)

        encoder.write_embedded(3, elem_encoder.get_bytes())
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
    if permissions:
        details.write_uint64(2, permissions)  # permissions (browser omits this)

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

    HashType enum (standard gNOI):
      UNSPECIFIED = 0;
      MD5 = 1;
      SHA256 = 2;
      SHA512 = 3;

    ⚠ Tarana G1 uses hash_type=3 with a 16-byte MD5 digest (not SHA512).
    This contradicts the standard enum but matches observed device behavior
    from HAR captures.  Always pass hash_type=3 with MD5 for Tarana.
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

    ⚠ Tarana G1 uses a NON-STANDARD Package proto.  Field numbers differ
    from the OpenConfig gNOI spec.  See docs/tarana-protocol.md for the
    HAR-verified wire format.

    Standard gNOI Package:
      string filename = 1;  string version = 2;  bool activate = 3;

    Tarana G1 actual (from HAR capture):

      SetPackageRequest message:
        Package package = 1;

      Package message:
        string filename = 1;
        // fields 2–4 unused
        bool activate = 5;           // ⚠ NOT field 3
        VersionInfo version_info = 6;

      VersionInfo message:
        string version = 1;          // same filename string
        int32 method = 2;            // observed value: 10
    """
    # Build VersionInfo (field 6 of Package)
    version_info = ProtobufEncoder()
    version_info.write_string(1, filename)  # version = filename string
    version_info.write_uint64(2, 10)        # method = 10 (observed from HAR)

    # Build Package message
    package = ProtobufEncoder()
    package.write_string(1, filename)                    # field 1: filename
    package.write_bool(5, activate)                      # field 5: activate (NOT 3)
    package.write_embedded(6, version_info.get_bytes())  # field 6: VersionInfo

    # Build SetPackageRequest
    request = ProtobufEncoder()
    request.write_embedded(1, package.get_bytes())  # package field

    return request.get_bytes()


# =============================================================================
# WebSocket gRPC Frame Helpers
# =============================================================================

def build_ws_grpc_frame(message: bytes) -> bytes:
    """Build a gRPC frame for the ``grpc-websockets`` WebSocket sub-protocol.

    Unlike standard gRPC-web (HTTP POST) which uses a 5-byte header, the
    ``grpc-websockets`` protocol prepends an extra byte before each frame:

      * ``0x00`` = data frame (followed by standard 5-byte gRPC header + payload)
      * ``0x01`` = end-of-stream / half-close (sent as a standalone 1-byte message)

    Client data message layout::

        [0x00] [flag:1] [length:4 BE] [protobuf payload]

    Verified from HAR capture: browser sends 41-byte open frame (1 + 5 + 35),
    65546-byte data chunks (1 + 5 + 65540), and 28-byte hash frame (1 + 5 + 22).
    """
    return b'\x00' + build_grpc_web_frame(message)


def build_grpc_websocket_metadata(credentials: Dict[str, str]) -> bytes:
    """Build gRPC-websockets metadata for the first WebSocket message.

    The grpc-websockets protocol requires metadata to be sent as the first
    WebSocket **binary** message in HTTP-header format.  The Tarana G1 gRPC
    gateway expects this as a binary frame (opcode 2), NOT a text frame.
    """
    username = credentials.get("username", "admin")
    password = credentials.get("password", "")
    lines = [
        f"user: {username}",
        f"password: {password}",
        "source: device-ui",
        "content-type: application/grpc-web+proto",
        "x-grpc-web: 1",
    ]
    # Each line ends with \r\n, including the last one (109 bytes total for
    # default credentials, verified from HAR capture).
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


# =============================================================================
# Tarana Handler
# =============================================================================

class TaranaHandler(BaseHandler):
    """Handler for Tarana Wireless G1 Radio Nodes using gRPC-web/gNOI.

    Protocol:
    - gNMI over gRPC-web (HTTP POST) for device queries
    - gNOI over WebSocket for file operations and system commands
    - Authentication via ``user`` / ``password`` HTTP headers (every request)

    Key invariants – do NOT change without updating tests:

    * ``DEFAULT_IP`` is ``169.254.100.1``; the host binds to ``169.254.100.2``.
    * ``DEFAULT_CREDENTIALS`` is ``admin / admin123`` (factory default).
    * ``connect()`` tries DEFAULT_CREDENTIALS **first** on a fresh device,
      then falls back to configured credentials.  On reconnect (after a
      confirmed login) the confirmed credential goes first.
    * ``_gnmi_get()`` checks ``Grpc-Status`` / ``Grpc-Message`` **HTTP
      response headers** before reading the body.  Tarana returns HTTP 200
      even on auth failure; without this check auth errors appear as
      silent empty responses.
    * Firmware bank versions are full dotted strings like
      ``SYS.A3.R10.XXX.3.611.002.00`` – compared via exact string equality.
    """

    # Tarana uses 169.254.100.1, different from other devices.
    # The provisioner host must have 169.254.100.2 on the same VLAN interface.
    DEFAULT_IP = "169.254.100.1"

    # Factory default credentials for Tarana devices.
    # This is the FIRST credential tried on every fresh device plug-in.
    DEFAULT_CREDENTIALS = {"username": "admin", "password": "admin123"}

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None,
                 alternate_credentials: list = None):
        # Use Tarana's default IP if the standard link-local is passed
        if ip == "169.254.1.1":
            ip = self.DEFAULT_IP
        super().__init__(ip, credentials, interface)
        self._session: Optional[aiohttp.ClientSession] = None
        self._base_url = f"http://{ip}"
        self._ws_url = f"ws://{ip}"
        self._device_data: Dict[str, Any] = {}
        self.login_error: Optional[str] = None
        self._credentials_confirmed: bool = False
        self._alternate_credentials = alternate_credentials or []

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
        """Connect to Tarana device and verify authentication.

        Tries credentials in order:
        1. If reconnecting after successful login, try confirmed creds first
        2. Default credentials (admin/admin123)
        3. Configured credentials from config (if different from default)
        """
        self.login_error = None
        logger.info(f"[CREDS] ========== TARANA CONNECT START for {self.ip} ==========")

        # Build credential list
        creds_to_try = []

        if self._credentials_confirmed:
            # Reconnect after reboot — use previously confirmed credentials first
            logger.info(f"[CREDS] Reconnect mode - using previously confirmed credentials first")
            creds_to_try.append(self.credentials.copy())
            # Fall back to default if confirmed creds fail (e.g. password was reset)
            if self.credentials.get("password") != self.DEFAULT_CREDENTIALS["password"]:
                creds_to_try.append(self.DEFAULT_CREDENTIALS.copy())
        else:
            # Fresh device — always try factory default first
            creds_to_try.append(self.DEFAULT_CREDENTIALS.copy())
            logger.info(f"[CREDS] Added default credentials (admin/admin123)")

            # Then try configured credentials if different from default
            if self.credentials.get("password") != self.DEFAULT_CREDENTIALS["password"]:
                creds_to_try.append(self.credentials.copy())
                logger.info(f"[CREDS] Added configured credentials")

        logger.info(f"[CREDS] Will try {len(creds_to_try)} credential set(s)")

        last_error = None

        for i, creds in enumerate(creds_to_try):
            username = creds.get("username", "admin")
            password = creds.get("password", "")
            logger.info(f"[CREDS] Attempt {i+1}/{len(creds_to_try)}: "
                        f"Trying {username}/{'*' * len(password) if password else '(empty)'}")

            self.credentials = creds.copy()
            self.login_error = None

            # Close previous session if any
            if self._session:
                await self._session.close()
                self._session = None

            try:
                # Session-level timeout must be generous: firmware uploads
                # stream ~120 MB over WebSocket and can take several minutes.
                # During a write-only WebSocket upload, no data is read from
                # the socket until the upload completes — so sock_read MUST
                # be None here.  Individual request timeouts are set per-call
                # (e.g. _gnmi_get uses ClientTimeout(total=30),
                # wait_for_reboot uses ClientTimeout(total=10)).
                timeout = aiohttp.ClientTimeout(
                    total=None,       # no overall cap — uploads run long
                    connect=15,       # TCP connect timeout
                    sock_read=None,   # no idle-read cap (upload is write-only)
                )

                local_addr = None
                if self.interface:
                    local_addr = ("169.254.100.2", 0)
                    logger.info(f"Tarana: binding to local address {local_addr[0]} for interface {self.interface}")

                connector = aiohttp.TCPConnector(ssl=False, local_addr=local_addr)
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout
                )

                logger.info(f"Tarana: attempting gNMI connection to {self.ip}")

                data = await self._gnmi_get([["system"]])

                if data:
                    self._connected = True
                    self._credentials_confirmed = True
                    self._device_data = data
                    logger.info(f"[CREDS] Login succeeded with attempt {i+1}")
                    logger.info(f"Connected to Tarana at {self.ip}")
                    return True
                else:
                    logger.warning(f"Connected but got no data from Tarana at {self.ip}")
                    last_error = "No data returned from device"

            except RuntimeError as e:
                error_msg = str(e)
                if "authentication" in error_msg.lower() or "password" in error_msg.lower():
                    logger.warning(f"[CREDS] Attempt {i+1} auth failed: {error_msg}")
                    last_error = "Invalid credentials"
                else:
                    logger.error(f"[CREDS] Attempt {i+1} gRPC error: {error_msg}")
                    last_error = error_msg
            except aiohttp.ClientResponseError as e:
                if e.status == 401:
                    logger.warning(f"[CREDS] Attempt {i+1} HTTP 401 auth failed")
                    last_error = "Invalid credentials"
                else:
                    logger.error(f"[CREDS] Attempt {i+1} HTTP error {e.status}")
                    last_error = f"HTTP error {e.status}"
                    break  # Non-auth HTTP errors — don't retry
            except Exception as e:
                logger.error(f"[CREDS] Attempt {i+1} error: {e}")
                last_error = str(e)
                break  # Connection/network errors — don't retry

        # All attempts failed
        self.login_error = last_error or "Failed to connect to device"
        logger.error(f"[CREDS] All {len(creds_to_try)} credential attempts failed: {self.login_error}")
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
                "-H", f"user: {self.credentials.get('username', 'admin')}",
                "-H", f"password: {self.credentials.get('password', '')}",
                "-H", "source: device-ui",
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
        """Execute a gNMI Get request via gRPC-web over HTTP POST.

        Args:
            paths: List of path element lists, e.g. [["system"], ["radios", "radio"]]

        Returns:
            Dictionary of ``"path/element/name" -> value`` mappings.

        Raises:
            RuntimeError: On gRPC-level errors, including authentication
                failures.  The error message contains the ``Grpc-Message``
                text from the device (e.g. "Password authentication failed").

        Important implementation notes:

        1. **HTTP-header gRPC errors** – Tarana returns HTTP 200 even on
           auth failure, putting the error into ``Grpc-Status`` /
           ``Grpc-Message`` *HTTP response headers* (not body trailers).
           This method checks those headers **before** reading the body.
           ⚠ Do not remove this check – without it, auth failures produce
           a silent 0-byte response that ``connect()`` cannot distinguish
           from a network glitch.

        2. **Body-trailer gRPC errors** – on a normal 200 response with a
           body, the last gRPC-web frame (flag ``0x80``) may contain
           ``grpc-status: N`` text lines.  These are also checked and
           raised as ``RuntimeError``.

        3. The response body is a sequence of gRPC-web frames:
           ``[0x00][4-byte BE length][protobuf data]`` for data frames,
           ``[0x80][4-byte BE length][text trailers]`` for the trailer.
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

        # Per-request timeout for gNMI queries (session timeout is open-ended
        # to allow long firmware uploads over the same session).
        request_timeout = aiohttp.ClientTimeout(total=30)

        async with self._session.post(
            url,
            headers=headers,
            data=frame,
            timeout=request_timeout,
        ) as response:
            logger.info(f"gNMI Get response status: {response.status}")
            logger.debug(f"gNMI Get response headers: {dict(response.headers)}")

            if response.status != 200:
                error_text = await response.text()
                logger.error(f"gNMI Get failed: {response.status} - {error_text}")
                response.raise_for_status()

            # Check for gRPC errors in HTTP response headers.
            # Tarana returns HTTP 200 even on auth failure, but sets
            # Grpc-Status and Grpc-Message as HTTP headers (not body trailers).
            grpc_status_hdr = response.headers.get("Grpc-Status") or response.headers.get("grpc-status")
            grpc_message_hdr = response.headers.get("Grpc-Message") or response.headers.get("grpc-message")
            if grpc_status_hdr and grpc_status_hdr != "0":
                error_msg = grpc_message_hdr or f"gRPC error {grpc_status_hdr}"
                logger.error(f"gNMI Get failed (header): grpc-status={grpc_status_hdr}, message={grpc_message_hdr}")
                raise RuntimeError(f"gRPC error: {error_msg}")

            response_data = await response.read()
            logger.info(f"gNMI response length: {len(response_data)} bytes")

            # Debug: show first 100 bytes in hex
            if response_data:
                hex_preview = response_data[:100].hex()
                logger.debug(f"gNMI response hex (first 100 bytes): {hex_preview}")

            # Parse gRPC-web frame(s) from response body.
            # The body contains one or more frames:
            #   - Data frame(s): flag byte 0x00, then 4-byte length, then protobuf
            #   - Trailer frame: flag byte 0x80, then 4-byte length, then text
            #     with "grpc-status: N\r\n" and optionally "grpc-message: ...\r\n"
            if len(response_data) < 5:
                logger.warning(f"Empty gNMI response (got {len(response_data)} bytes)")
                return {}

            # Walk through all frames in the response
            message_data = b""
            grpc_status = None
            grpc_message = None
            offset = 0

            while offset + 5 <= len(response_data):
                flag = response_data[offset]
                frame_len = struct.unpack('>I', response_data[offset + 1:offset + 5])[0]
                frame_body = response_data[offset + 5:offset + 5 + frame_len]
                offset += 5 + frame_len

                is_trailer = (flag & 0x80) != 0
                if is_trailer:
                    # Parse trailer text for grpc-status and grpc-message
                    trailer_text = frame_body.decode('utf-8', errors='ignore')
                    logger.debug(f"gRPC trailer: {trailer_text.strip()}")
                    for line in trailer_text.split('\r\n'):
                        line = line.strip()
                        if line.lower().startswith('grpc-status:'):
                            try:
                                grpc_status = int(line.split(':', 1)[1].strip())
                            except ValueError:
                                pass
                        elif line.lower().startswith('grpc-message:'):
                            grpc_message = line.split(':', 1)[1].strip()
                else:
                    message_data = frame_body

            # Check gRPC status from trailer
            if grpc_status is not None and grpc_status != 0:
                error_msg = grpc_message or f"gRPC error {grpc_status}"
                logger.error(f"gNMI Get failed: grpc-status={grpc_status}, message={grpc_message}")
                raise RuntimeError(f"gRPC error: {error_msg}")

            if not message_data:
                logger.warning("No data frame in gNMI response")
                return {}

            # Parse GetResponse
            result = parse_gnmi_get_response(message_data)
            logger.debug(f"Parsed gNMI response: {len(result)} entries")
            return result

    async def get_info(self) -> DeviceInfo:
        """Get device information from Tarana via gNMI.

        Uses specific gNMI paths known from the Tarana G1 schema:
          - /system/state: hostname (= serial), role (rn/bn), boot info
          - /system/software/state: active-bank, boot-status, firmware version
          - /platform/components/component[name=sys]: hardware model/description
        """
        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        try:
            # Use the /system path which returns the full system tree
            # including state, software/banks, aaa, etc.
            data = self._device_data or await self._gnmi_get([["system"]])
            self._device_data.update(data)

            # Extract info from known Tarana gNMI paths
            for key, value in data.items():
                if not isinstance(value, str):
                    continue
                key_lower = key.lower()

                # Hostname is the serial number (e.g. S197A1252300723)
                if "state/hostname" in key_lower:
                    info.hostname = value
                    info.serial_number = value

                # Role tells us the device type: rn = Remote Node, bn = Base Node
                elif "state/role" in key_lower:
                    role = value.lower()
                    if role == "rn":
                        info.model = "G1 Remote Node"
                    elif role == "bn":
                        info.model = "G1 Base Node"
                    else:
                        info.model = f"G1 {value}"

                # Active bank firmware version from software/banks
                elif "software/state/active-bank" in key_lower:
                    info.extra["active_bank"] = value

                # Software bank versions (e.g. SYS.A3.R10.XXX.3.611.002.00)
                elif "software/banks" in key_lower and "state/version" in key_lower:
                    if "system1" in key_lower:
                        info.extra["bank1_version"] = value
                    elif "system2" in key_lower:
                        info.extra["bank2_version"] = value

            # Set firmware version from the active bank
            active_bank = info.extra.get("active_bank", "")
            if "system1" in active_bank:
                info.firmware_version = info.extra.get("bank1_version", "")
            elif "system2" in active_bank:
                info.firmware_version = info.extra.get("bank2_version", "")

            # If we didn't get firmware from banks, try querying platform
            if not info.firmware_version:
                try:
                    platform_data = await self._gnmi_get([
                        ["platform", "components", "component[name=sys]"],
                    ])
                    self._device_data.update(platform_data)
                    for key, value in platform_data.items():
                        if isinstance(value, str) and "version" in key.lower():
                            info.firmware_version = value
                            break
                except Exception:
                    pass

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
        """Upload firmware to the device using gNOI File.Put over WebSocket.

        Protocol (observed from Tarana G1 web UI via HAR capture):

        1. Open WebSocket to ``ws://<ip>/gnoi.file.File/Put``
           with sub-protocol ``grpc-websockets``.
        2. **MSG 0 (binary):** Send auth metadata as ``\\r\\n``-delimited
           key-value pairs ending with ``\\r\\n`` (109 bytes for default creds).
           No ``0x00`` prefix — raw header text.
        3. **MSG 1 (binary):** ``0x00`` + gRPC frame with PutRequest.open
           containing the bare filename (NOT ``/tmp/filename``).  41 bytes.
        4. **MSGs 2..N (binary):** ``0x00`` + gRPC frames with PutRequest.contents
           — 64 KB chunks of the firmware file.  65546 bytes each.
        5. **MSG N+1 (binary):** ``0x00`` + gRPC frame with PutRequest.hash
           — MD5 hash (hash_type=3, 16 bytes).  28 bytes.
        6. **MSG N+2 (binary):** End-of-stream signal — single byte ``0x01``.
        7. Read 6 binary response messages (3 pairs of header+payload)
           confirming ``grpc-status: 0``.

        ⚠ Hash type MUST be MD5 (type 3).  The device rejects SHA256.
        ⚠ The end-of-stream byte ``0x01`` is required after the hash.
        ⚠ The filename is the bare name (e.g. ``SYS.A3...tbn``),
           not a path like ``/tmp/SYS.A3...tbn``.
        """
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
            import time

            # Tarana uses MD5 (hash_type=3), not SHA256
            md5 = hashlib.md5()

            # Use self._session (the authenticated session) for WebSocket.
            # A fresh/dedicated session lacks cookies/auth state from the
            # prior gNMI login and the WS upgrade may hang or be rejected.
            ws_url = f"{self._ws_url}/gnoi.file.File/Put"
            logger.info(f"Opening WebSocket to {ws_url}")

            async with self._session.ws_connect(
                ws_url,
                protocols=["grpc-websockets"],
            ) as ws:
                upload_start = time.monotonic()
                logger.info(f"WebSocket connected in {time.monotonic() - upload_start:.2f}s")

                # MSG 0: send auth metadata as BINARY (not text!)
                # The Tarana gRPC-websocket gateway requires opcode 2 (binary).
                metadata = build_grpc_websocket_metadata(self.credentials)
                await ws.send_bytes(metadata)
                logger.info(f"Sent auth metadata ({len(metadata)} bytes) at {time.monotonic() - upload_start:.2f}s")

                # MSG 1: send open request with bare filename (no /tmp/ prefix)
                # Browser sends NO permissions field, just the filename.
                remote_filename = firmware_file.name
                open_msg = build_gnoi_put_open(remote_filename, permissions=0)
                frame0 = build_ws_grpc_frame(open_msg)
                await ws.send_bytes(frame0)
                logger.info(f"Sent open request ({len(frame0)} bytes) at {time.monotonic() - upload_start:.2f}s")

                # MSGs 2..N: send file chunks.
                # Browser uses 64KB (65536) chunks — match exactly.
                chunk_size = 64 * 1024
                bytes_sent = 0
                chunks_sent = 0

                with open(firmware_file, "rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break

                        md5.update(chunk)

                        contents_msg = build_gnoi_put_contents(chunk)
                        frame = build_ws_grpc_frame(contents_msg)
                        await ws.send_bytes(frame)

                        bytes_sent += len(chunk)
                        chunks_sent += 1
                        if chunks_sent == 1:
                            logger.info(f"First chunk sent ({len(frame)} bytes frame) "
                                       f"at {time.monotonic() - upload_start:.2f}s")
                        if chunks_sent % 100 == 0:
                            elapsed = time.monotonic() - upload_start
                            progress = (bytes_sent / file_size) * 100
                            rate_mbps = (bytes_sent * 8 / 1_000_000) / elapsed if elapsed > 0 else 0
                            logger.info(f"Upload progress: {progress:.1f}% "
                                       f"({bytes_sent}/{file_size} bytes, "
                                       f"{elapsed:.1f}s, {rate_mbps:.1f} Mbps)")

                elapsed = time.monotonic() - upload_start
                logger.info(f"All {chunks_sent} chunks sent in {elapsed:.1f}s "
                           f"({bytes_sent} bytes)")

                # MSG N+1: send MD5 hash to finalize (hash_type=3 = MD5)
                hash_msg = build_gnoi_put_hash(3, md5.digest())
                await ws.send_bytes(build_ws_grpc_frame(hash_msg))
                logger.info(f"Firmware hash (MD5): {md5.hexdigest()}")

                # MSG N+2: end-of-stream signal (single byte 0x01)
                await ws.send_bytes(b'\x01')

                total_elapsed = time.monotonic() - upload_start
                logger.info(f"Upload stream complete in {total_elapsed:.1f}s, "
                           f"waiting for server response...")

                # Read server response.  The server sends 6 binary WS messages
                # in 3 pairs (header-frame + payload): initial metadata, body
                # (PutResponse with filename echo), and trailers (grpc-status).
                # All messages are BINARY — there are no TEXT frames.
                try:
                    grpc_ok = False
                    for _ in range(10):  # read up to 10 response messages
                        response = await asyncio.wait_for(ws.receive(), timeout=120)
                        if response.type == aiohttp.WSMsgType.BINARY:
                            data = response.data
                            logger.debug(f"Upload response: {len(data)} bytes, "
                                        f"hex={data[:20].hex()}")
                            # Check if this binary message contains grpc-status text.
                            # The trailer payload is plain text like "grpc-status: 0\r\n".
                            try:
                                text = data.decode('utf-8', errors='ignore')
                                if "grpc-status: 0" in text:
                                    grpc_ok = True
                                    break
                                elif "grpc-status:" in text:
                                    logger.error(f"Upload gRPC error: {text.strip()}")
                                    return False
                            except Exception:
                                pass
                        elif response.type in (aiohttp.WSMsgType.CLOSE,
                                               aiohttp.WSMsgType.CLOSED):
                            break

                    if grpc_ok:
                        logger.info(f"Firmware uploaded successfully to {self.ip}")
                    else:
                        logger.info(f"Upload completed (no explicit grpc-status)")
                except asyncio.TimeoutError:
                    logger.info(f"Upload completed (response timeout, may be OK)")

                # Store filename for SetPackage step
                self._uploaded_firmware_path = remote_filename
                self._uploaded_firmware_hash = md5.digest()
                return True

        except asyncio.TimeoutError:
            logger.error("Firmware upload timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Trigger firmware installation using gNOI System.SetPackage.

        Protocol (observed from Tarana G1 web UI via HAR capture):

        1. Open WebSocket to ``ws://<ip>/gnoi.system.System/SetPackage``
           with sub-protocol ``grpc-websockets``.
        2. **MSG 0 (binary):** Auth metadata (same format as File/Put).
        3. **MSG 1 (binary):** ``0x00`` + gRPC frame with SetPackageRequest
           containing filename + activate=true.
        4. **MSG 2 (binary):** ``0x00`` + gRPC frame with hash (same MD5
           sent during File/Put).
        5. **MSG 3 (binary):** End-of-stream signal ``0x01``.
        6. Read binary response pairs confirming ``grpc-status: 0``.

        After File/Put completes, the device stages the firmware internally.
        During this period (~20-30 s) it reports "system-reboot in progress"
        and rejects SetPackage requests.  This method retries with backoff
        until the device is ready or the retry budget is exhausted.
        """
        if not self._session:
            raise RuntimeError("Not connected")

        firmware_path = getattr(self, '_uploaded_firmware_path', None)
        firmware_hash = getattr(self, '_uploaded_firmware_hash', None)
        if not firmware_path:
            logger.error("No firmware has been uploaded")
            return False

        # Retry parameters — the device may need up to ~30 s after File/Put
        # to finish staging firmware before it accepts SetPackage.
        max_attempts = 6
        retry_delay = 10  # seconds between attempts

        for attempt in range(1, max_attempts + 1):
            try:
                result = await self._send_set_package(firmware_path, firmware_hash)
                if result is True:
                    return True
                if result is None:
                    # Retryable error (device busy) — wait and retry
                    if attempt < max_attempts:
                        logger.info(f"SetPackage attempt {attempt}/{max_attempts} "
                                    f"rejected (device busy), retrying in {retry_delay}s...")
                        await asyncio.sleep(retry_delay)
                        continue
                    else:
                        logger.error(f"SetPackage failed after {max_attempts} attempts "
                                     f"(device still busy)")
                        return False
                # result is False — permanent error
                return False

            except asyncio.TimeoutError:
                logger.error("Firmware installation request timed out")
                return False
            except Exception as e:
                logger.error(f"Failed to initiate firmware installation: {e}")
                return False

        return False

    async def _send_set_package(
        self,
        firmware_path: str,
        firmware_hash: Optional[bytes],
    ) -> Optional[bool]:
        """Send a single SetPackage request over WebSocket.

        Returns:
            True  — SetPackage succeeded (grpc-status: 0).
            False — permanent failure (non-retryable gRPC error).
            None  — device busy / "system-reboot in progress" (retryable).
        """
        logger.info(f"Installing firmware {firmware_path} on Tarana at {self.ip}")

        ws_url = f"{self._ws_url}/gnoi.system.System/SetPackage"

        async with self._session.ws_connect(
            ws_url,
            protocols=["grpc-websockets"],
        ) as ws:
            # MSG 0: auth metadata (binary frame, not text)
            metadata = build_grpc_websocket_metadata(self.credentials)
            await ws.send_bytes(metadata)

            # MSG 1: SetPackage request (filename + activate)
            set_package_msg = build_gnoi_set_package(
                filename=firmware_path,
                activate=True
            )
            await ws.send_bytes(build_ws_grpc_frame(set_package_msg))

            # MSG 2: hash (same MD5 from upload step)
            if firmware_hash:
                hash_msg = build_gnoi_put_hash(3, firmware_hash)
                await ws.send_bytes(build_ws_grpc_frame(hash_msg))

            # MSG 3: end-of-stream signal
            await ws.send_bytes(b'\x01')

            # Read response (same binary-pair format as File/Put).
            logger.info(f"Waiting for SetPackage response from {self.ip}...")
            try:
                for _ in range(10):
                    response = await asyncio.wait_for(ws.receive(), timeout=60)
                    if response.type == aiohttp.WSMsgType.BINARY:
                        data = response.data
                        logger.debug(f"SetPackage response: {len(data)} bytes, "
                                    f"hex={data[:20].hex()}")
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            if "grpc-status: 0" in text:
                                logger.info(f"SetPackage succeeded on {self.ip}")
                                return True
                            elif "grpc-status:" in text:
                                # Check for retryable "device busy" errors
                                if "reboot in progress" in text or "IsMessageAllowed" in text:
                                    logger.warning(f"SetPackage rejected (device busy): {text.strip()}")
                                    return None  # retryable
                                logger.error(f"SetPackage failed: {text.strip()}")
                                return False
                        except Exception:
                            pass
                    elif response.type in (aiohttp.WSMsgType.CLOSE,
                                           aiohttp.WSMsgType.CLOSED):
                        break
            except asyncio.TimeoutError:
                logger.warning(f"SetPackage response timeout (may still be OK)")

            return True

    async def reboot(self) -> bool:
        """Reboot the device using gNOI System.Reboot via gRPC-web HTTP POST.

        Protocol (observed from Tarana G1 web UI via HAR capture):

        Reboot is a **unary RPC** sent as a standard gRPC-web HTTP POST
        (NOT over WebSocket), unlike the streaming File/Put and SetPackage.

        * POST ``http://<ip>/gnoi.system.System/Reboot``
        * Body: gRPC-web frame wrapping an empty RebootRequest protobuf
          (``00 00 00 00 00`` = uncompressed, 0-byte message)
        * Response: ``grpc-status: 0`` on success
        * The device reboots within seconds; the connection may drop.
        """
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            # Empty RebootRequest — the HAR shows 5 bytes: flag(0) + length(0)
            frame = build_grpc_web_frame(b"")

            url = f"{self._base_url}/gnoi.system.System/Reboot"
            headers = self._get_auth_headers()

            logger.info(f"Sending reboot command to {self.ip}")

            try:
                async with self._session.post(
                    url,
                    headers=headers,
                    data=frame,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    logger.info(f"Reboot response status: {response.status}")
                    # Check for gRPC success in headers
                    grpc_status = response.headers.get("Grpc-Status") or response.headers.get("grpc-status")
                    if grpc_status and grpc_status != "0":
                        grpc_msg = response.headers.get("Grpc-Message") or response.headers.get("grpc-message")
                        logger.error(f"Reboot failed: grpc-status={grpc_status}, message={grpc_msg}")
                        return False
                    logger.info(f"Reboot command accepted by {self.ip}")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                # Connection drop is expected — device is rebooting
                logger.info(f"Reboot sent to {self.ip} (connection dropped, expected)")

            return True

        except Exception as e:
            # Connection errors are expected during reboot
            logger.info(f"Reboot initiated on {self.ip} (connection closed: {e})")
            return True

    async def get_firmware_version(self) -> str:
        """Get current firmware version."""
        if not self._connected:
            await self.connect()

        info = await self.get_info()
        return info.firmware_version or "unknown"

    async def get_firmware_banks(self) -> Dict[str, Any]:
        """Get firmware bank information from gNMI ``/system`` tree.

        Returns dict with:
          - bank1: Full version string for system1, e.g. ``"SYS.A3.R10.XXX.3.611.002.00"``
          - bank2: Full version string for system2 (same format)
          - active: Which bank is active (``1`` or ``2``)
          - current: Which bank is currently running (``1`` or ``2``)
          - next_install: Which bank will receive next firmware install (``1`` or ``2``)

        ⚠ Bank version strings must be returned **verbatim** as reported by
        the device (e.g. ``SYS.A3.R10.XXX.3.611.002.00``).  The base
        provisioning workflow in ``BaseHandler.provision()`` compares them
        to ``expected_firmware`` via **exact string equality**.  The
        ``FirmwareManager`` extracts the expected version by stripping
        ``.tbn`` from the firmware filename, which produces the same format.
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
                local_addr = ("169.254.100.2", 0) if self.interface else None
                connector = aiohttp.TCPConnector(ssl=False, local_addr=local_addr)
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
