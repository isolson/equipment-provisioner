#!/usr/bin/env python3
"""Bench tool: apply the business-switch profile to a Teltonika TSW202.

This is a bench tool ahead of a real handler. It is vendor-isolated: it
touches no provisioner module, registry, or template. The profile data lives
next to it in ``tsw202_business_switch_profile.json``.

The tool must run as root on the bench host. It reaches the switch through a
temporary network namespace with a macvlan child of the provisioning VLAN
interface. The namespace holds 192.168.1.250/24 for the factory address and
192.168.10.250/24 for the business management address, so neither address is
added to the host's main namespace. The namespace is removed on exit.

Steps: log in; back up the configuration once per serial; upgrade the
firmware if it is not at the profile version; apply the hardening; build the
VLANs; move management to VLAN 10 last; read everything back twice from the
new management address. Writes are idempotent: each value is read first and
written only if it differs.

The credential file is a root-only env file with the shell-quoted keys
TSW202_LABEL_USERNAME and TSW202_LABEL_PASSWORD. No secret is printed or
passed on a command line.

Example (unit 2, site placeholder):
    sudo /opt/provisioner/venv/bin/python scripts/tsw202_business_switch.py \\
        --cred-file /root/tsw202-unit2.env --serial DEVICE_SERIAL --unit 2 --site lakeview \\
        --trust-new-cert \\
        --firmware-dir /var/tmp/tsw202
"""

import argparse
import http.client
import hashlib
import json
import os
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROFILE = os.path.join(HERE, "tsw202_business_switch_profile.json")
NETNS = "tsw202bs"
MACVLAN = "tsw202mv"
DEFAULT_PIN_FILE = "/var/lib/provisioner/tsw202-pins.json"
STAGES = ("backup", "firmware", "hardening", "vlans", "move", "readback")


class StepError(Exception):
    """A write or check failed; the run stops and reports the state."""


class CertificatePinError(StepError):
    """TLS peer certificate does not match the approved device pin."""


def log(msg: str) -> None:
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def load_env(path: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.replace("export ", "").strip()
            parts = shlex.split(value)
            env[key] = parts[0] if parts else ""
    return env


def normalize_fingerprint(value: str) -> str:
    fingerprint = value.replace(":", "").strip().lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        raise StepError("certificate fingerprint must be 64 hexadecimal characters")
    return fingerprint


def peer_fingerprint(host: str, timeout: float = 5) -> str:
    """Read a TLS peer certificate without sending an HTTP request."""
    context = ssl._create_unverified_context()
    with socket.create_connection((host, 443), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert(binary_form=True)
    if not cert:
        raise StepError("switch did not present a TLS certificate")
    return hashlib.sha256(cert).hexdigest()


def _read_pins(path: str) -> Dict[str, str]:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {}
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise StepError("TLS pin file must be owned by the current user and mode 600")
    try:
        with open(path) as fh:
            pins = json.load(fh)
    except (OSError, ValueError):
        raise StepError("TLS pin file is unreadable or invalid")
    if not isinstance(pins, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in pins.items()):
        raise StepError("TLS pin file has an invalid structure")
    return {serial: normalize_fingerprint(pin) for serial, pin in pins.items()}


def _write_pins(path: str, pins: Dict[str, str]) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".tsw202-pins-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(pins, fh, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def pin_peer(host: str, serial: str, pin_file: str, trust_new_cert: bool = False,
             expected_fingerprint: Optional[str] = None) -> str:
    fingerprint = peer_fingerprint(host)
    expected = normalize_fingerprint(expected_fingerprint) if expected_fingerprint else None
    if expected and expected != fingerprint:
        raise CertificatePinError("TLS certificate does not match --cert-sha256 for serial %s" % serial)
    pins = _read_pins(pin_file)
    current = pins.get(serial)
    if current == fingerprint:
        return fingerprint
    if current and not (trust_new_cert or expected):
        raise CertificatePinError(
            "TLS certificate pin mismatch for serial %s; refusing credentials. Verify the device and "
            "re-run with --trust-new-cert on the direct bench link if approved" % serial)
    if not current and not (trust_new_cert or expected):
        raise StepError("no TLS pin for serial %s; use --trust-new-cert or --cert-sha256" % serial)
    pins[serial] = fingerprint
    _write_pins(pin_file, pins)
    log("tls: recorded SHA-256 pin for serial %s" % serial)
    return fingerprint


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, fingerprint: str, **kwargs: Any) -> None:
        self.fingerprint = fingerprint
        context = kwargs.pop("context", None) or ssl._create_unverified_context()
        super().__init__(host, context=context, **kwargs)

    def connect(self) -> None:
        super().connect()
        cert = self.sock.getpeercert(binary_form=True) if self.sock else None
        actual = hashlib.sha256(cert).hexdigest() if cert else ""
        if actual != self.fingerprint:
            self.close()
            raise CertificatePinError("TLS certificate pin mismatch; refusing request")


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = fingerprint
        super().__init__(context=ssl._create_unverified_context())

    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPSConnection(host, self.fingerprint, **kwargs), req)


def _pinned_opener(fingerprint: str) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_PinnedHTTPSHandler(fingerprint))


# --------------------------------------------------------------------------
# Network namespace orchestration (outer process)
# --------------------------------------------------------------------------

def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def netns_up(iface: str, addresses: List[str]) -> None:
    netns_down()
    _run(["ip", "netns", "add", NETNS])
    _run(["ip", "link", "add", MACVLAN, "link", iface, "type", "macvlan", "mode", "bridge"])
    _run(["ip", "link", "set", MACVLAN, "netns", NETNS])
    for addr in addresses:
        _run(["ip", "netns", "exec", NETNS, "ip", "addr", "add", addr, "dev", MACVLAN])
    _run(["ip", "netns", "exec", NETNS, "ip", "link", "set", MACVLAN, "up"])
    _run(["ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up"])
    time.sleep(2)


def netns_down() -> None:
    _run(["ip", "netns", "del", NETNS], check=False)


# --------------------------------------------------------------------------
# REST client
# --------------------------------------------------------------------------

class Api(object):
    def __init__(self, host: str, username: str, password: str, fingerprint: str) -> None:
        self.base = "https://%s" % host
        self._user = username
        self._pass = password
        self._token: Optional[str] = None
        self._token_time = 0.0
        self.fingerprint = fingerprint
        self.opener = _pinned_opener(fingerprint)

    def _raw(self, method: str, path: str, body: Optional[bytes], headers: Dict[str, str],
             timeout: float = 30) -> Tuple[int, bytes]:
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            resp = self.opener.open(req, timeout=timeout)
            return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, CertificatePinError):
                raise exc.reason
            raise StepError("HTTPS request failed (%s)" % type(exc.reason).__name__)

    def login(self) -> None:
        body = json.dumps({"username": self._user, "password": self._pass}).encode()
        code, raw = self._raw("POST", "/api/login", body, {"Content-Type": "application/json"})
        token = None
        try:
            token = (json.loads(raw).get("data") or {}).get("token")
        except ValueError:
            pass
        if code != 200 or not token:
            raise StepError("login failed (HTTP %d)" % code)
        self._token = token
        self._token_time = time.time()

    def _auth(self) -> Dict[str, str]:
        if not self._token or time.time() - self._token_time > 240:
            self.login()
        return {"Authorization": "Bearer %s" % self._token}

    def call(self, method: str, path: str, data: Any = None, timeout: float = 60) -> Tuple[int, Any]:
        for attempt in (1, 2):
            headers = {"Content-Type": "application/json"}
            headers.update(self._auth())
            body = json.dumps({"data": data}).encode() if data is not None else None
            code, raw = self._raw(method, path, body, headers, timeout)
            if code == 401 and attempt == 1:
                self._token = None
                continue
            try:
                parsed = json.loads(raw) if raw else {}
            except ValueError:
                parsed = {}
            return code, parsed
        return code, parsed

    def get(self, path: str) -> Any:
        code, parsed = self.call("GET", path)
        if code != 200 or not parsed.get("success", False):
            raise StepError("GET %s failed (HTTP %d)" % (path, code))
        return parsed.get("data")

    def write(self, method: str, path: str, data: Any = None, timeout: float = 60) -> Any:
        code, parsed = self.call(method, path, data, timeout)
        if code not in (200, 201, 207) or not parsed.get("success", False):
            errs = parsed.get("errors") if isinstance(parsed, dict) else None
            raise StepError("%s %s failed (HTTP %d): %s" % (method, path, code, json.dumps(errs)[:400]))
        if code == 207:
            items = parsed.get("data") or []
            failed = [(i, item) for i, item in enumerate(items) if not item.get("success", False)]
            if failed:
                summary = "; ".join("item %d of %d: %s" % (i + 1, len(items), json.dumps(item.get("errors"))[:300])
                                    for i, item in failed)
                raise StepError("bulk item failed (%s)" % summary)
        return parsed.get("data")

    def upload(self, path: str, option: str, filename: str, content: bytes) -> Any:
        boundary = "----tsw202%s" % uuid.uuid4().hex
        parts = [
            ("--%s\r\nContent-Disposition: form-data; name=\"option\"\r\n\r\n%s\r\n" % (boundary, option)).encode(),
            ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n" % (boundary, filename)).encode(),
            content,
            ("\r\n--%s--\r\n" % boundary).encode(),
        ]
        headers = {"Content-Type": "multipart/form-data; boundary=%s" % boundary}
        headers.update(self._auth())
        code, raw = self._raw("POST", path, b"".join(parts), headers, timeout=300)
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = {}
        if code not in (200, 201) or not parsed.get("success", False):
            raise StepError("upload failed (HTTP %d): %s" % (code, json.dumps(parsed.get("errors"))[:300]))
        return parsed.get("data")

    def download(self, path: str) -> bytes:
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth())
        code, raw = self._raw("POST", path, b"{}", headers, timeout=120)
        if code != 200:
            raise StepError("download %s failed (HTTP %d)" % (path, code))
        return raw


def probe(host: str, fingerprint: str, timeout: float = 4) -> Optional[Dict[str, Any]]:
    try:
        opener = _pinned_opener(fingerprint)
        resp = opener.open("https://%s/api/unauthorized/status" % host, timeout=timeout)
        return (json.loads(resp.read()) or {}).get("data")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, CertificatePinError):
            raise exc.reason
        return None
    except Exception:
        return None


def snmp_v2c_unanswered(host: str, community: str) -> bool:
    """Send a v2c GET for sysDescr.0; True when nothing answers (closed port or dropped)."""
    def tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value
    oid = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])
    varbind = tlv(0x30, tlv(0x30, tlv(0x06, oid) + b"\x05\x00"))
    pdu = tlv(0xA0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + varbind)
    msg = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, community.encode()) + pdu)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.connect((host, 161))
        sock.send(msg)
        sock.recv(2048)
        return False
    except (ConnectionRefusedError, socket.timeout):
        return True
    finally:
        sock.close()


def http_redirects(host: str) -> bool:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open("http://%s/" % host, timeout=5)
        return False
    except urllib.error.HTTPError as exc:
        return exc.code in (301, 302, 307, 308) and "https://" in (exc.headers.get("Location") or "")
    except Exception:
        return False


# --------------------------------------------------------------------------
# Profile application (inner process, inside the namespace)
# --------------------------------------------------------------------------

class Runner(object):
    def __init__(self, args: argparse.Namespace, profile: Dict[str, Any]) -> None:
        self.args = args
        self.p = profile
        self.dry = args.dry_run
        mgmt = profile["management"]
        self.mgmt_ip = "%s%d" % (mgmt["network_prefix"], mgmt["host_offset"] + args.unit)
        self.hostname = profile["hostname_pattern"].format(site=args.site, unit=args.unit)
        env = load_env(args.cred_file)
        self.user = env.get("TSW202_LABEL_USERNAME") or "admin"
        self.password = env["TSW202_LABEL_PASSWORD"]
        self.api: Optional[Api] = None
        self.changes: List[str] = []
        self._allow_pin_update = bool(args.trust_new_cert or args.cert_sha256)

    # -- helpers ----------------------------------------------------------
    def connect(self, quiet: bool = False) -> str:
        for host in (self.mgmt_ip, self.p["factory_address"]):
            try:
                fingerprint = pin_peer(host, self.args.serial, self.args.pin_file,
                                       self._allow_pin_update and self.args.trust_new_cert,
                                       self.args.cert_sha256 if self._allow_pin_update else None)
            except CertificatePinError:
                raise
            except (OSError, socket.timeout):
                continue
            info = probe(host, fingerprint)
            if info and info.get("device_model") == self.p["model"]:
                observed_serial = info.get("serial") or (info.get("mnfinfo") or {}).get("serial")
                if observed_serial and str(observed_serial) != self.args.serial:
                    raise StepError("device serial does not match the requested TLS pin serial")
                self.api = Api(host, self.user, self.password, fingerprint)
                self.api.login()
                serial = self.api.get("/api/system/device/status")["mnfinfo"]["serial"]
                if str(serial) != self.args.serial:
                    raise StepError("authenticated device serial does not match the requested TLS pin serial")
                self._allow_pin_update = False
                if not quiet:
                    log("reached %s at %s" % (info.get("device_model"), host))
                return host
        raise StepError("switch not reachable at %s or %s" % (self.mgmt_ip, self.p["factory_address"]))

    def ensure(self, path: str, desired: Dict[str, Any], current: Optional[Dict[str, Any]] = None,
               label: str = "") -> None:
        assert self.api is not None
        if current is None:
            current = self.api.get(path)
            if isinstance(current, list):
                current = current[0] if current else {}
        diff = {k: v for k, v in desired.items() if current.get(k) != v}
        if not diff:
            return
        self.changes.append("%s %s" % (label or path, sorted(diff)))
        if self.dry:
            log("  [dry-run] PUT %s %s" % (path, sorted(diff)))
            return
        self.api.write("PUT", path, diff)

    def _reconcile_ntp_servers(self, wanted: List[str]) -> None:
        assert self.api is not None
        path = "/api/date_time/ntp/time_servers/config"
        for host in wanted:
            servers = self.api.get(path) or []
            if any(server.get("hostname") == host for server in servers):
                continue
            while len(servers) >= 4:
                extra = next((server for server in servers if server.get("hostname") not in wanted), None)
                if extra is None:
                    raise StepError("no slot available for NTP server %s" % host)
                self.api.write("DELETE", "%s/%s" % (path, extra["id"]))
                servers = self.api.get(path) or []
            self.api.write("POST", path, {"hostname": host})

        for _ in range(32):
            remaining = self.api.get(path) or []
            extra = next((server for server in remaining if server.get("hostname") not in wanted), None)
            if not extra:
                return
            if len(remaining) <= 1:
                raise StepError("cannot remove the last NTP server")
            self.api.write("DELETE", "%s/%s" % (path, extra["id"]))
        raise StepError("could not remove extra NTP servers")

    def _reconcile_snmp(self, desired: Dict[str, Any], remove_communities: bool = True) -> None:
        """Set SNMP modes and restrict communities to loopback when firmware requires one."""
        assert self.api is not None
        agent_path = "/api/snmp/agent/config/general"
        v4_path = "/api/snmp/communities/config"
        v6_path = "/api/snmp/communities_v6/config"
        current = self.api.get(agent_path)
        diff = {k: v for k, v in desired.items() if current.get(k) != v}
        communities = (self.api.get(v4_path) or []) + (self.api.get(v6_path) or [])
        def loopback_ro(entry: Dict[str, Any]) -> bool:
            return (entry.get("secname") == "ro" and entry.get("ipaddr") == "127.0.0.1" and
                    entry.get("netmask") in ("32", "255.255.255.255"))
        v4_entries = self.api.get(v4_path) or []
        safe_entries = [entry for entry in v4_entries if loopback_ro(entry)]

        if (diff or communities) and not safe_entries:
            self.changes.append("temporary localhost-only SNMP community")
            if self.dry:
                log("  [dry-run] would add a localhost-only SNMP community, set agent modes, then remove remote communities")
            else:
                # RutOS 10.4 rejects an agent update when enabled and no community
                # exists. Add a random, loopback-only entry for the transition.
                # Keep the generated value out of logs and error messages.
                try:
                    temp_community = secrets.token_hex(15)
                    self.api.write("POST", v4_path, {
                        "community": temp_community,
                        "secname": "ro",
                        "ipaddr": "127.0.0.1",
                        "netmask": "32",
                    })
                    entries = self.api.get(v4_path) or []
                    if not any(loopback_ro(entry) for entry in entries):
                        for entry in entries:
                            if entry.get("community") != temp_community:
                                continue
                            self.api.write("DELETE", "%s/%s" % (v4_path, entry["id"]))
                        raise StepError("temporary SNMP community did not read back as loopback-only")
                except StepError:
                    # Validation responses may echo the community field.
                    raise StepError("temporary SNMP community creation failed (details withheld)")

        self.ensure(agent_path, desired, label="snmp agent after lldp")

        # Remove communities only after the agent modes are set. This ordering
        # also leaves the intended enabled-but-inert profile on firmware 10.4.
        if remove_communities:
            # Firmware 10.4 rejects deletion of the last IPv4 community while
            # the agent is enabled. Keep only a read-only entry bound to loopback.
            for _ in range(16):
                entries = self.api.get(v4_path) or []
                extra = next((entry for entry in entries if not loopback_ro(entry)), None)
                if not extra:
                    break
                if self.dry:
                    for entry in entries:
                        if not loopback_ro(entry):
                            log("  [dry-run] DELETE %s/%s" % (v4_path, entry["id"]))
                    break
                self.api.write("DELETE", "%s/%s" % (v4_path, extra["id"]))
            else:
                raise StepError("could not remove non-loopback SNMP communities")
            for _ in range(16):
                entries = self.api.get(v6_path) or []
                if not entries:
                    break
                if self.dry:
                    for entry in entries:
                        log("  [dry-run] DELETE %s/%s" % (v6_path, entry["id"]))
                    break
                self.api.write("DELETE", "%s/%s" % (v6_path, entries[0]["id"]))
            else:
                raise StepError("could not empty %s" % v6_path)
            remaining = self.api.get(v4_path) or []
            if remaining:
                log("snmp: kept %d loopback-only read-only community entry/entries; firmware requires one while enabled" % len(remaining))

    # -- stages -------------------------------------------------------------
    def backup(self) -> None:
        assert self.api is not None
        serial = self.api.get("/api/system/device/status")["mnfinfo"]["serial"]
        os.makedirs(self.args.backup_dir, mode=0o700, exist_ok=True)
        existing = [f for f in os.listdir(self.args.backup_dir) if f.startswith(serial + "-") and f.endswith("-pre.tar.gz")]
        if existing:
            log("backup: present (%s)" % existing[0])
            return
        if self.dry:
            log("  [dry-run] would save a pre-change backup")
            return
        self.api.write("POST", "/api/backup/actions/generate", {"encrypt": "0"}, timeout=120)
        blob = self.api.download("/api/backup/actions/download")
        name = os.path.join(self.args.backup_dir, "%s-%s-pre.tar.gz" % (serial, time.strftime("%Y%m%dT%H%M%S")))
        old = os.umask(0o077)
        try:
            with open(name, "wb") as fh:
                fh.write(blob)
        finally:
            os.umask(old)
        os.chmod(name, 0o600)
        log("backup: saved %s (%d bytes, root-only)" % (name, len(blob)))

    def firmware(self) -> None:
        assert self.api is not None
        fw = self.p["firmware"]
        current = self.api.get("/api/firmware/device/status").get("version")
        log("firmware: device %s, target %s" % (current, fw["version"]))
        if current == fw["version"]:
            return
        path = os.path.join(self.args.firmware_dir, fw["file"])
        with open(path, "rb") as fh:
            image = fh.read()
        if hashlib.md5(image).hexdigest() != fw["md5"]:
            raise StepError("firmware file checksum does not match the profile MD5")
        if self.dry:
            log("  [dry-run] would upload %s and upgrade (keep_settings=%s)" % (fw["file"], fw["keep_settings"]))
            return
        verification = self.api.upload("/api/firmware/actions/upload_device_firmware", "firmware", fw["file"], image)
        if str((verification or {}).get("valid")) != "1":
            raise StepError("firmware verification rejected the image: %s" % json.dumps(verification)[:300])
        log("firmware: uploaded and verified; starting upgrade")
        self.api.write("POST", "/api/firmware/actions/upgrade", {"keep_settings": fw["keep_settings"]}, timeout=60)
        time.sleep(90)
        deadline = time.time() + 900
        while time.time() < deadline:
            try:
                self.connect(quiet=True)
                version = self.api.get("/api/firmware/device/status").get("version")
                if version == fw["version"]:
                    log("firmware: now %s" % version)
                    return
            except CertificatePinError as exc:
                raise StepError("TLS certificate changed after firmware reboot; %s. Re-run with "
                                "--trust-new-cert on the direct bench link after verifying the device." % exc)
            except Exception:
                pass
            time.sleep(15)
        raise StepError("switch did not return on %s within 15 minutes" % fw["version"])

    def hardening(self) -> None:
        assert self.api is not None
        h = self.p["hardening"]
        self.ensure("/api/system/config/general", {"hostname": self.hostname, "devicename": self.hostname}, label="hostname")
        self.ensure("/api/rms/config/rms_connect_mqtt", {"enable": h["rms_enable"]}, label="rms")
        self.ensure("/api/access_control/webui/config/general", {"redirect_https": h["redirect_https"]}, label="https redirect")
        self.ensure("/api/access_control/cli/config/general", {"enabled": h["web_cli_enabled"]}, label="web shell")
        self.ensure("/api/access_control/ssh/config/general", {"enable_key_ssh": h["ssh_auth_mode"]}, label="ssh auth")
        self.ensure("/api/snmp/trap/global", {"enabled": h["snmp_trap_enabled"]}, label="snmp traps")
        # NTP servers
        servers = self.api.get("/api/date_time/ntp/time_servers/config") or []
        wanted = list(h["ntp_servers"])
        have = [s.get("hostname") for s in servers]
        if have != wanted:
            self.changes.append("ntp servers")
            if self.dry:
                log("  [dry-run] NTP servers %s -> %s" % (have, wanted))
            else:
                self._reconcile_ntp_servers(wanted)
        self.ensure("/api/date_time/ntp/client/config/ntpclient", {"enabled": "1"}, label="ntp client")
        logging_cfg = self.api.get("/api/logging/config")[0]
        if (logging_cfg.get("remote_logger") or []) != h["remote_syslog"]:
            self.changes.append("remote syslog")
            if self.dry:
                log("  [dry-run] remote syslog -> %s" % h["remote_syslog"])
            else:
                self.api.write("PUT", "/api/logging/config/general", {"remote_logger": h["remote_syslog"]})
        self.ensure("/api/loopback/global", {"enabled": h["loop_detection_enabled"]}, label="loop detection")
        # LLDP, then undo the firmware quirk (LLDP changes rewrite snmpd and lldp_filter)
        self.ensure("/api/lldp/config/general", {"enabled": h["lldp_enabled"]}, label="lldp")
        if not self.dry:
            time.sleep(3)
        # Firmware 10.2 keeps the SNMP agent on while LLDP is on; the profile sets it inert.
        self._reconcile_snmp(h["snmp_agent"], h.get("remove_snmp_communities", False))
        self.ensure("/api/ports_settings/global", {"lldp_filter": h["lldp_filter"]}, label="lldp filter")
        # Per-port settings
        port_cfg = {e["id"]: e for e in self.api.get("/api/ports_settings/config")}
        loop_cfg = {e["id"]: e for e in self.api.get("/api/loopback/config")}
        storm = self.p["storm_control"]
        for port, spec in self.p["ports"].items():
            desired = {"stp_edge": spec["stp_edge"], "storm_broad_rate": storm, "storm_mult_rate": storm, "storm_uni_rate": storm}
            if "poe" in spec:
                desired["poe_enable"] = spec["poe"]
            self.ensure("/api/ports_settings/config/%s" % port, desired, port_cfg.get(port, {}), label=port)
            self.ensure("/api/loopback/config/%s" % port, {"enabled": spec["loop_detect"]}, loop_cfg.get(port, {}), label="%s loop" % port)

    # -- VLAN and management stages ----------------------------------------
    #
    # Device rules learned on the bench (firmware 10.2):
    # - /api/bulk is NOT atomic; a failed item does not roll back earlier ones.
    # - A port can be untagged in only one VLAN (error 103).
    # - The factory VLAN 1 section is read-only: it cannot be deleted
    #   (error 113) and its VID cannot change. It is left empty at the end.
    # - An interface can only use an existing bridge VLAN.
    # - 802.1X port settings reference VLAN 1 (accept_vlan) even when 802.1X
    #   is off; they are re-homed to the management VLAN.
    #
    # Factory flow (management answers at the factory address):
    #   F1 build the profile on every port except the single linked (bench)
    #      port, which keeps untagged VLAN 1 and gains its tagged VLANs;
    #   F2 add a second static interface "mgmt" on the management VLAN, so the
    #      switch answers both on the bench port (VLAN 1) and on every other
    #      port (VLAN 10);
    #   F3 swap the bench port's untagged VLAN 1 -> 10 and verify the new
    #      address; a partial failure is recovered by moving the cable to any
    #      other copper port, never by a reset;
    #   F4 disable the factory interfaces, leaving VLAN 1 empty.

    def _target(self) -> Dict[str, Dict[str, str]]:
        """VID -> {port: 'u'|'t'|'off'} for the profile."""
        table: Dict[str, Dict[str, str]] = {}
        for vid in self.p["vlans"]:
            table[vid] = {}
            for port, spec in self.p["ports"].items():
                mode = "off"
                if str(spec["untagged"]) == vid:
                    mode = "u"
                elif int(vid) in spec["tagged"]:
                    mode = "t"
                table[vid][port] = mode
        return table

    def _vlan_sections(self) -> Dict[str, Dict[str, Any]]:
        assert self.api is not None
        return {str(s["vlan"]): s for s in self.api.get("/api/port_based_vlan/config")}

    def _linked_ports(self) -> List[str]:
        assert self.api is not None
        return [e["id"] for e in self.api.get("/api/ports_settings/status") if str(e.get("link")) == "1"]

    def _at_factory(self) -> bool:
        assert self.api is not None
        return self.api.base.endswith("//" + self.p["factory_address"])

    def _w(self, method: str, path: str, data: Any, why: str, timeout: float = 60,
           tolerate_drop: bool = False) -> Any:
        assert self.api is not None
        self.changes.append(why)
        if self.dry:
            log("  [dry-run] %s %s %s  (%s)" % (method, path, json.dumps(data) if data is not None else "", why))
            return None
        log("  %s %s  (%s)" % (method, path, why))
        try:
            return self.api.write(method, path, data, timeout=timeout)
        except StepError as exc:
            raise StepError("%s failed: %s" % (why, exc))
        except (OSError, socket.timeout) as exc:
            if not tolerate_drop:
                raise StepError("%s: no response (%s)" % (why, type(exc).__name__))
            log("  response dropped (%s); verifying by reachability" % type(exc).__name__)
            return None

    def _reconcile(self, target: Dict[str, Dict[str, str]], protected: List[str]) -> None:
        """Bring bridge VLAN membership to target with single-item writes (release, then claim)."""
        cur = self._vlan_sections()
        moves = []
        for port in self.p["ports"]:
            tgt = [v for v in target if target[v].get(port) == "u"]
            have = [v for v in cur if cur[v].get(port) == "u"]
            if have != tgt:
                moves.append((port, have, tgt))
        blocked = [m[0] for m in moves if m[0] in protected]
        if blocked:
            raise StepError("refusing to change the untagged VLAN of %s here (management path)" % blocked)
        for vid in target:
            if vid not in cur:
                data = {"vlan": vid}
                data.update({p: ("t" if m == "t" else "off") for p, m in target[vid].items()})
                self._w("POST", "/api/port_based_vlan/config", data, "create VLAN %s" % vid)
        if not self.dry:
            cur = self._vlan_sections()
        for port, have, tgt in moves:
            for v in have:
                if v in cur:
                    new = target.get(v, {}).get(port, "off")
                    self._w("PUT", "/api/port_based_vlan/config/%s" % cur[v]["id"], {port: "off" if new == "u" else new},
                            "release %s from untagged VLAN %s" % (port, v))
            for v in tgt:
                sec_id = cur[v]["id"] if v in cur else "(new VLAN %s)" % v
                self._w("PUT", "/api/port_based_vlan/config/%s" % sec_id, {port: "u"},
                        "set %s untagged in VLAN %s" % (port, v))
        if not self.dry:
            cur = self._vlan_sections()
        for vid, want in target.items():
            if vid not in cur:
                continue
            diff = {p: m for p, m in want.items() if cur[vid].get(p) != m and m != "u"}
            if diff:
                self._w("PUT", "/api/port_based_vlan/config/%s" % cur[vid]["id"], diff, "VLAN %s membership" % vid)

    def _bench_port(self) -> str:
        linked = self._linked_ports()
        if len(linked) != 1:
            raise StepError("expected exactly one linked port (the bench port) at the factory address, found %s" % linked)
        return linked[0]

    def vlans(self) -> None:
        assert self.api is not None
        mv = str(self.p["management"]["vlan"])
        target = self._target()
        if self._at_factory():
            bench = self._bench_port()
            log("vlans: factory address; bench port %s keeps untagged VLAN 1 until the swap" % bench)
            target[mv][bench] = "off"
            target["1"] = {p: ("u" if p == bench else "off") for p in self.p["ports"]}
            self._reconcile(target, protected=[bench])
        else:
            log("vlans: management address; full profile")
            if "1" in self._vlan_sections():
                target["1"] = {p: "off" for p in self.p["ports"]}
            # The reach port is already untagged in the management VLAN, so it is not moved.
            self._reconcile(target, protected=[])
        if not self.dry:
            time.sleep(3)
            self.connect(quiet=True)

    def _wait_for(self, host: str, seconds: int = 180) -> None:
        deadline = time.time() + seconds
        while time.time() < deadline:
            time.sleep(8)
            try:
                fingerprint = pin_peer(host, self.args.serial, self.args.pin_file,
                                       False, None)
            except CertificatePinError:
                raise
            except (OSError, socket.timeout):
                continue
            info = probe(host, fingerprint)
            if info and info.get("device_model") == self.p["model"]:
                observed_serial = info.get("serial") or (info.get("mnfinfo") or {}).get("serial")
                if observed_serial and str(observed_serial) != self.args.serial:
                    raise StepError("device serial does not match the requested TLS pin serial")
                self.api = Api(host, self.user, self.password, fingerprint)
                self.api.login()
                serial = self.api.get("/api/system/device/status")["mnfinfo"]["serial"]
                if str(serial) != self.args.serial:
                    raise StepError("authenticated device serial does not match the requested TLS pin serial")
                return
        raise StepError("switch not reachable at %s within %ds" % (host, seconds))

    def _mgmt_fields(self) -> Dict[str, Any]:
        mgmt = self.p["management"]
        return {"vlan_id": str(mgmt["vlan"]), "proto": "static", "ipaddr": self.mgmt_ip, "netmask": mgmt["netmask"],
                "gateway": mgmt["gateway"], "dns": mgmt["dns"], "enabled": "1"}

    def move(self) -> None:
        assert self.api is not None
        mgmt = self.p["management"]
        mv = str(mgmt["vlan"])
        want = self._mgmt_fields()
        if self._at_factory():
            bench = self._bench_port()
            # F2: second management interface on VLAN 10 (inert on the bench port until the swap).
            ifaces = self.api.get("/api/interfaces/config")
            if not any(i.get("ipaddr") == self.mgmt_ip for i in ifaces):
                data = {"id": "mgmt"}
                data.update(want)
                self._w("POST", "/api/interfaces/config", data, "F2: add management interface %s on VLAN %s" % (self.mgmt_ip, mv))
            # F3: swap the bench port's untagged VLAN; both items in one request, verified by reachability.
            cur = self._vlan_sections()
            if self.dry:
                log("  [dry-run] F3: swap %s untagged VLAN 1 -> %s, then reach %s" % (bench, mv, self.mgmt_ip))
                return
            ops = [{"method": "PUT", "endpoint": "/api/port_based_vlan/config/%s" % cur["1"]["id"], "data": {bench: "off"}},
                   {"method": "PUT", "endpoint": "/api/port_based_vlan/config/%s" % cur[mv]["id"], "data": {bench: "u"}}]
            try:
                self._w("POST", "/api/bulk", ops, "F3: swap %s untagged VLAN 1 -> %s" % (bench, mv), timeout=30,
                        tolerate_drop=True)
            except StepError as exc:
                raise StepError("%s. If the switch no longer answers on the bench port, move the cable to any other "
                                "copper port (untagged VLAN %s) and re-run." % (exc, mv))
            self._wait_for(self.mgmt_ip)
            log("move: F3 verified; management answers at %s" % self.mgmt_ip)
        if self.dry:
            log("  [dry-run] then: management interface %s on VLAN %s, other interfaces off, VLAN 1 empty" % (self.mgmt_ip, mv))
            return
        if self._at_factory():
            raise StepError("still at the factory address after the swap")
        # Management interface fields (the interface that holds the address, else 'static').
        ifaces = self.api.get("/api/interfaces/config")
        holder = next((i for i in ifaces if i.get("ipaddr") == self.mgmt_ip), None) or \
            next(i for i in ifaces if i["id"] == "static")
        diff = {k: v for k, v in want.items() if holder.get(k) != v}
        if diff:
            self._w("PUT", "/api/interfaces/config/%s" % holder["id"], diff, "management interface %s" % holder["id"],
                    timeout=20, tolerate_drop=True)
            self._wait_for(self.mgmt_ip)
        log("move: management answers at %s on interface %s" % (self.mgmt_ip, holder["id"]))
        # F4: remove every other interface (DHCP clients, factory static). On
        # firmware 10.4 a PUT {"enabled": "0"} on an interface returns 200 but
        # does not persist, so the interface is deleted. If a delete is refused,
        # fall back to disable + re-home and verify that it stuck.
        for iface in self.api.get("/api/interfaces/config"):
            if iface["id"] == holder["id"]:
                continue
            try:
                self._w("DELETE", "/api/interfaces/config/%s" % iface["id"], None, "remove interface %s" % iface["id"])
                continue
            except StepError as exc:
                log("  delete refused (%s); disabling instead" % exc)
            d = {}
            if iface.get("enabled") != "0":
                d["enabled"] = "0"
            if iface.get("vlan_id") != mv:
                d["vlan_id"] = mv
            if d:
                self._w("PUT", "/api/interfaces/config/%s" % iface["id"], d, "interface %s off on VLAN %s" % (iface["id"], mv))
                if self.api.get("/api/interfaces/config/%s" % iface["id"]).get("enabled") != "0":
                    raise StepError("interface %s cannot be removed or disabled" % iface["id"])
        for entry in self.api.get("/api/dot1x/ports/config") or []:
            d = {k: mv for k in ("accept_vlan", "fallback_vlan", "guest_vlan", "reject_vlan") if entry.get(k) == "1"}
            if d:
                self._w("PUT", "/api/dot1x/ports/config/%s" % entry["id"], d,
                        "802.1X %s VLAN references to VLAN %s" % (entry["id"], mv))
        cur = self._vlan_sections()
        if "1" in cur:
            members = [p for p in self.p["ports"] if cur["1"].get(p) in ("u", "t")]
            if members:
                raise StepError("VLAN 1 still has members %s" % members)
            log("move: VLAN 1 is empty (the factory section is read-only and stays)")
        time.sleep(3)
        self._wait_for(self.mgmt_ip, seconds=60)
        log("move: verified; management answers at %s" % self.mgmt_ip)

    def readback(self) -> List[Tuple[str, bool, str]]:
        assert self.api is not None
        p, h, mgmt = self.p, self.p["hardening"], self.p["management"]
        a = self.api
        checks: List[Tuple[str, bool, str]] = []

        def chk(name: str, ok: bool, detail: str = "") -> None:
            checks.append((name, bool(ok), detail))

        chk("reached at management address", a.base.endswith(self.mgmt_ip), a.base)
        ver = a.get("/api/firmware/device/status").get("version")
        chk("firmware", ver == p["firmware"]["version"], ver)
        gen = a.get("/api/system/config/general")
        chk("hostname", gen.get("hostname") == self.hostname, gen.get("hostname"))
        chk("rms disabled", a.get("/api/rms/config/rms_connect_mqtt").get("enable") == h["rms_enable"])
        web = a.get("/api/access_control/webui/config")[0]
        chk("https redirect configured", web.get("redirect_https") == h["redirect_https"])
        chk("http redirects to https (probe)", http_redirects(self.mgmt_ip))
        chk("web shell disabled", a.get("/api/access_control/cli/config")[0].get("enabled") == h["web_cli_enabled"])
        chk("ssh key-or-password", a.get("/api/access_control/ssh/config")[0].get("enable_key_ssh") == h["ssh_auth_mode"])
        agent = a.get("/api/snmp/agent/config/general")
        chk("snmp agent as profile (inert)", all(agent.get(k) == v for k, v in h["snmp_agent"].items()),
            " ".join("%s=%s" % (k, agent.get(k)) for k in sorted(h["snmp_agent"])))
        users = a.get("/api/snmp/users/config") or []
        chk("snmp v3 users none", not users, "users=%d" % len(users))
        chk("snmp traps disabled", a.get("/api/snmp/trap/global").get("enabled") == h["snmp_trap_enabled"])
        v4 = a.get("/api/snmp/communities/config") or []
        v6 = a.get("/api/snmp/communities_v6/config") or []
        communities_safe = not v6 and all(
            entry.get("secname") == "ro" and entry.get("ipaddr") == "127.0.0.1" and
            entry.get("netmask") in ("32", "255.255.255.255") for entry in v4)
        chk("snmp communities absent or loopback-only", communities_safe,
            "v4=%d v6=%d" % (len(v4), len(v6)))
        chk("snmp v2c factory community unanswered (probe)", snmp_v2c_unanswered(self.mgmt_ip, "public"))
        ntp = [s.get("hostname") for s in a.get("/api/date_time/ntp/time_servers/config") or []]
        chk("ntp servers", ntp == h["ntp_servers"], ",".join(ntp))
        logcfg = a.get("/api/logging/config")[0]
        chk("remote syslog", (logcfg.get("remote_logger") or []) == h["remote_syslog"], ",".join(logcfg.get("remote_logger") or []))
        chk("lldp enabled", a.get("/api/lldp/config/general").get("enabled") == h["lldp_enabled"])
        chk("lldp filter (locked to 1 while LLDP is on)", a.get("/api/ports_settings/global").get("lldp_filter") == h["lldp_filter"])
        chk("loop detection on", a.get("/api/loopback/global").get("enabled") == h["loop_detection_enabled"])
        ports = {e["id"]: e for e in a.get("/api/ports_settings/config")}
        loops = {e["id"]: e for e in a.get("/api/loopback/config")}
        storm = p["storm_control"]
        bad = []
        for port, spec in p["ports"].items():
            cur = ports.get(port, {})
            if cur.get("stp_edge") != spec["stp_edge"]:
                bad.append("%s edge" % port)
            if "poe" in spec and cur.get("poe_enable") != spec["poe"]:
                bad.append("%s poe" % port)
            for key in ("storm_broad_rate", "storm_mult_rate", "storm_uni_rate"):
                if cur.get(key) != storm:
                    bad.append("%s %s" % (port, key))
            if loops.get(port, {}).get("enabled") != spec["loop_detect"]:
                bad.append("%s loop" % port)
        chk("per-port poe/edge/storm/loop", not bad, ", ".join(bad))
        want = self._target()
        have = self._vlan_sections()
        vbad = [vid for vid in want if vid not in have or any(have[vid].get(pt) != m for pt, m in want[vid].items())]
        extra = [vid for vid in have if vid not in want and
                 not (vid == "1" and all(have[vid].get(pt) in (None, "off") for pt in p["ports"]))]
        chk("vlan table (per port: untagged 10, tagged 20/40/70; VLAN 1 empty)", not vbad and not extra,
            "mismatch=%s extra=%s" % (vbad, extra))
        ifaces = a.get("/api/interfaces/config")
        holder = next((i for i in ifaces if i.get("ipaddr") == self.mgmt_ip), {})
        wantf = self._mgmt_fields()
        ok = bool(holder) and all(holder.get(k) == v for k, v in wantf.items())
        chk("management interface", ok, "%s vlan %s %s/%s gw %s" % (holder.get("id"), holder.get("vlan_id"), holder.get("ipaddr"),
                                                               holder.get("netmask"), holder.get("gateway")))
        others = [i["id"] for i in ifaces if i is not holder and i.get("enabled") != "0"]
        chk("no other interfaces (no DHCP client)", not others, ",".join(others))
        return checks

    # -- driver -------------------------------------------------------------
    def run(self) -> int:
        stop_after = self.args.stop_after
        self.connect()
        for stage in STAGES:
            if stage == "readback":
                if self.dry:
                    break
                ok_all = True
                for n in (1, 2):
                    if n == 2:
                        time.sleep(30)
                        self.connect(quiet=True)
                    results = self.readback()
                    log("read-back %d:" % n)
                    for name, ok, detail in results:
                        log("  %s  %s%s" % ("PASS" if ok else "FAIL", name, ("  (%s)" % detail) if detail else ""))
                    ok_all = ok_all and all(r[1] for r in results)
                log("RESULT: %s" % ("PASS" if ok_all else "FAIL"))
                return 0 if ok_all else 1
            log("== %s" % stage)
            getattr(self, stage)()
            if stage == stop_after:
                log("stopped after %s" % stage)
                break
        if self.dry:
            log("dry-run: %d planned change groups" % len(self.changes))
        return 0


def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Apply the business-switch profile to a Teltonika TSW202 (bench tool).")
    ap.add_argument("--cred-file", required=True, help="root-only env file with TSW202_LABEL_USERNAME/TSW202_LABEL_PASSWORD")
    ap.add_argument("--serial", required=True, help="expected device serial used to select its TLS certificate pin")
    ap.add_argument("--unit", type=int, required=True, help="switch number at the site (1 -> 192.168.10.2)")
    ap.add_argument("--site", default="business", help="site name for the th.{site}.swNN hostname")
    ap.add_argument("--dry-run", action="store_true", help="read and plan only; no writes")
    ap.add_argument("--pin-file", default=DEFAULT_PIN_FILE, help="root-only JSON file for per-serial TLS pins")
    ap.add_argument("--trust-new-cert", action="store_true", help="explicitly trust and record this serial's current certificate")
    ap.add_argument("--cert-sha256", help="expected TLS certificate SHA-256 fingerprint")
    ap.add_argument("--profile", default=DEFAULT_PROFILE)
    ap.add_argument("--iface", default="enp3s0.1993", help="host provisioning VLAN interface for the switch port")
    ap.add_argument("--firmware-dir", default="/var/tmp/tsw202")
    ap.add_argument("--backup-dir", default="/root/tsw202-backups")
    ap.add_argument("--stop-after", choices=STAGES[:-1], default=None)
    ap.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    return ap.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    with open(args.profile) as fh:
        profile = json.load(fh)
    if args.unit < 1 or args.unit > 8:
        log("unit must be 1-8 (management .2-.9)")
        return 2
    if args.inner:
        try:
            return Runner(args, profile).run()
        except StepError as exc:
            log("STOPPED: %s" % exc)
            return 1
    if os.geteuid() != 0:
        log("run as root (the tool creates a temporary network namespace)")
        return 2
    addresses = [profile["factory_netns_address"], profile["management"]["netns_address"]]
    netns_up(args.iface, addresses)
    try:
        cmd = ["ip", "netns", "exec", NETNS, sys.executable, os.path.abspath(__file__), "--inner"] + argv
        return subprocess.call(cmd)
    finally:
        netns_down()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
