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
        --cred-file /root/tsw202-unit2.env --unit 2 --site business \\
        --firmware-dir /var/tmp/tsw202
"""

import argparse
import hashlib
import json
import os
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROFILE = os.path.join(HERE, "tsw202_business_switch_profile.json")
NETNS = "tsw202bs"
MACVLAN = "tsw202mv"
STAGES = ("backup", "firmware", "hardening", "vlans", "move", "readback")


class StepError(Exception):
    """A write or check failed; the run stops and reports the state."""


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
    def __init__(self, host: str, username: str, password: str) -> None:
        self.base = "https://%s" % host
        self._user = username
        self._pass = password
        self._token: Optional[str] = None
        self._token_time = 0.0
        self.ctx = ssl._create_unverified_context()

    def _raw(self, method: str, path: str, body: Optional[bytes], headers: Dict[str, str],
             timeout: float = 30) -> Tuple[int, bytes]:
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=timeout)
            return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

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


def probe(host: str, timeout: float = 4) -> Optional[Dict[str, Any]]:
    ctx = ssl._create_unverified_context()
    try:
        resp = urllib.request.urlopen("https://%s/api/unauthorized/status" % host, context=ctx, timeout=timeout)
        return (json.loads(resp.read()) or {}).get("data")
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

    # -- helpers ----------------------------------------------------------
    def connect(self, quiet: bool = False) -> str:
        for host in (self.mgmt_ip, self.p["factory_address"]):
            info = probe(host)
            if info and info.get("device_model") == self.p["model"]:
                self.api = Api(host, self.user, self.password)
                self.api.login()
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
        if h.get("remove_snmp_communities"):
            # Anonymous UCI sections (cfgNNxxxx) renumber after each delete, so
            # re-read the list before every delete instead of iterating a stale one.
            for ep in ("/api/snmp/communities/config", "/api/snmp/communities_v6/config"):
                for _ in range(16):
                    entries = self.api.get(ep) or []
                    if not entries:
                        break
                    entry = entries[0]
                    self.changes.append("delete %s/%s" % (ep, entry["id"]))
                    if self.dry:
                        for e in entries:
                            log("  [dry-run] DELETE %s/%s" % (ep, e["id"]))
                        break
                    self.api.write("DELETE", "%s/%s" % (ep, entry["id"]))
                else:
                    raise StepError("could not empty %s" % ep)
        # NTP servers
        servers = self.api.get("/api/date_time/ntp/time_servers/config") or []
        wanted = list(h["ntp_servers"])
        have = [s.get("hostname") for s in servers]
        if have != wanted:
            self.changes.append("ntp servers")
            if self.dry:
                log("  [dry-run] NTP servers %s -> %s" % (have, wanted))
            else:
                # The device refuses to delete its last server: add first, then prune.
                for host in wanted:
                    if host not in have:
                        self.api.write("POST", "/api/date_time/ntp/time_servers/config", {"hostname": host})
                for _ in range(32):
                    remaining = self.api.get("/api/date_time/ntp/time_servers/config") or []
                    extra = [s for s in remaining if s.get("hostname") not in wanted]
                    if not extra:
                        break
                    self.api.write("DELETE", "/api/date_time/ntp/time_servers/config/%s" % extra[0]["id"])
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
        self.ensure("/api/snmp/agent/config/general", h["snmp_agent"], label="snmp agent after lldp")
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

    def _desired_vlans(self, final: bool) -> Dict[str, Dict[str, str]]:
        """VID -> {port: 'u'|'t'|'off'}; before the move, the move port stays untagged in VLAN 1."""
        move_port = self.p["management_move_port"]
        ports = list(self.p["ports"])
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
        if not final:
            table[str(self.p["management"]["vlan"])][move_port] = "off"
            table["1"] = {p: ("u" if p == move_port else "off") for p in ports}
        return table

    def _vlan_sections(self) -> Dict[str, Dict[str, Any]]:
        assert self.api is not None
        return {str(s["vlan"]): s for s in self.api.get("/api/port_based_vlan/config")}

    def vlans(self) -> None:
        """Build the business VLANs while management stays on VLAN 1 via the move port."""
        assert self.api is not None
        current = self._vlan_sections()
        if str(self.p["management"]["vlan"]) in current and "1" not in current:
            log("vlans: management already moved")
            return
        desired = self._desired_vlans(final=False)
        ops = []
        # Remove ports from VLAN 1 first so no port is untagged twice.
        if "1" in current:
            diff = {p: m for p, m in desired["1"].items() if current["1"].get(p) != m}
            if diff:
                ops.append({"method": "PUT", "endpoint": "/api/port_based_vlan/config/%s" % current["1"]["id"], "data": diff})
        for vid in self.p["vlans"]:
            want = desired[vid]
            if vid in current:
                diff = {p: m for p, m in want.items() if current[vid].get(p) != m}
                if diff:
                    ops.append({"method": "PUT", "endpoint": "/api/port_based_vlan/config/%s" % current[vid]["id"], "data": diff})
            else:
                data = {"vlan": vid}
                data.update(want)
                ops.append({"method": "POST", "endpoint": "/api/port_based_vlan/config", "data": data})
        if not ops:
            log("vlans: already built")
            return
        self.changes.append("vlan build (%d ops)" % len(ops))
        if self.dry:
            for op in ops:
                log("  [dry-run] bulk %s %s" % (op["method"], op["endpoint"]))
            return
        self.api.write("POST", "/api/bulk", ops, timeout=120)
        time.sleep(5)

    def move(self) -> None:
        """Atomic move: VLAN 1 removed, move port untagged in VLAN 10, management interface to VLAN 10."""
        assert self.api is not None
        mgmt = self.p["management"]
        vid = str(mgmt["vlan"])
        current = self._vlan_sections()
        iface = self.api.get("/api/interfaces/config/static")
        target_iface = {"vlan_id": vid, "proto": "static", "ipaddr": self.mgmt_ip, "netmask": mgmt["netmask"],
                        "gateway": mgmt["gateway"], "dns": mgmt["dns"], "enabled": "1"}
        iface_diff = {k: v for k, v in target_iface.items() if iface.get(k) != v}
        ops = []
        if "1" in current:
            ops.append({"method": "DELETE", "endpoint": "/api/port_based_vlan/config/%s" % current["1"]["id"]})
        move_port = self.p["management_move_port"]
        if vid in current and current[vid].get(move_port) != "u":
            ops.append({"method": "PUT", "endpoint": "/api/port_based_vlan/config/%s" % current[vid]["id"], "data": {move_port: "u"}})
        if iface_diff:
            ops.append({"method": "PUT", "endpoint": "/api/interfaces/config/static", "data": iface_diff})
        for name in mgmt["disable_interfaces"]:
            cfg = self.api.get("/api/interfaces/config/%s" % name)
            if cfg.get("enabled") != "0":
                ops.append({"method": "PUT", "endpoint": "/api/interfaces/config/%s" % name, "data": {"enabled": "0"}})
        if not ops:
            log("move: management already on VLAN %s at %s" % (vid, self.mgmt_ip))
            return
        self.changes.append("management move (%d ops)" % len(ops))
        if self.dry:
            for op in ops:
                log("  [dry-run] bulk %s %s %s" % (op["method"], op["endpoint"], sorted((op.get("data") or {}).keys())))
            return
        log("move: applying %d operations; the session will drop" % len(ops))
        # /api/bulk is NOT atomic: items apply in order and a failed item does
        # not roll back earlier ones. Log every item result before probing.
        try:
            self.api.write("POST", "/api/bulk", ops, timeout=30)
        except StepError as exc:
            log("move: bulk reported a failure: %s" % exc)
            raise StepError("management move partially applied; see the bulk failure above. "
                            "Recover by connecting the bench to another VLAN 10 untagged port and re-running.")
        except (OSError, socket.timeout) as exc:
            log("move: request ended (%s); checking the new address" % type(exc).__name__)
        deadline = time.time() + 180
        while time.time() < deadline:
            time.sleep(10)
            info = probe(self.mgmt_ip)
            if info and info.get("device_model") == self.p["model"]:
                self.api = Api(self.mgmt_ip, self.user, self.password)
                self.api.login()
                log("move: reached management at %s" % self.mgmt_ip)
                return
        raise StepError("management address %s not reachable after the move" % self.mgmt_ip)

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
        chk("snmp communities removed", not v4 and not v6, "v4=%d v6=%d" % (len(v4), len(v6)))
        chk("snmp v2c factory community unanswered (probe)", snmp_v2c_unanswered(self.mgmt_ip, "public"))
        ntp = [s.get("hostname") for s in a.get("/api/date_time/ntp/time_servers/config") or []]
        chk("ntp servers", ntp == h["ntp_servers"], ",".join(ntp))
        logcfg = a.get("/api/logging/config")[0]
        chk("remote syslog", (logcfg.get("remote_logger") or []) == h["remote_syslog"], ",".join(logcfg.get("remote_logger") or []))
        chk("lldp enabled", a.get("/api/lldp/config/general").get("enabled") == h["lldp_enabled"])
        chk("lldp filter off", a.get("/api/ports_settings/global").get("lldp_filter") == h["lldp_filter"])
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
        want = self._desired_vlans(final=True)
        have = self._vlan_sections()
        vbad = [vid for vid in want if vid not in have or any(have[vid].get(pt) != m for pt, m in want[vid].items())]
        extra = [vid for vid in have if vid not in want]
        chk("vlan table", not vbad and not extra, "mismatch=%s extra=%s" % (vbad, extra))
        iface = a.get("/api/interfaces/config/static")
        ok = (iface.get("vlan_id") == str(mgmt["vlan"]) and iface.get("ipaddr") == self.mgmt_ip and
              iface.get("netmask") == mgmt["netmask"] and iface.get("gateway") == mgmt["gateway"] and
              iface.get("dns") == mgmt["dns"])
        chk("management interface", ok, "vlan %s %s gw %s" % (iface.get("vlan_id"), iface.get("ipaddr"), iface.get("gateway")))
        for name in mgmt["disable_interfaces"]:
            chk("%s client disabled" % name, a.get("/api/interfaces/config/%s" % name).get("enabled") == "0")
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
    ap.add_argument("--unit", type=int, required=True, help="switch number at the site (1 -> 192.168.10.2)")
    ap.add_argument("--site", default="business", help="site name for the th.{site}.swNN hostname")
    ap.add_argument("--dry-run", action="store_true", help="read and plan only; no writes")
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
