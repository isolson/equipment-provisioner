#!/usr/bin/env python3
"""Interim bench tool: MikroTik business router/switch profiles on one bench port.

Run on the bench host. The profile text and read-back checks come from
provisioner/handlers/mikrotik_business.py, so this tool adds no second copy of
the business policy. See docs/business-bench-sop.md for the procedure.

The device password is read from the MIKROTIK_PASS environment variable. It is
never accepted on the command line and never printed.

    probe               ARP + MNDP on the port; no login
    clear-first-login   re-set admin to its current password (clears RouterOS
                        7.20+ "expired"); the login does not change
    update              RouterOS + RouterBOOT to --target from the firmware repo
    apply               upload, dry-run, import on-device, reconnect, read back
    verify              read-only read-back of every profile check
    relay               internal: interface-bound TCP relay for ssh ProxyCommand
"""
import argparse
import base64
import importlib.util
import json
import os
import select
import shlex
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = Path("/var/lib/provisioner/repo/firmware/mikrotik")
FACTORY_IP, FACTORY_SRC = "192.168.88.1", "192.168.88.11"
MGMT_SRC = "192.168.10.254"
SO_BINDTODEVICE = 25
REMOTE_PROFILE = "business-profile.rsc"
# Boards with a business-profile run on record (docs/business-bench-sop.md).
# Anything else needs --allow-unqualified-board and its own evidence.
KNOWN_BOARDS = {"hEX S": "arm", "hEX PoE": "mipsbe"}


def business():
    """Load the handler-owned profile module without importing the handler package."""
    path = REPO / "provisioner" / "handlers" / "mikrotik_business.py"
    spec = importlib.util.spec_from_file_location("mikrotik_business", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render(mode, pin_poe):
    """Return (profile text, checks) for a mode, optionally pinning one PoE port."""
    b = business()
    text, checks = b.profile_text(mode), b.check_expressions(mode)
    if pin_poe and "poe_" + pin_poe not in checks:
        marker = '/system note set note="%s%s"' % (b.PROFILE_MARKER, mode)
        if text.count(marker) != 1:
            raise SystemExit("profile marker not found; cannot pin PoE")
        line = '/interface ethernet poe set [find where name="%s"] poe-out=auto-on' % pin_poe
        text = text.replace(marker, line + "\n" + marker)
        checks["poe_" + pin_poe] = '[/interface ethernet poe get [find where name="%s"] poe-out] = "auto-on"' % pin_poe
    return text, checks, b.MANAGEMENT_IPS[mode]


class Device:
    def __init__(self, iface, src, dst):
        self.iface, self.src, self.dst = iface, src, dst
        if not os.environ.get("MIKROTIK_PASS"):
            raise SystemExit("set MIKROTIK_PASS in the environment (read -rs MIKROTIK_PASS; export MIKROTIK_PASS)")
        self.env = dict(os.environ, SSHPASS=os.environ["MIKROTIK_PASS"])

    def opts(self):
        relay = "%s %s relay %s %s %s 22" % (shlex.quote(sys.executable), shlex.quote(str(Path(__file__).resolve())),
                                            self.iface, self.src, self.dst)
        return ["-o", "ProxyCommand=" + relay, "-o", "PubkeyAuthentication=no",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10"]

    def run(self, command, timeout=120):
        r = subprocess.run(["sshpass", "-e", "ssh"] + self.opts() + ["admin@device", command],
                           capture_output=True, text=True, timeout=timeout, env=self.env)
        return r.returncode, r.stdout.replace("\r", "").strip()

    def upload(self, local, remote, timeout=300):
        r = subprocess.run(["sshpass", "-e", "scp", "-O"] + self.opts() + [str(local), "admin@device:" + remote],
                           capture_output=True, text=True, timeout=timeout, env=self.env)
        return r.returncode == 0

    def facts(self):
        rc, out = self.run(':put [/system routerboard get serial-number]; :put [/system resource get board-name]; '
                           ':put [/system resource get architecture-name]; :put [/system resource get version]; '
                           ':put [/system routerboard get current-firmware]; :put [/system routerboard get upgrade-firmware]',
                           timeout=40)
        lines = out.splitlines()
        if rc or len(lines) != 6:
            return None
        serial, board, arch, version, current, upgrade = lines
        return dict(serial=serial, board=board, arch=arch, version=version.split()[0], current=current, upgrade=upgrade)

    def checks(self, checks):
        command = "; ".join(':put ("%s=" . (%s))' % kv for kv in checks.items())
        rc, out = self.run(command, timeout=120)
        values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        return {key: values.get(key) == "true" for key in checks}


def require(dev, args):
    facts = dev.facts()
    if not facts:
        raise SystemExit("login failed or device unreachable at %s on %s" % (dev.dst, dev.iface))
    if facts["serial"] != args.serial:
        raise SystemExit("serial mismatch: expected %s, device reports %s" % (args.serial, facts["serial"]))
    expected_arch = KNOWN_BOARDS.get(facts["board"])
    if expected_arch != facts["arch"] and not args.allow_unqualified_board:
        raise SystemExit("board %s/%s has no business-profile run on record; see the SOP" % (facts["board"], facts["arch"]))
    return facts


def wait_for(dev, serial, attempts=40):
    for _ in range(attempts):
        time.sleep(5)
        try:
            facts = dev.facts()
        except subprocess.TimeoutExpired:
            continue
        if facts and facts["serial"] == serial:
            return facts
    raise SystemExit("device did not come back at %s" % dev.dst)


def reboot(dev, serial):
    try:
        dev.run(":execute {/system reboot}", timeout=20)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(30)
    return wait_for(dev, serial)


def ensure_mgmt_source(iface):
    subprocess.run(["sudo", "-n", "ip", "address", "replace", MGMT_SRC + "/32", "dev", iface, "noprefixroute"], check=True)


def report(results):
    for key, ok in results.items():
        print("%-34s %s" % (key, "PASS" if ok else "FAIL"))
    passed = sum(results.values())
    print("RESULT: %d/%d checks pass" % (passed, len(results)))
    return passed == len(results)


def cmd_probe(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, (args.iface + "\0").encode())
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", 5678))
    s.settimeout(5)
    names = {1: "mac", 5: "identity", 7: "version", 12: "board", 16: "interface"}
    end = time.time() + args.timeout
    while time.time() < end:
        try:
            data, addr = s.recvfrom(2000)
        except socket.timeout:
            s.sendto(b"\0\0\0\0", ("255.255.255.255", 5678))
            continue
        if len(data) <= 4:
            continue
        fields, i = {}, 4
        while i + 4 <= len(data):
            kind, length = struct.unpack(">HH", data[i:i + 4])
            fields[kind] = data[i + 4:i + 4 + length]
            i += 4 + length
        shown = {names[k]: (v.hex(":") if k == 1 else v.decode(errors="replace")) for k, v in fields.items() if k in names}
        print(addr[0], json.dumps(shown))
        return 0
    print("no MNDP announcement on %s within %ss" % (args.iface, args.timeout))
    return 1


def cmd_clear_first_login(args):
    password = os.environ.get("MIKROTIK_PASS")
    if not password:
        raise SystemExit("set MIKROTIK_PASS in the environment")

    def rest(method, path, body=b""):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, (args.iface + "\0").encode())
        s.settimeout(30)
        s.bind((FACTORY_SRC, 0))
        s.connect((FACTORY_IP, 80))
        auth = base64.b64encode(("admin:" + password).encode()).decode()
        s.sendall(("%s %s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\nContent-Type: application/json\r\n"
                   "Content-Length: %d\r\n\r\n" % (method, path, FACTORY_IP, auth, len(body))).encode() + body)
        reply = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            reply += chunk
        head, _, payload = reply.partition(b"\r\n\r\n")
        return int(head.split()[1]), payload

    status, payload = rest("GET", "/rest/user")
    if status != 200:
        raise SystemExit("REST login refused (HTTP %d): the password does not match this unit" % status)
    users = [u for u in json.loads(payload) if u.get("name") == "admin"]
    if not users:
        raise SystemExit("no admin user")
    if users[0].get("expired") != "true":
        print("admin is not flagged expired; nothing to do")
        return 0
    body = json.dumps({".id": users[0][".id"], "password": password}).encode()
    status, _ = rest("POST", "/rest/user/set", body)
    status_after, payload = rest("GET", "/rest/user")
    admin = [u for u in json.loads(payload) if u.get("name") == "admin"][0] if status_after == 200 else {}
    if status != 200 or admin.get("expired") != "false":
        raise SystemExit("first-login flag not cleared")
    print("first-login flag cleared; login unchanged")
    return 0


def cmd_update(args):
    dev = Device(args.iface, FACTORY_SRC, FACTORY_IP)
    facts = require(dev, args)
    print("before: RouterOS %s, RouterBOOT %s (%s/%s)" % (facts["version"], facts["current"], facts["board"], facts["arch"]), flush=True)
    if facts["version"] != args.target:
        npk = FIRMWARE_DIR / ("routeros-%s-%s.npk" % (facts["arch"], args.target))
        if not npk.is_file():
            raise SystemExit("missing %s" % npk)
        remote = npk.name
        # 16 MB boards show less free flash than the package size; RouterOS
        # still accepted the upload on the hEX PoE. Remove a partial file on failure.
        if not dev.upload(npk, remote):
            dev.run(':do {/file remove [find where name="%s"]} on-error={}' % remote)
            raise SystemExit("package upload failed; partial file removed; no reboot")
        rc, size = dev.run(':put [/file get [find where name="%s"] size]' % remote)
        if size != str(npk.stat().st_size):
            dev.run(':do {/file remove [find where name="%s"]} on-error={}' % remote)
            raise SystemExit("uploaded size mismatch; file removed; no reboot")
        print("package uploaded; rebooting to install", flush=True)
        facts = reboot(dev, args.serial)
        if facts["version"] != args.target:
            raise SystemExit("install not verified: device reports %s" % facts["version"])
    if facts["current"] != facts["upgrade"]:
        dev.run("/system routerboard upgrade")
        time.sleep(5)
        print("RouterBOOT upgrade staged; rebooting", flush=True)
        facts = reboot(dev, args.serial)
    if facts["current"] != facts["upgrade"]:
        raise SystemExit("RouterBOOT not verified (%s vs %s)" % (facts["current"], facts["upgrade"]))
    print("RESULT: RouterOS %s, RouterBOOT %s" % (facts["version"], facts["current"]))
    return 0


def cmd_apply(args):
    text, checks, mgmt_ip = render(args.mode, args.pin_poe)
    ensure_mgmt_source(args.iface)
    dev = Device(args.iface, FACTORY_SRC, FACTORY_IP)
    facts = require(dev, args)
    print("identity: %s %s %s RouterOS %s" % (facts["serial"], facts["board"], facts["arch"], facts["version"]), flush=True)
    local = Path("/tmp") / ("business-profile-%s.rsc" % args.serial)
    local.write_text(text)
    try:
        if not dev.upload(local, REMOTE_PROFILE, timeout=60):
            raise SystemExit("profile upload failed")
    finally:
        local.unlink()
    rc, out = dev.run("/import file-name=%s verbose=yes dry-run" % REMOTE_PROFILE, timeout=180)
    if "No syntax errors found" not in out:
        dev.run("/file remove %s" % REMOTE_PROFILE)
        raise SystemExit("dry-run failed; nothing applied (diagnose in the protected evidence workflow)")
    print("dry-run: no syntax errors", flush=True)
    dev.run("/execute {/import file-name=%s}" % REMOTE_PROFILE)
    print("import launched on device; waiting for %s" % mgmt_ip, flush=True)
    mgmt = Device(args.iface, MGMT_SRC, mgmt_ip)
    wait_for(mgmt, args.serial)
    results = {}
    for _ in range(12):
        results = mgmt.checks(checks)
        if all(results.values()):
            break
        time.sleep(5)
    rc, _ = mgmt.run("/file remove %s" % REMOTE_PROFILE)
    print("uploaded profile removed (rc=%s)" % rc)
    return 0 if report(results) else 1


def cmd_verify(args):
    _, checks, mgmt_ip = render(args.mode, args.pin_poe)
    ensure_mgmt_source(args.iface)
    dev = Device(args.iface, MGMT_SRC, mgmt_ip)
    require(dev, args)
    return 0 if report(dev.checks(checks)) else 1


def cmd_relay(args):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, (args.iface + "\0").encode())
    s.bind((args.src, 0))
    s.connect((args.dst, args.port))
    while True:
        ready, _, _ = select.select([0, s], [], [])
        if 0 in ready:
            data = os.read(0, 65536)
            if not data:
                s.shutdown(socket.SHUT_WR)
            else:
                s.sendall(data)
        if s in ready:
            data = s.recv(65536)
            if not data:
                return 0
            os.write(1, data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def device_args(p):
        p.add_argument("--iface", required=True, help="bench port VLAN interface, e.g. enp3s0.1995")
        p.add_argument("--serial", required=True, help="serial from the label; every write is guarded by it")
        p.add_argument("--allow-unqualified-board", action="store_true")

    p = sub.add_parser("probe")
    p.add_argument("--iface", required=True)
    p.add_argument("--timeout", type=int, default=60)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("clear-first-login")
    p.add_argument("--iface", required=True)
    p.set_defaults(func=cmd_clear_first_login)

    p = sub.add_parser("update")
    device_args(p)
    p.add_argument("--target", required=True, help="RouterOS version present in the firmware repo, e.g. 7.24.5")
    p.set_defaults(func=cmd_update)

    for name, func in (("apply", cmd_apply), ("verify", cmd_verify)):
        p = sub.add_parser(name)
        device_args(p)
        p.add_argument("--mode", required=True, choices=sorted(business().MANAGEMENT_IPS))
        p.add_argument("--pin-poe", metavar="PORT", help="also set PORT poe-out=auto-on and check it, e.g. ether5")
        p.set_defaults(func=func)

    p = sub.add_parser("relay")
    p.add_argument("iface")
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("port", type=int)
    p.set_defaults(func=cmd_relay)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
