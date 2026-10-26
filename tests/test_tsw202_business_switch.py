import json
import os
import stat
import sys
from argparse import Namespace

import pytest

from scripts import tsw202_business_switch
from scripts.tsw202_business_switch import Runner


class FactoryApi:
    base = "https://192.168.1.2"

    def get(self, path):
        if path == "/api/interfaces/config":
            return []
        if path == "/api/ports_settings/status":
            return [{"id": "port1", "link": "1"}]
        if path == "/api/port_based_vlan/config":
            return [{"id": "vlan1", "vlan": "1", "port1": "u"}]
        raise AssertionError("unexpected GET %s" % path)


def test_factory_dry_run_plans_swap_when_management_vlan_is_new(capsys):
    runner = Runner.__new__(Runner)
    runner.api = FactoryApi()
    runner.p = {
        "factory_address": "192.168.1.2",
        "management": {
            "vlan": 10,
            "netmask": "255.255.255.0",
            "gateway": "192.168.10.1",
            "dns": ["100.126.15.20", "9.9.9.9"],
        },
    }
    runner.mgmt_ip = "192.168.10.3"
    runner.dry = True
    runner.changes = []

    runner.move()

    assert "F3: swap port1 untagged VLAN 1 -> 10" in capsys.readouterr().out


class NtpApi:
    def __init__(self):
        self.servers = [
            {"id": "ntp1", "hostname": "time1.google.com"},
            {"id": "ntp2", "hostname": "time2.google.com"},
            {"id": "ntp3", "hostname": "time3.google.com"},
            {"id": "ntp4", "hostname": "time4.google.com"},
        ]
        self.operations = []
        self.max_entries = len(self.servers)

    def get(self, path):
        assert path == "/api/date_time/ntp/time_servers/config"
        return list(self.servers)

    def write(self, method, path, data=None):
        assert path.startswith("/api/date_time/ntp/time_servers/config")
        if method == "DELETE":
            self.servers = [server for server in self.servers if server["id"] != path.rsplit("/", 1)[1]]
        elif method == "POST":
            assert len(self.servers) < 4
            self.servers.append({"id": "new%d" % len(self.servers), "hostname": data["hostname"]})
        else:
            raise AssertionError("unexpected method %s" % method)
        self.operations.append(method)
        self.max_entries = max(self.max_entries, len(self.servers))


def test_ntp_reconcile_frees_slots_before_adding():
    runner = Runner.__new__(Runner)
    runner.api = NtpApi()

    runner._reconcile_ntp_servers(["129.6.15.28", "129.6.15.29"])

    assert [server["hostname"] for server in runner.api.servers] == ["129.6.15.28", "129.6.15.29"]
    assert runner.api.max_entries == 4
    assert runner.api.operations[:2] == ["DELETE", "POST"]


class SnmpApi:
    def __init__(self):
        self.agent = {"enabled": "1", "v1mode": "1", "v2cmode": "1", "v3mode": None}
        self.communities = []
        self.operations = []

    def get(self, path):
        if path == "/api/snmp/agent/config/general":
            return dict(self.agent)
        if path == "/api/snmp/communities/config":
            return list(self.communities)
        if path == "/api/snmp/communities_v6/config":
            return []
        raise AssertionError("unexpected GET %s" % path)

    def write(self, method, path, data=None):
        if method == "POST" and path == "/api/snmp/communities/config":
            self.communities.append(dict(data, id="temporary"))
        elif method == "PUT" and path == "/api/snmp/agent/config/general":
            self.agent.update(data)
        elif method == "DELETE" and path == "/api/snmp/communities/config/temporary":
            self.communities = []
        else:
            raise AssertionError("unexpected write %s %s" % (method, path))
        self.operations.append((method, path, data))


def test_snmp_reconcile_keeps_loopback_community_as_firmware_requires(monkeypatch):
    runner = Runner.__new__(Runner)
    runner.api = SnmpApi()
    runner.dry = False
    runner.changes = []
    monkeypatch.setattr(tsw202_business_switch.secrets, "token_hex", lambda size: "a" * (size * 2))

    runner._reconcile_snmp({"enabled": "1", "v1mode": "0", "v2cmode": "0", "v3mode": "1"})

    assert [op[0] for op in runner.api.operations] == ["POST", "PUT"]
    temporary = runner.api.operations[0][2]
    assert temporary["secname"] == "ro"
    assert temporary["ipaddr"] == "127.0.0.1"
    assert temporary["netmask"] == "32"
    assert len(temporary["community"]) == 30
    assert runner.api.agent == {"enabled": "1", "v1mode": "0", "v2cmode": "0", "v3mode": "1"}
    assert len(runner.api.communities) == 1


def test_snmp_community_validation_error_does_not_echo_generated_value(monkeypatch):
    class RejectingApi(SnmpApi):
        def write(self, method, path, data=None):
            if method == "POST":
                raise tsw202_business_switch.StepError(
                    'POST failed: [{"value":"test-community-secret","error":"invalid"}]')
            return super().write(method, path, data)

    runner = Runner.__new__(Runner)
    runner.api = RejectingApi()
    runner.dry = False
    runner.changes = []
    monkeypatch.setattr(tsw202_business_switch.secrets, "token_hex", lambda size: "b" * (size * 2))

    try:
        runner._reconcile_snmp({"enabled": "1", "v1mode": "0", "v2cmode": "0", "v3mode": "1"})
    except tsw202_business_switch.StepError as exc:
        assert "test-community-secret" not in str(exc)
        assert "details withheld" in str(exc)
    else:
        raise AssertionError("SNMP validation failure should stop the run")


def test_tls_pin_match_passes(tmp_path, monkeypatch):
    serial = "1234567890"
    fingerprint = "a" * 64
    pin_file = str(tmp_path / "pins.json")
    tsw202_business_switch._write_pins(pin_file, {serial: fingerprint})
    monkeypatch.setattr(tsw202_business_switch, "peer_fingerprint", lambda host: fingerprint)

    assert tsw202_business_switch.pin_peer("192.0.2.1", serial, pin_file) == fingerprint


def test_tls_pin_mismatch_stops_before_login_or_credentials(monkeypatch, tmp_path, capsys):
    serial = "1234567890"
    tsw202_business_switch._write_pins(str(tmp_path / "pins.json"), {serial: "a" * 64})
    monkeypatch.setattr(tsw202_business_switch, "peer_fingerprint", lambda host: "b" * 64)
    monkeypatch.setattr(tsw202_business_switch, "probe", lambda host, fingerprint: pytest.fail("probe must not run"))
    monkeypatch.setattr(tsw202_business_switch, "Api", lambda *args: pytest.fail("credentials must not be sent"))
    runner = Runner.__new__(Runner)
    runner.args = Namespace(serial=serial, pin_file=str(tmp_path / "pins.json"),
                             trust_new_cert=False, cert_sha256=None)
    runner.mgmt_ip = "192.0.2.1"
    runner.p = {"factory_address": "192.0.2.2"}
    runner.user = "label-user"
    runner.password = "test-password-value"
    runner._allow_pin_update = False

    with pytest.raises(tsw202_business_switch.CertificatePinError):
        runner.connect()
    output = capsys.readouterr().out
    assert "test-password-value" not in output


def test_tls_without_pin_or_explicit_trust_stops_before_request(monkeypatch, tmp_path):
    monkeypatch.setattr(tsw202_business_switch, "peer_fingerprint", lambda host: "c" * 64)

    with pytest.raises(tsw202_business_switch.StepError, match="no TLS pin"):
        tsw202_business_switch.pin_peer("192.0.2.1", "1234567890", str(tmp_path / "pins.json"))


def test_trust_new_certificate_records_root_only_pin(tmp_path, monkeypatch, capsys):
    serial = "1234567890"
    fingerprint = "d" * 64
    pin_file = str(tmp_path / "pins.json")
    monkeypatch.setattr(tsw202_business_switch, "peer_fingerprint", lambda host: fingerprint)

    assert tsw202_business_switch.pin_peer("192.0.2.1", serial, pin_file, trust_new_cert=True) == fingerprint
    assert tsw202_business_switch._read_pins(pin_file) == {serial: fingerprint}
    assert stat.S_IMODE(os.stat(pin_file).st_mode) == 0o600
    assert "test-password-value" not in capsys.readouterr().out


def test_explicit_trust_can_replace_a_changed_pin(tmp_path, monkeypatch):
    serial = "1234567890"
    pin_file = str(tmp_path / "pins.json")
    tsw202_business_switch._write_pins(pin_file, {serial: "d" * 64})
    monkeypatch.setattr(tsw202_business_switch, "peer_fingerprint", lambda host: "e" * 64)

    assert tsw202_business_switch.pin_peer("192.0.2.1", serial, pin_file, trust_new_cert=True) == "e" * 64
    assert tsw202_business_switch._read_pins(pin_file) == {serial: "e" * 64}


def test_login_password_is_not_in_argv_or_logs(monkeypatch, capsys):
    password = "test-password-value"

    class Response:
        status = 200

        def read(self):
            return b'{"data":{"token":"test-token"}}'

    class Opener:
        def open(self, request, timeout):
            assert json.loads(request.data.decode())["password"] == password
            return Response()

    api = tsw202_business_switch.Api("192.0.2.1", "label-user", password, "e" * 64)
    api.opener = Opener()
    monkeypatch.setattr(sys, "argv", ["tsw202_business_switch.py"])

    api.login()

    assert password not in sys.argv
    assert password not in capsys.readouterr().out


def test_https_pin_mismatch_blocks_login_request(monkeypatch, capsys):
    password = "test-password-value"

    def reject_connection(self):
        raise tsw202_business_switch.CertificatePinError("pin mismatch")

    monkeypatch.setattr(tsw202_business_switch._PinnedHTTPSConnection, "connect", reject_connection)
    api = tsw202_business_switch.Api("192.0.2.1", "label-user", password, "f" * 64)

    with pytest.raises(tsw202_business_switch.CertificatePinError):
        api.login()
    assert password not in capsys.readouterr().out

