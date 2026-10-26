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

