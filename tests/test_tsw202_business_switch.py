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

