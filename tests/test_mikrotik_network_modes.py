"""Wired-mode changes must preserve management and refuse unrelated layouts."""
from unittest.mock import AsyncMock
import pytest
from provisioner.handlers.mikrotik import MikrotikHandler


def state(mode="router"):
    result = dict(model="hEX S", architecture="arm", bridges=1, standard_bridge=1,
                  ethernet_ports=6, lan_bridged=5, nat_rules=1, standard_nat=1,
                  dhcp_servers=1, standard_dhcp_server=1, dhcp_clients=1,
                  wan_dhcp_client=1, management_address=1, fleet_scripts=0,
                  mode=mode, firmware="7.23.5")
    switch = mode == "switch"
    result.update(wan_bridged=int(switch), nat_enabled=int(not switch),
                  dhcp_servers_enabled=int(not switch), dhcp_clients_enabled=int(not switch),
                  forward_ipv4="no" if switch else "yes", forward_ipv6="no" if switch else "yes")
    return result


def handler():
    return MikrotikHandler("192.0.2.1", {}, interface="test0")


@pytest.mark.asyncio
@pytest.mark.parametrize("key,value", [("architecture", "mmips"), ("bridges", 2),
    ("lan_bridged", 4), ("standard_nat", 0), ("fleet_scripts", 1), ("management_address", 0)])
async def test_unrecognized_layout_never_writes(key, value):
    h = handler()
    before = state()
    before[key] = value
    h.network_mode_state = AsyncMock(return_value=before)
    h._run_command = AsyncMock()
    with pytest.raises(ValueError):
        await h.apply_network_mode("switch")
    h._run_command.assert_not_awaited()



@pytest.mark.asyncio
async def test_qualified_layout_delegates_to_business_executor(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h = handler()
    h.network_mode_state = AsyncMock(return_value=state())
    executor = AsyncMock(return_value={"profile": "business-v1", "mode": "switch"})
    monkeypatch.setattr(mikrotik_business, "apply", executor)
    assert (await h.apply_network_mode("switch"))["profile"] == "business-v1"
    executor.assert_awaited_once_with(h, "switch")


@pytest.mark.asyncio
async def test_correct_business_profile_is_read_only(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h = handler()
    before = state("router")
    before.update(profile="business-v1", checks={"physical_ports":True,"policy":True})
    h.network_mode_state = AsyncMock(return_value=before)
    executor = AsyncMock()
    monkeypatch.setattr(mikrotik_business,"apply",executor)
    assert await h.apply_network_mode("router") == before
    executor.assert_not_awaited()


@pytest.mark.asyncio
async def test_drifted_profile_requires_reapply(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h = handler()
    before = state("router")
    before.update(profile="business-v1", checks={"physical_ports":True,"policy":False})
    h.network_mode_state = AsyncMock(return_value=before)
    executor = AsyncMock(return_value={"mode":"router"})
    monkeypatch.setattr(mikrotik_business,"apply",executor)
    await h.apply_network_mode("router")
    executor.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_readback_never_passes():
    from provisioner.handlers import mikrotik_business
    h = handler()
    h._run_command = AsyncMock(return_value="physical_ports=true")
    result = await mikrotik_business.read_state(h,"router")
    assert result["checks"]["physical_ports"]
    assert not all(result["checks"].values())


def test_switch_profile_has_no_routing_or_dhcp_server():
    from provisioner.handlers.mikrotik_business import profile_text
    text = profile_text("switch")
    assert "ip-forward=no" in text
    assert "dhcp-internal" not in text
    assert "action=masquerade" not in text
    assert "poe-out=forced-on" not in text


def _switch_asset():
    from provisioner.handlers.mikrotik_business import PROFILE_ROOT
    return (PROFILE_ROOT / "business-switch.rsc").read_text()


def test_switch_profile_takes_management_address_by_dhcp():
    text = _switch_asset()
    assert "/ip address add" not in text
    assert "/ip route add" not in text
    assert "192.168.10.2" not in text
    assert ("add interface=vlan10-internal add-default-route=yes "
            "use-peer-dns=no use-peer-ntp=no disabled=no") in text
    # Management firewall still admits only the Internal LAN.
    assert "in-interface=vlan10-internal src-address=192.168.10.0/24" in text


def test_switch_profile_treats_every_port_the_same():
    from provisioner.handlers.mikrotik_business import SWITCH_PORTS
    text = _switch_asset()
    for port in SWITCH_PORTS:
        assert ("add bridge=bridge interface=%s " % port) in text
    ports = [line for line in text.splitlines() if line.startswith("add bridge=bridge interface=")]
    assert len(ports) == 6
    assert all("pvid=10 ingress-filtering=yes frame-types=admit-all" in line for line in ports)
    assert "trusted=yes" not in text
    assert "dhcp-snooping=no" in text
    assert "list=WAN" not in text and "name=WAN" not in text
    every = ",".join(SWITCH_PORTS)
    assert "vlan-ids=10 tagged=bridge untagged=%s" % every in text
    for vlan in (20, 40, 70):
        assert "vlan-ids=%d tagged=%s" % (vlan, every) in text


def test_router_profile_keeps_snooping_and_fixed_port_map():
    from provisioner.handlers.mikrotik_business import check_expressions
    checks = check_expressions("router")
    assert "dhcp-snooping=yes" in checks["bridge"]
    assert "access_ether3" in checks and "access_sfp1" in checks
    assert '"192.168.10.1/24"' in checks["management_address"]


def test_switch_readback_checks_dhcp_management_and_open_ports():
    from provisioner.handlers.mikrotik_business import check_expressions
    checks = check_expressions("switch")
    assert "trusted_uplink" not in checks
    assert checks["trusted_ports"].endswith("= 0")
    assert "dhcp-snooping=no" in checks["bridge"]
    assert "dynamic=yes" in checks["management_address"]
    assert checks["address_count"].endswith("= 0")
    assert checks["static_routes"].endswith("= 0")
    assert 'interface="vlan10-internal" and add-default-route=yes' in checks["management_dhcp_client"]
    assert checks["vlan_20_tagged"].endswith('"ether1;ether2;ether3;ether4;ether5;sfp1"')
    assert not any("192.168.10.2" in expression for expression in checks.values())


@pytest.mark.asyncio
async def test_readback_reports_connected_address():
    from provisioner.handlers import mikrotik_business
    h = handler()
    h.ip = "192.168.10.37"
    h._run_command = AsyncMock(return_value="")
    assert (await mikrotik_business.read_state(h, "switch"))["management_ip"] == "192.168.10.37"


@pytest.mark.asyncio
async def test_device_macs_reads_every_port():
    from provisioner.handlers import mikrotik_business
    h = handler()
    h._run_command = AsyncMock(return_value="AA:BB:CC:00:00:01\r\nAA:BB:CC:00:00:02\r\n")
    assert await mikrotik_business.device_macs(h) == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}


@pytest.mark.asyncio
async def test_find_switch_matches_mac_and_skips_router_and_source(monkeypatch):
    from provisioner.handlers import mikrotik_business
    probed = []

    async def fake_arp(interface, ip, limit):
        probed.append(ip)
        return {"192.168.10.37": "aa:bb:cc:00:00:01",
                "192.168.10.38": "de:ad:be:ef:00:01"}.get(ip)

    monkeypatch.setattr(mikrotik_business, "_arp_mac", fake_arp)
    found = await mikrotik_business.find_switch("test0", {"aa:bb:cc:00:00:01"})
    assert found == ["192.168.10.37"]
    assert "192.168.10.1" not in probed
    assert "192.168.10.254" not in probed
    assert len(probed) == 252


class _Sftp:
    def __init__(self):
        self.removed = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def open(self, *_args):
        return _File()

    async def remove(self, name):
        self.removed.append(name)

    async def exists(self, _name):
        return False


class _File:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def write(self, _text):
        return None


class _Ssh:
    def __init__(self):
        self.sftp = _Sftp()

    def start_sftp_client(self):
        return self.sftp

    async def run(self, *_args, **_kwargs):
        from types import SimpleNamespace
        return SimpleNamespace(exit_status=0, stdout="No syntax errors found")


def _info(serial):
    from types import SimpleNamespace
    return SimpleNamespace(serial_number=serial, model="hEX S", hardware_version="arm",
                           firmware_version="7.23.5")


def _switch_handler(monkeypatch, serials, candidates):
    from provisioner.handlers import mikrotik_business
    h = handler()
    h.ip = "192.168.10.2"
    h._ssh = _Ssh()
    connected = []
    h.get_info = AsyncMock(side_effect=[_info(s) for s in serials])
    h._run_command = AsyncMock(side_effect=lambda command: "AA:BB:CC:00:00:01" if "mac-address" in command else "")
    h.disconnect = AsyncMock()

    async def fake_connect():
        connected.append(h.ip)
        h._ssh = _Ssh()
        return True

    h.connect = fake_connect
    lookups = []

    async def fake_find(interface, macs):
        lookups.append((interface, macs))
        return candidates

    async def no_sleep(_seconds):
        return None

    async def passing_state(handler_, mode):
        return {"mode": mode, "profile": "business-v1", "checks": {"all": True},
                "management_ip": handler_.ip}

    monkeypatch.setattr(mikrotik_business, "ensure_source", AsyncMock())
    monkeypatch.setattr(mikrotik_business, "find_switch", fake_find)
    monkeypatch.setattr(mikrotik_business.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(mikrotik_business, "read_state", passing_state)
    return h, connected, lookups


@pytest.mark.asyncio
async def test_switch_apply_finds_new_lease_by_mac_and_serial(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h, connected, lookups = _switch_handler(monkeypatch, ["SERIAL-A", "SERIAL-A"], ["192.168.10.37"])
    state = await mikrotik_business.apply(h, "switch")
    assert lookups == [("test0", {"aa:bb:cc:00:00:01"})]
    assert connected == ["192.168.10.37"]
    assert state["management_ip"] == "192.168.10.37"
    assert h.ip == "192.168.10.37"


@pytest.mark.asyncio
async def test_switch_apply_refuses_another_unit(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h, connected, _ = _switch_handler(monkeypatch, ["SERIAL-A", "SERIAL-B"], ["192.168.10.37"])
    with pytest.raises(ValueError):
        await mikrotik_business.apply(h, "switch")
    assert connected == ["192.168.10.37"]


@pytest.mark.asyncio
async def test_switch_apply_without_lease_fails_readback(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h, connected, lookups = _switch_handler(monkeypatch, ["SERIAL-A"], [])
    with pytest.raises(RuntimeError):
        await mikrotik_business.apply(h, "switch")
    assert connected == []
    assert len(lookups) == 30


def test_business_profile_rejects_other_firmware():
    before=state()
    before.update(profile="business-v1",firmware="7.24.2",checks={"physical_ports":True})
    with pytest.raises(ValueError):
        handler().validate_network_mode_layout(before)


def test_private_key_store_permissions(tmp_path, monkeypatch):
    import stat
    from provisioner.handlers import mikrotik_business as business
    monkeypatch.setattr(business,"SECRET_ROOT",tmp_path / "secrets")
    path=business._secret_file("TEST-DEVICE")
    business._save_secrets(path,{"test":"private-test-value"})
    assert stat.S_IMODE(path.stat().st_mode)==0o600
    assert stat.S_IMODE(path.parent.stat().st_mode)==0o700
    assert "TEST-DEVICE" not in path.name


@pytest.mark.asyncio
async def test_unknown_advanced_option_never_contacts_device():
    h=handler()
    h._run_command=AsyncMock()
    with pytest.raises(ValueError):
        await h.apply_network_mode_advanced({"unknown":True})
    h._run_command.assert_not_awaited()


def test_replacement_keeps_dynamic_firewall_counters():
    from provisioner.handlers.mikrotik_business import CLEANUP
    assert "/ip firewall filter remove [find where dynamic=no]" in CLEANUP
    assert "/interface bridge vlan remove [find where dynamic=no]" in CLEANUP
    assert "/interface wireguard" not in CLEANUP
    assert "/user" not in CLEANUP


@pytest.mark.parametrize("ip", ["192.168.88.1", "192.168.10.1", "192.168.10.2", "192.168.10.37"])
def test_management_discovery_uses_existing_isolated_source(ip):
    assert MikrotikHandler.discovery_arp_source(ip)=="192.168.88.11"
    assert MikrotikHandler.discovery_arp_source("169.254.1.1") is None
    assert MikrotikHandler.discovery_arp_source("192.168.10.254") is None
    assert MikrotikHandler.discovery_arp_source("not-an-address") is None
