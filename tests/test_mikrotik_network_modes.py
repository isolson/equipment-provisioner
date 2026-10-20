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
    assert "192.168.10.2/24" in text
    assert "trusted=yes" in text
    assert "poe-out=forced-on" not in text


def test_sfp_wan_router_moves_only_the_wan_port():
    from provisioner.handlers.mikrotik_business import profile_text
    router, sfp = profile_text("router").splitlines(), profile_text("router-sfp").splitlines()
    changed = [line for line in sfp if line not in router]
    assert changed == [
        'add bridge=bridge interface=ether1 pvid=10 ingress-filtering=yes frame-types=admit-only-untagged-and-priority-tagged comment="Internal access"',
        'add bridge=bridge vlan-ids=10 tagged=bridge untagged=ether1,ether2,ether3,ether4,ether5',
        'add interface=sfp1        list=WAN',
        'add interface=sfp1 disabled=no comment="WAN"',
        '/interface ethernet poe set [find where name="ether5"] poe-out=auto-on',
        '/system note set note="treehouse-business-v1:router-sfp"',
    ]
    assert not any("interface=sfp1 " in line and "bridge" in line for line in sfp)


def test_sfp_wan_router_readback_checks_the_sfp_wan():
    from provisioner.handlers.mikrotik_business import check_expressions
    checks = check_expressions("router-sfp")
    assert 'interface="sfp1"' in checks["wan_bridge"] and checks["wan_bridge"].endswith("= 0")
    assert 'interface="sfp1"' in checks["dhcp_clients"] and checks["dhcp_clients"].endswith("= 1")
    assert "access_ether1" in checks and "access_sfp1" not in checks
    assert "auto-on" in checks["poe_ether5"]
    assert checks["profile_marker"].endswith('"treehouse-business-v1:router-sfp"')
    # The existing router readback is unchanged by the variant.
    assert "poe_ether5" not in check_expressions("router")
    assert "wan_list" not in check_expressions("router")


def test_sfp_wan_router_is_not_offered_without_evidence():
    assert "router-sfp" not in MikrotikHandler.network_mode_labels_for_model("hEX S")


@pytest.mark.parametrize("mode", ["router", "router-sfp"])
def test_routers_allow_interim_wan_ssh_from_server_vlan_only(mode):
    from provisioner.handlers.mikrotik_business import profile_text, check_expressions
    text = profile_text(mode)
    rule = 'add chain=input action=accept protocol=tcp dst-port=22 in-interface-list=WAN src-address=100.126.15.0/24 comment="SSH from server VLAN 15 via WAN"'
    assert text.index(rule) < text.index('comment="drop everything else (WAN + untrusted VLANs)"')
    assert "set ssh     disabled=no address=192.168.10.0/24,100.126.15.0/24" in text
    # Only SSH is opened; Winbox and HTTPS stay Internal-only.
    assert "set winbox  disabled=no address=192.168.10.0/24\n" in text
    assert "set www-ssl disabled=no certificate=webfig-local address=192.168.10.0/24\n" in text
    checks = check_expressions(mode)
    assert "wan_ssh" in checks and "wan_ssh_before_drop" in checks
    assert r"100\\.126\\.15\\.0/24" in checks["service_ssh"]


def test_switch_has_no_wan_ssh_exception():
    from provisioner.handlers.mikrotik_business import profile_text, check_expressions
    assert "100.126.15.0/24" not in profile_text("switch").split("/ip service", 1)[1].split("/ip neighbor", 1)[0]
    assert "wan_ssh" not in check_expressions("switch")


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


@pytest.mark.parametrize("ip", ["192.168.88.1", "192.168.10.1", "192.168.10.2"])
def test_management_discovery_uses_existing_isolated_source(ip):
    assert MikrotikHandler.discovery_arp_source(ip)=="192.168.88.11"
    assert MikrotikHandler.discovery_arp_source("169.254.1.1") is None
