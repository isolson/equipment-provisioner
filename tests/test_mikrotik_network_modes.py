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
async def test_wrong_readback_does_not_report_success():
    h = handler()
    h.network_mode_state = AsyncMock(side_effect=[state(), state()])
    h._run_command = AsyncMock(return_value="")
    with pytest.raises(RuntimeError, match="readback"):
        await h.apply_network_mode("switch")


@pytest.mark.asyncio
async def test_device_command_error_stops_sequence():
    h = handler()
    h.network_mode_state = AsyncMock(return_value=state())
    h._run_command = AsyncMock(return_value="failure: blocked by device-mode")
    with pytest.raises(RuntimeError, match="rejected"):
        await h.apply_network_mode("switch")
    assert h._run_command.await_count == 1


@pytest.mark.asyncio
async def test_both_directions_verify_and_preserve_management():
    h = handler()
    h.network_mode_state = AsyncMock(side_effect=[state(), state("switch"), state("switch"), state()])
    h._run_command = AsyncMock(return_value="")
    assert (await h.apply_network_mode("switch"))["mode"] == "switch"
    assert (await h.apply_network_mode("router"))["mode"] == "router"
    commands = [c.args[0] for c in h._run_command.await_args_list]
    assert not any("/ip address" in c or "/user" in c or "/import" in c or "reset-configuration" in c for c in commands)


@pytest.mark.asyncio
async def test_mixed_flags_in_recognized_layout_can_be_reconciled():
    h = handler()
    before = state()
    before.update(mode="custom", nat_enabled=0)
    h.network_mode_state = AsyncMock(side_effect=[before, state()])
    h._run_command = AsyncMock(return_value="")
    assert (await h.apply_network_mode("router"))["mode"] == "router"


@pytest.mark.asyncio
async def test_already_correct_mode_is_read_only():
    h = handler()
    h.network_mode_state = AsyncMock(return_value=state("switch"))
    h._run_command = AsyncMock()
    assert (await h.apply_network_mode("switch"))["mode"] == "switch"
    h._run_command.assert_not_awaited()
