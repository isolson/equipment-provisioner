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


def test_business_profile_rejects_other_firmware():
    before=state()
    before.update(profile="business-v1",firmware="7.24.2",checks={"physical_ports":True})
    with pytest.raises(ValueError):
        handler().validate_network_mode_layout(before)


def test_no_persistent_secret_store_symbols():
    """#167: the bench must not carry a per-device secret store any more."""
    from provisioner.handlers import mikrotik_business as business
    assert not hasattr(business, "_save_secrets")
    assert not hasattr(business, "_secret_file")
    assert not hasattr(business, "SECRET_ROOT")


def test_cleanup_bench_secret_store_removes_files(tmp_path, monkeypatch):
    from provisioner.handlers import mikrotik_business as business
    root = tmp_path / "device-secrets" / "mikrotik"
    root.mkdir(parents=True)
    (root / "abc.json").write_text("{}")
    (root / "def.tmp").write_text("{}")
    monkeypatch.setattr(business, "LEGACY_SECRET_ROOT", root)
    assert business.cleanup_bench_secret_store() == 2
    assert not root.exists()
    # Idempotent: nothing left to remove.
    assert business.cleanup_bench_secret_store() == 0


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


# --- #167: transient credentials, no persistent secret store ----------------
from types import SimpleNamespace


class _FakeConn:
    """Minimal asyncssh-style connection for login-verification tests."""
    def __init__(self, ok):
        self._ok = ok
    async def run(self, cmd, check=False):
        return SimpleNamespace(exit_status=0 if self._ok else 1)
    def close(self):
        pass
    async def wait_closed(self):
        pass


def _advanced_handler(monkeypatch, romon_readback=False, wg_public=None):
    from provisioner.handlers import mikrotik_business
    h = handler()
    h.network_mode_state = AsyncMock(return_value={"profile": "business-v1", "checks": {"ok": True}, "mode": "router"})
    monkeypatch.setattr(mikrotik_business, "read_state", AsyncMock(return_value={"checks": {"ok": True}, "mode": "router"}))
    monkeypatch.setattr(mikrotik_business, "advanced_state", AsyncMock(return_value={
        "romon_enabled": romon_readback, "romon_port": "ether3",
        "wireguard_public_key": wg_public, "wireguard_status": "x"}))
    monkeypatch.setattr(mikrotik_business, "cleanup_bench_secret_store", lambda: 0)
    h._ssh = SimpleNamespace(run=AsyncMock())
    return h


@pytest.mark.asyncio
async def test_wireguard_prepare_reads_public_only(monkeypatch):
    from provisioner.handlers import mikrotik_business
    pub = "A" * 43 + "="
    h = _advanced_handler(monkeypatch, wg_public=pub)
    calls = []
    async def run_cmd(cmd, *a, **k):
        calls.append(cmd)
        if "wg-management" in cmd and ":len" in cmd:
            return "1"
        if "public-key" in cmd:
            return pub
        return ""
    h._run_command = run_cmd
    await mikrotik_business.apply_advanced(h, prepare_wireguard=True)
    assert any("public-key" in c for c in calls)
    assert not any("private-key" in c for c in calls)


@pytest.mark.asyncio
async def test_wireguard_rotate_regenerates_key(monkeypatch):
    from provisioner.handlers import mikrotik_business
    pub = "B" * 43 + "="
    h = _advanced_handler(monkeypatch, wg_public=pub)
    calls = []
    async def run_cmd(cmd, *a, **k):
        calls.append(cmd)
        if "wg-management" in cmd and ":len" in cmd:
            return "1"
        if "public-key" in cmd:
            return pub
        return ""
    h._run_command = run_cmd
    await mikrotik_business.apply_advanced(h, prepare_wireguard=True, rotate_wireguard=True)
    assert any("wireguard remove" in c for c in calls)
    assert not any("private-key" in c for c in calls)


@pytest.mark.asyncio
async def test_romon_enable_requires_transient_secret(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h = _advanced_handler(monkeypatch)
    h._run_command = AsyncMock(return_value="")
    with pytest.raises(ValueError):
        await mikrotik_business.apply_advanced(h, romon_enabled=True)
    # Nothing was written to the device and no secret command was sent.
    h._run_command.assert_not_awaited()
    h._ssh.run.assert_not_awaited()


@pytest.mark.asyncio
async def test_romon_enable_with_transient_secret_not_stored(monkeypatch):
    from provisioner.handlers import mikrotik_business
    h = _advanced_handler(monkeypatch, romon_readback=True)
    h._run_command = AsyncMock(return_value="")
    res = await mikrotik_business.apply_advanced(h, romon_enabled=True, romon_secret="k" * 32)
    assert res["romon_enabled"] is True
    # The transient secret is applied over SSH (unlogged), never persisted.
    assert h._ssh.run.await_count == 1
    assert "secrets=" in h._ssh.run.await_args_list[0].args[0]


@pytest.mark.asyncio
async def test_accept_credentials_replaces_and_verifies(monkeypatch):
    from provisioner.handlers import mikrotik_business
    from provisioner.handlers.mikrotik_render_credentials import ReleaseResult
    h = handler()
    monkeypatch.setattr(mikrotik_business, "cleanup_bench_secret_store", lambda: 0)
    h._run_command = AsyncMock(return_value="0")  # localadmin absent
    h._ssh = SimpleNamespace(run=AsyncMock())
    async def open_conn(username, password):
        return _FakeConn(ok=(username == "localadmin"))
    h._open_ssh_connection = open_conn
    res = await mikrotik_business.accept_credentials(
        h, ReleaseResult(password="new-localadmin-pw", seed_id="s1", secret_version="3"),
        previous_credentials={"username": "admin", "password": "label-pw"})
    assert res["local_login_verified"] and res["previous_login_disabled"]
    assert h.credentials["username"] == "localadmin"
    assert any("disabled=yes" in c.args[0] for c in h._ssh.run.await_args_list)


@pytest.mark.asyncio
async def test_accept_credentials_failsafe_keeps_old_login(monkeypatch):
    from provisioner.handlers import mikrotik_business
    from provisioner.handlers.mikrotik_render_credentials import ReleaseResult
    h = handler()
    monkeypatch.setattr(mikrotik_business, "cleanup_bench_secret_store", lambda: 0)
    h._run_command = AsyncMock(return_value="1")  # localadmin exists
    h._ssh = SimpleNamespace(run=AsyncMock())
    async def open_conn(username, password):
        return _FakeConn(ok=False)  # even localadmin cannot log in
    h._open_ssh_connection = open_conn
    with pytest.raises(RuntimeError):
        await mikrotik_business.accept_credentials(
            h, ReleaseResult(password="pw", seed_id="s", secret_version="1"),
            previous_credentials={"username": "admin", "password": "label-pw"})
    # Old login was never disabled; the device keeps a working login.
    assert not any("disabled=yes" in c.args[0] for c in h._ssh.run.await_args_list)
    assert h.credentials.get("username") != "localadmin"


@pytest.mark.asyncio
async def test_accept_business_credentials_release_apply_complete(monkeypatch):
    from provisioner.handlers import mikrotik_business
    from provisioner.handlers.mikrotik_render_credentials import ReleaseResult
    h = handler()
    h.get_info = AsyncMock(return_value=SimpleNamespace(serial_number="SER123", model="hEX S"))
    h.network_mode_state = AsyncMock(return_value={"profile": "business-v1", "checks": {"ok": True}})
    monkeypatch.setattr(mikrotik_business, "accept_credentials",
                        AsyncMock(return_value={"local_login_verified": True, "previous_login_disabled": True}))
    client = SimpleNamespace(
        release=AsyncMock(return_value=ReleaseResult(password="pw", seed_id="sid", secret_version="1")),
        complete=AsyncMock())
    res = await h.accept_business_credentials(client, job_id="J", bench_upstream_sha="SHA", render_sha256="R")
    assert res["credential_accepted"] and res["seed_id"] == "sid"
    client.release.assert_awaited_once()
    _, kwargs = client.complete.await_args
    assert kwargs["serial"] == "SER123"
    assert kwargs["readback_passed"] and kwargs["local_login_passed"]
