"""Regression tests for Tachyon config apply / verify honesty.

These pin the exact false-positive that shipped: ``apply_config`` read back the
config over curl, and on ANY read-back failure logged a warning and returned
``True`` anyway — reporting "config applied" when it was never confirmed.
``verify_config`` likewise returned ``True`` after only a reconnect + firmware
bank check, never comparing the config that was sent.

Tests marked "RED today" fail against the pre-fix handler and pass once
verification is made fail-closed (Wave 2).
"""

import json
import tarfile

from provisioner.handlers.tachyon import TachyonHandler


def _curl_handler() -> TachyonHandler:
    """A handler wired for the interface-bound curl transport (no network)."""
    h = TachyonHandler(
        ip="169.254.1.1",
        credentials={"username": "root", "password": "admin"},
        interface="eth0",
    )
    h._use_curl = True
    h._api_token = "tok"
    h._connected = True
    return h


def _full_export_config():
    return {
        "version": 3,
        "ethernet": {
            "ports": {
                "eth0": {"enabled": True, "mtu": 1500, "network": {"zone": "wan"}},
                "eth1": {"enabled": False, "mtu": 1500, "network": {"zone": "wan"}},
            }
        },
        "network": {
            "zones": {
                "wan": {
                    "enabled": True,
                    "name": "Management",
                    "ip": {"enabled": True, "ipaddr": "192.168.2.1", "prefix": 24},
                    "dataVlan": {"proto": "802.1q", "vlan": 12},
                }
            }
        },
        "services": {
            "snmp": {"enabled": True, "v2": {"rw": {"enabled": True}}},
            "telnet": {"enabled": False, "port": 23},
        },
        "system": {"hostname": "canoeoninn", "name": "Canoe on Inn"},
        "wireless": {
            "radios": {
                "wlan0": {
                    "enabled": True,
                    "vaps": [
                        {
                            "enabled": True,
                            "mode": "sta",
                            "ssid": "WEST",
                            "network": {"zone": "wan"},
                            "sta_profiles": {
                                "enabled": True,
                                "profiles": [
                                    {"ssid": "NORTH"},
                                    {"ssid": "EAST"},
                                    {"ssid": "SOUTH"},
                                    {"ssid": "WEST"},
                                ],
                            },
                        }
                    ],
                }
            }
        },
    }


def _write_config_tar(tmp_path, config):
    config_path = tmp_path / "config.json"
    control_path = tmp_path / "CONTROL"
    tar_path = tmp_path / "export.tar"
    config_path.write_text(json.dumps(config))
    control_path.write_text("CONTROL\n")
    with tarfile.open(tar_path, "w") as tar:
        tar.add(control_path, arcname="CONTROL")
        tar.add(config_path, arcname="config.json")
    return tar_path


# ---------------------------------------------------------------------------
# apply_config read-back
# ---------------------------------------------------------------------------


async def test_apply_config_false_when_readback_curl_fails(fake_curl, fast_sleep):
    """RED today: a failed read-back GET must fail the apply, not be swallowed.

    The POST succeeds but the read-back GET fails at the curl layer (the exact
    shape of the tachyon incident). The pre-fix code caught the resulting
    RuntimeError and returned True.
    """
    h = _curl_handler()
    config = {"system": {"hostname": "AP-1"}}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            return (0, json.dumps({"reboot_required": False}))
        return (1, "", "curl: (7) Failed to connect")  # read-back GET fails

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is False


async def test_apply_config_false_on_hostname_mismatch(fake_curl, fast_sleep):
    """The device echoes a different hostname than we sent -> not applied."""
    h = _curl_handler()
    config = {"system": {"hostname": "AP-1"}}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            return (0, json.dumps({}))
        return (0, json.dumps({"system": {"hostname": "WRONG"}}))

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is False


async def test_apply_config_true_on_full_match(fake_curl, fast_sleep):
    """Happy path lock-in: read-back confirms hostname AND ssid -> True."""
    h = _curl_handler()
    config = {
        "system": {"hostname": "AP-1"},
        "wireless": {"radios": {"wlan0": {"vaps": [{"ssid": "NET"}]}}},
    }

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            return (0, json.dumps({}))
        return (0, json.dumps(config))  # device echoes exactly what we sent

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is True


async def test_apply_config_adds_missing_radio_isolation_default(fake_curl):
    """Older Tachyon exports omit fields current firmware requires on enabled radios."""
    h = _curl_handler()
    config = {
        "wireless": {
            "radios": {
                "wlan0": {
                    "enabled": True,
                    "vaps": [{"enabled": True, "network": {"zone": "wan"}}],
                },
                "wlan1": {
                    "enabled": True,
                    "vaps": [{"enabled": True, "network": {"zone": "lan"}}],
                },
                "wlan2": {"enabled": False},
            }
        }
    }
    posted = {}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method != "POST":
            raise AssertionError("unexpected method: %s" % method)
        posted.update(json.loads(argv[argv.index("-d") + 1]))
        return (0, json.dumps({}))

    fake_curl.set_handler(route)

    assert await h.apply_config(config) is True

    radios = posted["wireless"]["radios"]
    assert radios["wlan0"]["isolation"] is False
    assert radios["wlan1"]["isolation"] is False
    assert radios["wlan0"]["vaps"][0]["isolate"] is False
    assert radios["wlan1"]["vaps"][0]["isolate"] is False
    assert radios["wlan0"]["vaps"][0]["network"]["mgmt_vlan_enabled"] is False
    assert radios["wlan1"]["vaps"][0]["network"]["mgmt_vlan_enabled"] is False
    assert "isolation" not in radios["wlan2"]


async def test_apply_config_adds_missing_full_export_schema_defaults(fake_curl):
    """Tachyon exports can omit fields the API still requires on POST."""
    h = _curl_handler()
    config = _full_export_config()
    config["services"]["snmp_traps"] = {
        "enabled": False,
        "community": "public",
        "protocol": "2",
    }
    config["services"]["ssh"] = {"enabled": True, "port": 22}
    config["services"]["snmp"]["v3"] = {
        "ro": {"enabled": False, "password": "", "user": ""}
    }
    config["network"]["zones"]["wan"]["dhcp"] = {"broadcast": False, "custom_dns": False}
    posted = {}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            posted.update(json.loads(argv[argv.index("-d") + 1]))
            return (0, json.dumps({}))
        if method == "GET":
            return (0, json.dumps(posted))
        raise AssertionError("unexpected method: %s" % method)

    fake_curl.set_handler(route)

    assert await h.apply_config(config) is True

    assert posted["system"]["description"] == ""
    assert posted["system"]["latitude"] == 0
    assert posted["system"]["longitude"] == 0
    assert posted["services"]["cloud"] == {"enabled": False}
    assert posted["services"]["snmp_traps"]["port"] == 162
    assert posted["services"]["ssh"]["password_login"] is True
    assert posted["services"]["snmp"]["v3"]["ro"]["encryption_mode"] == "aes"
    assert posted["network"]["zones"]["wan"]["lldp_forward"] is False
    assert posted["network"]["zones"]["wan"]["carrier_drop"] == {
        "enabled": False,
        "rssi_threshold": -68,
        "down_time": 3,
        "start_delay": 300,
    }
    assert posted["network"]["zones"]["wan"]["dhcp"]["enabled_options"] == {
        "log_server": True,
        "ntp_server": True,
        "timezone_offset": True,
    }
    assert posted["ethernet"]["ports"]["eth0"]["network"]["mgmt_vlan_enabled"] is True


async def test_apply_config_file_tar_posts_authoritative_export_without_deep_merge(
    tmp_path, fake_curl, fast_sleep
):
    """Full Tachyon exports must not inherit stale live keys like eth2-eth5."""
    h = _curl_handler()
    export_config = _full_export_config()
    tar_path = _write_config_tar(tmp_path, export_config)
    posted = {}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            posted.update(json.loads(argv[argv.index("-d") + 1]))
            return (0, json.dumps({}))
        if method == "GET":
            return (0, json.dumps(posted))
        raise AssertionError("unexpected method: %s" % method)

    fake_curl.set_handler(route)

    assert await h.apply_config_file(str(tar_path)) is True
    assert fake_curl.methods == ["POST", "GET"]
    assert sorted(posted["ethernet"]["ports"].keys()) == ["eth0", "eth1"]
    assert "vlans" not in posted["network"]["zones"]["wan"]


async def test_apply_config_file_partial_json_still_merges_live_config(
    tmp_path, fake_curl, fast_sleep
):
    """Partial templates keep patch semantics for naming/SSID style updates."""
    h = _curl_handler()
    partial_path = tmp_path / "partial.json"
    partial_path.write_text(json.dumps({"system": {"hostname": "AP-1"}}))
    live_config = _full_export_config()
    live_config["ethernet"]["ports"]["eth2"] = {"enabled": True}
    posted = {}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "GET" and not posted:
            return (0, json.dumps(live_config))
        if method == "POST":
            posted.update(json.loads(argv[argv.index("-d") + 1]))
            return (0, json.dumps({}))
        if method == "GET":
            return (0, json.dumps(posted))
        raise AssertionError("unexpected method: %s" % method)

    fake_curl.set_handler(route)

    assert await h.apply_config_file(str(partial_path)) is True
    assert fake_curl.methods == ["GET", "POST", "GET"]
    assert posted["system"]["hostname"] == "AP-1"
    assert "eth2" in posted["ethernet"]["ports"]


# ---------------------------------------------------------------------------
# verify_config
# ---------------------------------------------------------------------------


def _stub_reconnect(monkeypatch, h):
    """Make verify_config's reconnect + bank check succeed without a network."""

    async def ok_connect():
        h._connected = True
        return True

    async def noop_disconnect():
        h._connected = False

    async def banks():
        return {"bank1": "v1", "bank2": "v1", "active": 1}

    monkeypatch.setattr(h, "connect", ok_connect)
    monkeypatch.setattr(h, "disconnect", noop_disconnect)
    monkeypatch.setattr(h, "get_firmware_banks", banks)


async def test_verify_config_false_when_readback_hostname_mismatches(monkeypatch, fast_sleep):
    """RED today: verify_config must compare the config, not just reconnect."""
    h = _curl_handler()
    h._last_applied_config = {"system": {"hostname": "AP-1"}}
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return {"system": {"hostname": "WRONG"}}

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is False


async def test_verify_config_false_when_readback_unavailable(monkeypatch, fast_sleep):
    """RED today: if the config can't be read back, verify cannot claim success."""
    h = _curl_handler()
    h._last_applied_config = {"system": {"hostname": "AP-1"}}
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return {}

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is False


async def test_verify_config_true_on_match(monkeypatch, fast_sleep):
    """Happy path lock-in: read-back hostname matches what was applied."""
    h = _curl_handler()
    h._last_applied_config = {"system": {"hostname": "AP-1"}}
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return {"system": {"hostname": "AP-1"}}

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is True


async def test_verify_config_false_when_readback_has_stale_ethernet_ports(monkeypatch, fast_sleep):
    h = _curl_handler()
    expected = _full_export_config()
    readback_config = json.loads(json.dumps(expected))
    readback_config["ethernet"]["ports"]["eth2"] = {"enabled": True}
    h._last_applied_config = expected
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return readback_config

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is False


async def test_verify_config_false_when_readback_keeps_old_wan_vlans(monkeypatch, fast_sleep):
    h = _curl_handler()
    expected = _full_export_config()
    readback_config = json.loads(json.dumps(expected))
    readback_config["network"]["zones"]["wan"]["vlans"] = [
        {"id": 12, "name": "Management"},
        {"id": 101, "name": "Last mile"},
    ]
    h._last_applied_config = expected
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return readback_config

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is False
