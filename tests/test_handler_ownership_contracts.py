"""Every vendor with a contract classifies its fields consistently."""

from provisioner.field_ownership import Owner, classify, parse_path, template_violations
from provisioner.handlers.base import BaseHandler
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.handlers.ubiquiti import UbiquitiHandler
from provisioner.vendor_registry import all_specs


def _classify(handler_cls, dotted):
    return classify(handler_cls.FIELD_OWNERSHIP, parse_path(dotted))


def test_tachyon_role_secret_and_identity_classification():
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].mode") is Owner.ROLE
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].ssid") is Owner.MODE_ACTION
    # The SM profile list is fleet policy; only the shared passphrase is secret.
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].sta_profiles.profiles[2].ssid") is Owner.FLEET_POLICY
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].sta_profiles.profiles[2].security.mode") is Owner.FLEET_POLICY
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].sta_profiles.profiles[2].security.wpapsk.passphrase") is Owner.SECRET
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].sta_profiles.profiles[2].trackingId") is Owner.DEVICE_DEFAULT
    assert _classify(TachyonHandler, "network.zones.wan.management.ip.ipaddr") is Owner.DEVICE_DEFAULT
    assert _classify(TachyonHandler, "network.zones.wan.management.vlan") is Owner.FLEET_POLICY
    assert _classify(TachyonHandler, "system.users[0].password") is Owner.SECRET
    assert _classify(TachyonHandler, "system.users[1].name") is Owner.SECRET
    assert _classify(TachyonHandler, "services.snmp.v2.ro") is Owner.SECRET
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].security.psk") is Owner.SECRET
    assert _classify(TachyonHandler, "services.remote_syslog.server") is Owner.FLEET_POLICY
    assert _classify(TachyonHandler, "wireless.radios.wlan0.vaps[0].bssid") is Owner.DEVICE_DEFAULT
    assert _classify(TachyonHandler, "something.new") is Owner.DEVICE_DEFAULT


def test_tachyon_sensitive_path_uses_the_contract():
    handler = TachyonHandler(ip="10.0.0.1", credentials={"username": "root", "password": "x"})
    assert handler._is_sensitive_path("system.users[0].password")
    assert handler._is_sensitive_path("services.snmp.v2.ro")
    assert handler._is_sensitive_path("services.snmp.v3.ro.password")
    assert not handler._is_sensitive_path("services.remote_syslog.server")


def test_tachyon_sm_baseline_template_shape_is_allowed_except_secrets():
    template = {
        "wireless": {"radios": {"wlan0": {"vaps": [{"mode": "sta", "bssid": "00:11"}]}}},
        "services": {"snmp": {"enabled": True, "v2": {"ro": "public"}}},
        "system": {"hostname": "unit"},
    }
    # TNA-303X has no required coherent set yet, so only owner classes apply.
    found = {(v.path, v.reason) for v in template_violations(
        TachyonHandler.FIELD_OWNERSHIP, template, "SM", "TNA-303X"
    )}
    assert found == {
        ("wireless.radios.wlan0.vaps[0].bssid", "device_default"),
        ("services.snmp.v2.ro", "secret"),
        ("system.hostname", "mode_action"),
    }


def test_ubiquiti_contract():
    assert _classify(UbiquitiHandler, "network.interfaces.data.mgmtVLAN") is Owner.FLEET_POLICY
    assert _classify(UbiquitiHandler, "system.hostname") is Owner.MODE_ACTION
    assert _classify(UbiquitiHandler, "wireless.interfaces[0].ssid") is Owner.MODE_ACTION
    assert _classify(UbiquitiHandler, "wireless.interfaces[0].security.key") is Owner.SECRET
    assert _classify(UbiquitiHandler, "services.snmpAgent.community") is Owner.SECRET


def test_every_provisionable_handler_declares_a_contract_or_none():
    for spec in all_specs():
        if spec.handler_cls is None:
            continue
        contract = spec.handler_cls.FIELD_OWNERSHIP
        assert contract is None or contract.fields is not None
        if contract is not None:
            # A role field must never also be classified as anything else.
            for family_roles in contract.role_fields.values():
                for paths in family_roles.values():
                    for path in paths:
                        assert classify(contract, path) is Owner.ROLE, path


def test_base_module_has_no_vendor_strings():
    import provisioner.handlers.base as module

    source = open(module.__file__).read().lower()
    for vendor in ("cambium", "tachyon", "tarana", "mikrotik", "ubiquiti"):
        assert vendor not in source, vendor
    assert BaseHandler.FIELD_OWNERSHIP is None


def test_tachyon_303l_sm_baseline_requires_the_management_vlan_set_and_profiles():
    template = {
        "network": {"zones": {"wan": {"management": {"enabled": True, "vlan": 12, "proto": "802.1q"}}}},
        "ethernet": {"ports": {"eth0": {"network": {"mgmt_vlan_enabled": True}}}},
        "wireless": {"radios": {"wlan0": {"vaps": [{"mode": "sta", "network": {"mgmt_vlan_enabled": True},
                                                     "sta_profiles": {"profiles": [{"ssid": "x", "priority": 1}]}}]}}},
    }
    assert template_violations(TachyonHandler.FIELD_OWNERSHIP, template, "SM", "TNA-303L-65") == []
    del template["ethernet"]["ports"]["eth0"]["network"]["mgmt_vlan_enabled"]
    del template["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"]
    reasons = {(v.path, v.reason) for v in template_violations(TachyonHandler.FIELD_OWNERSHIP, template, "SM", "TNA-303L-65")}
    assert reasons == {
        ("ethernet.ports.eth0.network.mgmt_vlan_enabled", "missing_required_field"),
        ("wireless.radios.wlan0.vaps[0].sta_profiles.profiles", "missing_required_field"),
    }
    # A profile passphrase in a baseline is refused.
    template["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"] = {"profiles": [{"ssid": "x", "security": {"wpapsk": {"passphrase": "s"}}}]}
    template["ethernet"]["ports"]["eth0"]["network"]["mgmt_vlan_enabled"] = True
    assert ("wireless.radios.wlan0.vaps[0].sta_profiles.profiles[0].security.wpapsk.passphrase", "secret") in {
        (v.path, v.reason) for v in template_violations(TachyonHandler.FIELD_OWNERSHIP, template, "SM", "TNA-303L-65")
    }


async def test_tachyon_apply_secrets_sets_every_profile_passphrase(monkeypatch):
    handler = TachyonHandler(ip="10.0.0.1", credentials={"username": "root", "password": "x"})
    live = {"wireless": {"radios": {"wlan0": {"vaps": [{"mode": "sta", "sta_profiles": {"profiles": [{"ssid": "a"}, {"ssid": "b", "security": {"mode": "wpapsk", "wpapsk": {"passphrase": "old"}}}]}}]}}}}
    applied = {}

    async def get_live():
        return live

    async def apply(config):
        applied.update(config)
        return True

    monkeypatch.setattr(handler, "_get_config_curl", get_live)
    monkeypatch.setattr(handler, "apply_config", apply)
    handler._last_applied_config = {"keep": "me"}
    assert await handler.apply_secrets({"wpa_key": "SHARED"}) is True
    profiles = applied["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"]["profiles"]
    assert [p["security"]["wpapsk"]["passphrase"] for p in profiles] == ["SHARED", "SHARED"]
    assert profiles[0]["security"]["mode"] == "wpapsk"
    assert handler._last_applied_config == {"keep": "me"}
    assert live["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"]["profiles"][0].get("security") is None
