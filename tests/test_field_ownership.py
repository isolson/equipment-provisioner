"""Contract tests for the vendor-neutral field ownership module."""

import re

import pytest

from provisioner.field_ownership import (
    Owner,
    OwnershipContract,
    Violation,
    classify,
    expected_values,
    flatten,
    format_path,
    get_path,
    parse_path,
    template_violations,
    unchanged_expectations,
)


def _contract(root=""):
    return OwnershipContract.from_dotted(
        {
            "mgmtVLANVID": Owner.FLEET_POLICY,
            "radioMode": Owner.ROLE,
            "gpsPriority": Owner.DEVICE_DEFAULT,
            "ssid": Owner.MODE_ACTION,
            "users[0].name": Owner.MODE_ACTION,
        },
        role_fields={"family-a": {"SM": ("radioMode",)}},
        root=root,
    )


def test_parse_and_format_round_trip():
    path = parse_path("wireless.radios.wlan0.vaps[0].ssid")
    assert path == ("wireless", "radios", "wlan0", "vaps", 0, "ssid")
    assert format_path(path) == "wireless.radios.wlan0.vaps[0].ssid"


@pytest.mark.parametrize("bad", ["", "a..b", "a[x]", "a]"])
def test_parse_path_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_path(bad)


def test_flatten_skips_metadata_and_indexes_lists():
    leaves = dict(flatten({"_comment": "x", "a": {"b": [1, {"c": 2}]}}))
    assert leaves == {("a", "b", 0): 1, ("a", "b", 1, "c"): 2}


def test_get_path_reports_missing():
    assert get_path({"a": [{"b": 1}]}, ("a", 0, "b")) == (True, 1)
    assert get_path({"a": [{"b": 1}]}, ("a", 1, "b")) == (False, None)
    assert get_path({"a": 1}, ("a", "b")) == (False, None)


def test_classify_uses_table_then_secret_shape_then_device_default():
    contract = _contract()
    assert classify(contract, ("mgmtVLANVID",)) is Owner.FLEET_POLICY
    assert classify(contract, ("wpaPassphrase",)) is Owner.SECRET
    assert classify(contract, ("users", 0, "password")) is Owner.SECRET
    assert classify(contract, ("somethingElse",)) is Owner.DEVICE_DEFAULT


def test_sm_baseline_allows_only_fleet_policy_and_role():
    contract = _contract()
    template = {"mgmtVLANVID": "12", "radioMode": "2"}
    assert template_violations(contract, template, "SM", "family-a") == []


def test_sm_baseline_rejects_secret_device_default_mode_action_and_unclassified():
    contract = _contract()
    template = {
        "mgmtVLANVID": "12",
        "radioMode": "2",
        "adminPassword": "x",
        "gpsPriority": "1",
        "ssid": "site",
        "mystery": "0",
    }
    found = {(v.path, v.reason) for v in template_violations(contract, template, "SM", "family-a")}
    assert found == {
        ("adminPassword", "secret"),
        ("gpsPriority", "device_default"),
        ("ssid", "mode_action"),
        ("mystery", "unclassified"),
    }


def test_non_strict_allows_unclassified_but_not_explicit_device_default():
    contract = _contract()
    template = {"radioMode": "2", "gpsPriority": "1", "mystery": "0"}
    reasons = {v.reason for v in template_violations(contract, template, "SM", "family-a", strict=False)}
    assert reasons == {"device_default"}


def test_missing_required_role_field_is_a_violation():
    contract = _contract()
    found = template_violations(contract, {"mgmtVLANVID": "12"}, "SM", "family-a")
    assert [(v.path, v.reason) for v in found] == [("radioMode", "missing_role_field")]
    # An unknown family declares no role fields.
    assert template_violations(contract, {"mgmtVLANVID": "12"}, "SM", "family-b") == []


def test_mode_templates_may_contain_mode_action_fields():
    contract = _contract()
    template = {"radioMode": "1", "ssid": "tw05-north", "users": [{"name": "ap"}]}
    assert template_violations(contract, template, "AP") == []
    assert template_violations(contract, template, "ptp") == []


def test_root_container_is_honored_and_optional():
    contract = _contract(root="device_props")
    wrapped = {"template_props": {"version": "5.11.1"}, "device_props": {"radioMode": "2"}}
    assert template_violations(contract, wrapped, "SM", "family-a") == []
    assert expected_values(contract, wrapped) == {"radioMode": "2"}
    # Already unwrapped documents work too.
    assert expected_values(contract, {"radioMode": "2"}) == {"radioMode": "2"}


def test_expected_values_never_include_secrets_or_device_defaults():
    contract = _contract()
    applied = {
        "mgmtVLANVID": "12",
        "radioMode": "2",
        "gpsPriority": "1",
        "ssid": "site",
        "adminPassword": "x",
        "mystery": "0",
    }
    assert expected_values(contract, applied) == {"mgmtVLANVID": "12", "radioMode": "2"}
    assert expected_values(contract, applied, include_mode_action=True) == {
        "mgmtVLANVID": "12",
        "radioMode": "2",
        "ssid": "site",
    }


def test_unchanged_expectations_selects_device_defaults_only():
    contract = _contract()
    fixture = {"gpsPriority": "1", "mystery": "0", "mgmtVLANVID": "12", "adminPassword": "x"}
    assert unchanged_expectations(contract, fixture) == {"gpsPriority": "1", "mystery": "0"}


def test_container_entry_covers_nested_fields():
    contract = OwnershipContract.from_dotted({"preferredAPs": Owner.MODE_ACTION, "accounts": Owner.SECRET})
    assert classify(contract, ("preferredAPs", 0, "ssid")) is Owner.MODE_ACTION
    assert classify(contract, ("accounts", 1, "name")) is Owner.SECRET
    template = {"preferredAPs": [{"ssid": "x"}]}
    assert template_violations(contract, template, "PTP") == []
    assert [v.reason for v in template_violations(contract, template, "SM")] == ["mode_action"]


def test_custom_secret_pattern():
    contract = OwnershipContract.from_dotted({}, secret_re=re.compile(r"hidden", re.I))
    assert classify(contract, ("HiddenThing",)) is Owner.SECRET
    assert classify(contract, ("password",)) is Owner.DEVICE_DEFAULT


def test_module_has_no_vendor_names():
    import provisioner.field_ownership as module

    source = open(module.__file__).read().lower()
    for vendor in ("cambium", "tachyon", "tarana", "mikrotik", "ubiquiti", "epmp", "tna-"):
        assert vendor not in source


def test_wildcard_index_matches_any_concrete_index():
    contract = OwnershipContract.from_dotted({
        "vaps[0].profiles": Owner.FLEET_POLICY,
        "vaps[0].profiles[].security.passphrase": Owner.SECRET,
        "vaps[].bssid": Owner.DEVICE_DEFAULT,
    })
    assert classify(contract, ("vaps", 0, "profiles", 2, "ssid")) is Owner.FLEET_POLICY
    assert classify(contract, ("vaps", 0, "profiles", 2, "security", "passphrase")) is Owner.SECRET
    assert classify(contract, ("vaps", 0, "profiles", 0, "security", "mode")) is Owner.FLEET_POLICY
    assert classify(contract, ("vaps", 3, "bssid")) is Owner.DEVICE_DEFAULT
    assert format_path(parse_path("a[].b")) == "a[].b"


def test_required_fields_are_a_coherent_set_of_any_owner():
    from provisioner.field_ownership import reduce_to_baseline

    contract = OwnershipContract.from_dotted(
        {"zone.mgmt": Owner.FLEET_POLICY, "ports": Owner.FLEET_POLICY, "vaps[0].mode": Owner.ROLE, "vaps[0].profiles": Owner.FLEET_POLICY,
         "vaps[0].profiles[].psk": Owner.SECRET, "vaps[0].bssid": Owner.DEVICE_DEFAULT},
        role_fields={"fam": {"SM": ("vaps[0].mode",)}},
        required_fields={"fam": {"SM": ("zone.mgmt.enabled", "ports.eth0.flag", "vaps[0].profiles")}},
    )
    full = {"zone": {"mgmt": {"enabled": True}}, "ports": {"eth0": {"flag": True}},
            "vaps": [{"mode": "sta", "bssid": "x", "profiles": [{"ssid": "a", "psk": "SECRET"}]}]}
    assert template_violations(contract, {"zone": {"mgmt": {"enabled": True}}, "vaps": [{"mode": "sta"}]}, "SM", "fam") == [
        Violation("ports.eth0.flag", "missing_required_field"),
        Violation("vaps[0].profiles", "missing_required_field"),
    ]
    reduced = reduce_to_baseline(contract, full, "SM")
    assert reduced == {"zone": {"mgmt": {"enabled": True}}, "ports": {"eth0": {"flag": True}},
                       "vaps": [{"mode": "sta", "profiles": [{"ssid": "a"}]}]}
    assert template_violations(contract, reduced, "SM", "fam") == []


def test_reduce_keeps_root_wrapper():
    from provisioner.field_ownership import reduce_to_baseline

    contract = OwnershipContract.from_dotted({"a": Owner.FLEET_POLICY, "k": Owner.SECRET}, root="device_props")
    doc = {"template_props": {"v": 1}, "device_props": {"a": "1", "k": "s", "z": "d"}}
    assert reduce_to_baseline(contract, doc, "SM") == {"device_props": {"a": "1"}}
