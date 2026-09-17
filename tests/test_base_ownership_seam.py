"""The shared flow passes contract expectations into verify_config."""

from typing import Any, Dict, Optional

from provisioner.handlers.base import BaseHandler, UNVERIFIED


async def test_default_verify_compares_by_structural_path(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()

    async def readback():
        return {"system": {"hostname": "AP-1"}, "vaps": [{"ssid": "ok"}]}

    spy._read_back_config = readback
    result = await BaseHandler.verify_config(
        spy, expected_values={"system.hostname": "AP-1", "vaps[0].ssid": "ok"}
    )
    assert result is True
    assert spy.last_verify_mismatches == []


async def test_default_verify_records_mismatch_names_only(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()

    async def readback():
        return {"system": {"hostname": "WRONG"}}

    spy._read_back_config = readback
    result = await BaseHandler.verify_config(
        spy, expected_values={"system.hostname": "AP-1", "missing.field": "x"}
    )
    assert result is False
    assert spy.last_verify_mismatches == ["system.hostname", "missing.field"]


async def test_provision_passes_applied_config_expectations(spy_handler_factory, fast_sleep):
    seen = {}

    spy = spy_handler_factory()
    original_verify = spy.verify_config

    async def verify(expected_values: Optional[Dict[str, Any]] = None):
        seen["expected"] = expected_values
        return await original_verify(expected_values)

    spy.verify_config = verify
    spy.applied_config_expectations = lambda: {"mgmtVLANVID": "12"}

    await spy.provision(
        config={"mgmtVLANVID": "12"},
        firmware_path="/tmp/fw.bin",
        expected_firmware="new",
        dual_bank=True,
    )

    assert seen["expected"] == {"mgmtVLANVID": "12"}


async def test_default_expectations_are_none_so_legacy_handlers_are_unchanged(spy_handler_factory):
    spy = spy_handler_factory()
    assert spy.applied_config_expectations() is None
    assert BaseHandler.FIELD_OWNERSHIP is None


async def test_provision_applies_pending_secrets_after_config(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()
    spy.credentials["wpa_key"] = "k"
    seen = {}

    async def apply_secrets(secrets):
        seen.update(secrets)
        return True

    spy.apply_secrets = apply_secrets
    result = await spy.provision(
        config={"mgmtVLANVID": "12"},
        firmware_path="/tmp/fw.bin",
        expected_firmware="new",
        dual_bank=True,
    )
    assert result.success, result.error_message
    assert seen == {"wpa_key": "k"}
    plan = [step["key"] for step in spy.provisioning_step_plan(True, True, True, True)]
    assert plan.index("secrets") == plan.index("config_verify") + 1


async def test_provision_fails_when_secrets_cannot_be_applied(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()
    spy.credentials["snmp_community"] = "c"

    async def apply_secrets(secrets):
        return False

    spy.apply_secrets = apply_secrets
    result = await spy.provision(
        config={"mgmtVLANVID": "12"},
        firmware_path="/tmp/fw.bin",
        expected_firmware="new",
        dual_bank=True,
    )
    assert not result.success
    assert "secrets" in result.error_message


def test_no_secrets_means_no_secrets_step(spy_handler_factory):
    spy = spy_handler_factory()
    assert spy.pending_secrets() == {}
    assert "secrets" not in [s["key"] for s in spy.provisioning_step_plan(True, True, True, True)]


async def test_deferred_config_flow_still_applies_secrets(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory(config_after_all_firmware=True)
    spy.credentials["wpa_key"] = "k"
    seen = []

    async def apply_secrets(secrets):
        seen.append(dict(secrets))
        return True

    spy.apply_secrets = apply_secrets
    result = await spy.provision(
        config={"mgmtVLANVID": "12"},
        firmware_path="/tmp/fw.bin",
        expected_firmware="new",
        dual_bank=True,
    )
    assert result.success, result.error_message
    assert seen == [{"wpa_key": "k"}]
    names = spy.call_names
    assert names.index("apply_config") < len(names)


def test_secret_values_survive_credential_replacement(spy_handler_factory):
    spy = spy_handler_factory()
    spy.credentials["snmp_community"] = "c"
    spy._secret_values = dict(spy.pending_secrets())
    spy.credentials = {"username": "admin", "password": "x"}  # connect() may swap candidates
    assert spy.pending_secrets() == {"snmp_community": "c"}


async def test_missing_required_secret_fails_before_config(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()
    spy.required_secrets = lambda: ["wpa_key"]
    result = await spy.provision(
        config={"mgmtVLANVID": "12"},
        firmware_path="/tmp/fw.bin",
        expected_firmware="new",
        dual_bank=True,
    )
    assert not result.success
    assert "wpa_key" in result.error_message
    assert "apply_config" not in spy.call_names
    assert "secrets" in [s["key"] for s in spy.provisioning_step_plan(True, True, True, True)]


async def test_required_secret_present_lets_the_run_continue(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()
    spy.required_secrets = lambda: ["wpa_key"]
    spy.credentials["wpa_key"] = "k"
    seen = []

    async def apply_secrets(secrets):
        seen.append(secrets)
        return True

    spy.apply_secrets = apply_secrets
    result = await spy.provision(
        config={"mgmtVLANVID": "12"},
        firmware_path="/tmp/fw.bin",
        expected_firmware="new",
        dual_bank=True,
    )
    assert result.success, result.error_message
    assert seen == [{"wpa_key": "k"}]


def test_cambium_and_tachyon_require_the_wpa_key():
    from provisioner.handlers.cambium import CambiumHandler
    from provisioner.handlers.tachyon import TachyonHandler

    for cls in (CambiumHandler, TachyonHandler):
        handler = cls(ip="10.0.0.1", credentials={"username": "u", "password": "p"})
        assert handler.required_secrets() == ["wpa_key"]
        assert handler.missing_required_secrets() == ["wpa_key"]
        handler = cls(ip="10.0.0.1", credentials={"username": "u", "password": "p", "wpa_key": "k"})
        assert handler.missing_required_secrets() == []
