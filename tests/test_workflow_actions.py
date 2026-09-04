"""Contextual operator-action contract tests."""

from types import SimpleNamespace

from provisioner.handler_manager import HandlerManager
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.workflow_actions import workflow_for_port


def _state(**overrides):
    values = {
        "device_type": "tachyon",
        "device_model": "TNA-303X",
        "firmware_version": "1.15.1-rev-8541",
        "device_detected": True,
        "provisioning": False,
        "waiting_for_boot": False,
        "last_result": None,
        "needs_credentials": False,
        "device_mode": None,
        "mode_selection_required": False,
        "checklist": {"config_upload": True, "config_verify": True},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _action_ids(workflow, key="available_actions"):
    return [action["id"] for action in workflow[key]]


def _qualify(tmp_path, monkeypatch, vendor, model, firmware, modes=("ptp",)):
    """Record both directions of each mode in a temporary evidence root."""
    import textwrap
    from provisioner import qualification

    rows = []
    for mode in modes:
        rows.append("  - {from: sm, to: %s, result: success}\n" % mode)
        rows.append("  - {from: %s, to: sm, result: success}\n" % mode)
    directory = tmp_path / vendor / model.replace(" ", "_") / firmware
    directory.mkdir(parents=True, exist_ok=True)
    directory.joinpath("manifest.yaml").write_text(textwrap.dedent("""\
        vendor: %s
        model: %s
        firmware: %s
        config_role: SM
        artifact_purpose: hardware-validation
        reusable_template: false
        canonical_template_status: tracked-family-baseline
        transitions:
        """) % (vendor, model, firmware) + "".join(rows))
    monkeypatch.setenv("PROVISIONER_QUALIFICATION_ROOT", str(tmp_path))
    qualification.clear_cache()


def _qualify_tachyon_modes(monkeypatch, modes=("ap", "ptp"), tmp_path=None):
    monkeypatch.setattr(
        TachyonHandler,
        "qualified_post_provision_modes",
        modes,
    )
    if tmp_path is not None:
        _qualify(tmp_path, monkeypatch, "tachyon", "TNA-303X", "1.15.1-rev-8541", modes)


def test_handler_capabilities_require_explicit_qualification():
    assert HandlerManager.operator_capabilities_for("tachyon")[
        "post_provision_modes"
    ] == []
    assert HandlerManager.operator_capabilities_for("tachyon")[
        "required_baseline_mode"
    ] == "sm"
    assert HandlerManager.operator_capabilities_for("cambium")[
        "post_provision_modes"
    ] == []
    assert HandlerManager.operator_capabilities_for("cambium")[
        "required_baseline_mode"
    ] == "sm"
    assert HandlerManager.operator_capabilities_for("tarana")[
        "post_provision_modes"
    ] == []
    assert HandlerManager.operator_capabilities_for(
        "cambium", "ePMP 4616"
    )["ptp_settings_required"] is True
    assert HandlerManager.operator_capabilities_for(
        "tachyon", "TNA-301"
    )["ptp_settings_required"] is True
    assert HandlerManager.operator_capabilities_for("not-a-vendor") == {
        "post_provision_modes": [],
        "advertised_modes": [],
        "unqualified": {},
        "baseline_qualified": False,
        "transitions": {},
        "required_baseline_mode": "",
        "ptp_settings_required": False,
        "manual_netinstall": False,
        "manual_netinstall_label": "",
    }


def test_radio_success_requires_verified_handler_owned_baseline(monkeypatch):
    _qualify_tachyon_modes(monkeypatch)

    missing = workflow_for_port(
        _state(
            last_result="success",
            checklist={"config_upload": "skipped", "config_verify": None},
        ),
        mode_config_enabled=True,
    )
    unverified = workflow_for_port(
        _state(
            last_result="success",
            checklist={"config_upload": True, "config_verify": "unverified"},
        ),
        mode_config_enabled=True,
    )

    assert missing["state"] == "config_required"
    assert missing["required_action"] == "apply_baseline_config"
    assert missing["baseline_mode"] == "sm"
    assert _action_ids(missing) == []
    assert unverified["state"] == "config_unverified"
    assert unverified["required_action"] == "verify_baseline_config"
    assert _action_ids(unverified) == []


def test_success_actions_respect_feature_flag_and_qualification(tmp_path, monkeypatch):
    _qualify_tachyon_modes(monkeypatch, tmp_path=tmp_path)
    disabled = workflow_for_port(
        _state(last_result="success"), mode_config_enabled=False
    )
    enabled = workflow_for_port(
        _state(last_result="success"), mode_config_enabled=True
    )
    unsupported = workflow_for_port(
        _state(device_type="tarana", last_result="success"),
        mode_config_enabled=True,
    )

    assert disabled["state"] == "ready"
    assert _action_ids(disabled) == []
    assert _action_ids(enabled) == ["configure_ap", "configure_ptp"]
    assert _action_ids(unsupported) == []


def test_cambium_ptp_is_offered_only_with_bench_evidence(tmp_path, monkeypatch):
    def workflow(model):
        return workflow_for_port(
            _state(
                device_type="cambium",
                device_model=model,
                firmware_version="5.11.1",
                last_result="success",
            ),
            mode_config_enabled=True,
        )

    # Family membership alone advertises PTP; nothing is offered without evidence.
    assert _action_ids(workflow("ePMP 4616")) == []
    assert workflow("ePMP 4616")["unqualified"]["ptp"].startswith("PTP not qualified for ePMP 4616 on 5.11.1")

    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 4616", "5.11.1")
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 3000", "5.11.1")
    assert _action_ids(workflow("ePMP 4616")) == ["configure_ptp"]
    assert _action_ids(workflow("ePMP 3000")) == ["configure_ptp"]
    # Same family, no evidence for this model: still not offered.
    assert _action_ids(workflow("ePMP 4625")) == []
    # A model outside every certified family is never advertised.
    assert _action_ids(workflow("ePMP 2000")) == []
    assert "ptp" not in workflow("ePMP 2000")["unqualified"]


def test_configured_4616_offers_only_sm_restore():
    workflow = workflow_for_port(
        _state(
            device_type="cambium",
            device_model="ePMP 4616",
            last_result="success",
            device_mode="ptp-a",
        ),
        mode_config_enabled=True,
    )

    assert workflow["state"] == "ready"
    assert _action_ids(workflow) == ["configure_sm"]


def test_configured_mode_without_verified_baseline_has_no_restore_action():
    workflow = workflow_for_port(
        _state(
            device_type="cambium",
            device_model="ePMP 4616",
            last_result="success",
            device_mode="ptp-a",
            checklist={"config_upload": True, "config_verify": "unverified"},
        ),
        mode_config_enabled=True,
    )

    assert workflow["state"] == "ready"
    assert _action_ids(workflow) == []


def test_tachyon_ptp_is_offered_only_with_bench_evidence(tmp_path, monkeypatch):
    def workflow(model):
        return workflow_for_port(
            _state(device_type="tachyon", device_model=model, last_result="success"),
            mode_config_enabled=True,
        )

    for model in ("TNA-301", "TNA-303X", "TNA-303L-65"):
        assert _action_ids(workflow(model)) == [], model
        assert "ptp" in workflow(model)["unqualified"], model

    for model in ("TNA-301", "TNA-303X", "TNA-303L-65"):
        _qualify(tmp_path, monkeypatch, "tachyon", model, "1.15.1-rev-8541")
    for model in ("TNA-301", "TNA-303X", "TNA-303L-65"):
        assert _action_ids(workflow(model)) == ["configure_ptp"], model

    # The switch is never advertised, so evidence cannot make it appear.
    _qualify(tmp_path, monkeypatch, "tachyon", "TNS-100", "1.15.1-rev-8541")
    assert _action_ids(workflow("TNS-100")) == []


def test_mode_qualification_is_independent_per_mode(tmp_path, monkeypatch):
    _qualify_tachyon_modes(monkeypatch, modes=("ap",), tmp_path=tmp_path)

    workflow = workflow_for_port(
        _state(last_result="success"),
        mode_config_enabled=True,
    )

    assert _action_ids(workflow) == ["configure_ap"]


def test_required_mode_is_not_reported_ready(tmp_path, monkeypatch):
    _qualify_tachyon_modes(monkeypatch, tmp_path=tmp_path)
    workflow = workflow_for_port(
        _state(last_result="success", mode_selection_required=True),
        mode_config_enabled=True,
    )

    assert workflow["state"] == "action_required"
    assert workflow["required_action"] == "choose_device_mode"


def test_configured_mode_finishes_required_follow_up(tmp_path, monkeypatch):
    _qualify_tachyon_modes(monkeypatch, tmp_path=tmp_path)
    workflow = workflow_for_port(
        _state(
            last_result="success",
            mode_selection_required=True,
            device_mode="ap",
        ),
        mode_config_enabled=True,
    )

    assert workflow["state"] == "ready"
    assert workflow["required_action"] is None
    assert _action_ids(workflow) == ["configure_sm"]


def test_failures_offer_only_the_contextual_retry():
    generic = workflow_for_port(
        _state(last_result="failed"), mode_config_enabled=True
    )
    credentials = workflow_for_port(
        _state(last_result="failed", needs_credentials=True),
        mode_config_enabled=True,
    )

    assert _action_ids(generic) == ["retry_provisioning"]
    assert _action_ids(credentials) == ["retry_credentials"]


def test_manual_recovery_is_handler_owned_and_separate():
    workflow = workflow_for_port(
        _state(device_type="mikrotik", last_result="success"),
        mode_config_enabled=True,
    )

    assert _action_ids(workflow) == []
    assert _action_ids(workflow, "service_actions") == ["manual_netinstall"]
    assert workflow["service_actions"][0]["label"] == (
        "MikroTik recovery (Netinstall)"
    )


def test_active_run_has_no_actions():
    workflow = workflow_for_port(
        _state(device_type="mikrotik", provisioning=True, last_result="failed"),
        mode_config_enabled=True,
    )

    assert workflow["state"] == "running"
    assert workflow["available_actions"] == []
    assert workflow["service_actions"] == []
