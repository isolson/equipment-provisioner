"""Contextual operator-action contract tests."""

from types import SimpleNamespace

from provisioner.handler_manager import HandlerManager
from provisioner.workflow_actions import workflow_for_port


def _state(**overrides):
    values = {
        "device_type": "tachyon",
        "device_detected": True,
        "provisioning": False,
        "waiting_for_boot": False,
        "last_result": None,
        "needs_credentials": False,
        "device_mode": None,
        "mode_selection_required": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _action_ids(workflow, key="available_actions"):
    return [action["id"] for action in workflow[key]]


def test_handler_capabilities_own_mode_support():
    assert HandlerManager.operator_capabilities_for("tachyon")[
        "post_provision_modes"
    ] == ["ap", "ptp"]
    assert HandlerManager.operator_capabilities_for("cambium")[
        "post_provision_modes"
    ] == ["ap", "ptp"]
    assert HandlerManager.operator_capabilities_for("tarana")[
        "post_provision_modes"
    ] == []
    assert HandlerManager.operator_capabilities_for("not-a-vendor") == {
        "post_provision_modes": [],
        "manual_netinstall": False,
        "manual_netinstall_label": "",
    }


def test_success_actions_respect_feature_flag_and_handler_capability():
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


def test_required_mode_is_not_reported_ready():
    workflow = workflow_for_port(
        _state(last_result="success", mode_selection_required=True),
        mode_config_enabled=True,
    )

    assert workflow["state"] == "action_required"
    assert workflow["required_action"] == "choose_device_mode"


def test_configured_mode_finishes_required_follow_up():
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
    assert _action_ids(workflow) == []


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
