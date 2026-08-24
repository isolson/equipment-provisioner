"""Server-owned operator workflow state and contextual actions.

The port modal renders this contract instead of inferring vendor behavior in
JavaScript. Handler traits supply capabilities; this module combines them with
the current run state. The forthcoming job-intent selector can mark
``mode_selection_required`` on a port without changing the action renderer.
"""

from typing import Any, Dict, List

from .handler_manager import HandlerManager


_MODE_ACTIONS = {
    "ap": {
        "id": "configure_ap",
        "label": "Set up AP",
        "kind": "primary",
    },
    "ptp": {
        "id": "configure_ptp",
        "label": "Set up PTP link",
        "kind": "primary",
    },
}


def _mode_actions(modes: List[str]) -> List[Dict[str, str]]:
    actions = []
    for mode in modes:
        action = _MODE_ACTIONS.get(mode)
        if action is None:
            action = {
                "id": "configure_" + mode,
                "label": "Set up " + mode.replace("_", " ").upper(),
                "kind": "primary",
            }
        actions.append(dict(action))
    return actions


def workflow_for_port(state: Any, mode_config_enabled: bool) -> Dict[str, Any]:
    """Build the workflow contract for one ``PortState``-like object."""
    capabilities = HandlerManager.operator_capabilities_for(
        getattr(state, "device_type", None)
    )
    actions = []  # type: List[Dict[str, str]]
    service_actions = []  # type: List[Dict[str, str]]
    required_action = None

    is_active = bool(
        getattr(state, "provisioning", False)
        or getattr(state, "waiting_for_boot", False)
    )
    result = getattr(state, "last_result", None)
    is_success = result in ("complete", "success")
    is_failed = result == "failed"

    if is_active:
        workflow_state = "running"
    elif is_failed:
        workflow_state = "failed"
        if getattr(state, "needs_credentials", False):
            actions.append({
                "id": "retry_credentials",
                "label": "Enter credentials and retry",
                "kind": "primary",
            })
        else:
            actions.append({
                "id": "retry_provisioning",
                "label": "Retry provisioning",
                "kind": "primary",
            })
    elif is_success:
        workflow_state = "ready"
        mode_actions = []
        if mode_config_enabled and not getattr(state, "device_mode", None):
            mode_actions = _mode_actions(capabilities["post_provision_modes"])
            actions.extend(mode_actions)
        if mode_actions and getattr(state, "mode_selection_required", False):
            workflow_state = "action_required"
            required_action = "choose_device_mode"
    elif getattr(state, "device_detected", False):
        workflow_state = "detected"
    else:
        workflow_state = "idle"

    if not is_active and capabilities["manual_netinstall"]:
        service_actions.append({
            "id": "manual_netinstall",
            "label": capabilities["manual_netinstall_label"],
            "kind": "recovery",
        })

    return {
        "state": workflow_state,
        "required_action": required_action,
        "available_actions": actions,
        "service_actions": service_actions,
    }
