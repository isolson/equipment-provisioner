"""Server-owned operator workflow state and contextual actions.

The port modal renders this contract instead of inferring vendor behavior in
JavaScript. Handler traits supply capabilities; this module combines them with
the current run state. The forthcoming job-intent selector can mark
``mode_selection_required`` on a port without changing the action renderer.
"""

import time
from typing import Any, Dict, List, Optional

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
    "sm": {
        "id": "configure_sm",
        "label": "Restore SM config",
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


def _checklist_value(state: Any, key: str) -> Any:
    """Read one checklist value from a real or test port state."""
    checklist = getattr(state, "checklist", None)
    if isinstance(checklist, dict):
        return checklist.get(key)
    return getattr(checklist, key, None)


def workflow_for_port(state: Any, mode_config_enabled: bool) -> Dict[str, Any]:
    """Build the workflow contract for one ``PortState``-like object."""
    capabilities = HandlerManager.operator_capabilities_for(
        getattr(state, "device_type", None),
        getattr(state, "device_model", None),
        getattr(state, "firmware_version", None),
    )
    actions = []  # type: List[Dict[str, str]]
    service_actions = []  # type: List[Dict[str, str]]
    required_action = None

    is_active = bool(
        getattr(state, "provisioning", False)
        or getattr(state, "waiting_for_boot", False)
        or getattr(state, "mode_job", None)
    )
    result = getattr(state, "last_result", None)
    is_success = result in ("complete", "success")
    is_failed = result == "failed"
    baseline_mode = capabilities["required_baseline_mode"]

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
        device_mode = getattr(state, "device_mode", None)
        has_configured_mode = bool(device_mode)
        is_converted_mode = device_mode == "ap" or str(device_mode).startswith("ptp")
        baseline_verified = (
            baseline_mode
            and _checklist_value(state, "config_upload") is True
            and _checklist_value(state, "config_verify") is True
        )
        if (
            baseline_mode
            and not has_configured_mode
            and _checklist_value(state, "config_upload") is not True
        ):
            workflow_state = "config_required"
            required_action = "apply_baseline_config"
        elif (
            baseline_mode
            and not has_configured_mode
            and _checklist_value(state, "config_verify") is not True
        ):
            workflow_state = "config_unverified"
            required_action = "verify_baseline_config"
        else:
            mode_actions = []
            if mode_config_enabled:
                if is_converted_mode and baseline_verified:
                    mode_actions = [dict(_MODE_ACTIONS["sm"])]
                elif not has_configured_mode:
                    mode_actions = _mode_actions(capabilities["post_provision_modes"])
                actions.extend(mode_actions)
            if mode_actions and not is_converted_mode and getattr(
                state, "mode_selection_required", False
            ):
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
        "baseline_mode": baseline_mode or None,
        "available_actions": actions,
        "service_actions": service_actions,
        # Evidence-derived qualification (provisioner/qualification.py). The
        # kiosk shows why an advertised mode is not offered.
        "baseline_qualified": bool(capabilities.get("baseline_qualified")),
        "unqualified": dict(capabilities.get("unqualified") or {}),
        "transitions": dict(capabilities.get("transitions") or {}),
    }


# ---------------------------------------------------------------------------
# Presentation state
# ---------------------------------------------------------------------------

#: One tone per phase. Card border, icon, and text derive from the phase, so
#: they can never disagree.
_PHASE_TONE = {
    "idle": "idle",
    "no_link": "idle",
    "detected": "active",
    "booting": "active",
    "running": "active",
    "mode_changing": "active",
    "qualifying": "active",
    "needs_credentials": "warning",
    "config_required": "warning",
    "config_unverified": "warning",
    "action_required": "warning",
    "qualified_caution": "warning",
    "failed": "error",
    "qualified_fail": "error",
    "complete": "success",
    "deployed": "success",
    "qualified_pass": "success",
}
_TONE_ICON = {
    "idle": "dash",
    "active": "spinner",
    "success": "check",
    "warning": "alert",
    "error": "x",
}
_PHASE_HEADLINE = {
    "idle": "NO LINK",
    "no_link": "NO LINK",
    "detected": "DETECTED",
    "booting": "BOOTING",
    "running": "PROVISIONING",
    "mode_changing": "MODE CHANGE",
    "qualifying": "QUALIFYING",
    "needs_credentials": "NEEDS CREDENTIALS",
    "config_required": "SM CONFIG MISSING",
    "config_unverified": "SM CONFIG UNVERIFIED",
    "action_required": "ACTION REQUIRED",
    "qualified_caution": "CAUTION",
    "failed": "FAILED",
    "qualified_fail": "FAIL",
    "complete": "COMPLETE",
    "deployed": "DEPLOYED",
    "qualified_pass": "PASS",
}
#: Seconds a device may sit in the boot wait before the card suggests a reset.
BOOT_RESET_HINT_AFTER = 300.0


def _progress(state: Any) -> Optional[Dict[str, Any]]:
    """Return ``{done, total, current_key, current_label}`` from the run plan."""
    plan = list(getattr(state, "step_plan", None) or [])
    if not plan:
        return None
    status = getattr(state, "step_status", None) or {}
    done = 0
    current = None
    for step in plan:
        key = step.get("key")
        value = status.get(key)
        if value is None:
            if current is None:
                current = step
            continue
        if value == "loading":
            current = current or step
            continue
        done += 1
    if current is None and done < len(plan):
        current = plan[done]
    return {
        "done": done,
        "total": len(plan),
        "current_key": current.get("key") if current else None,
        "current_label": current.get("label") if current else None,
    }


def _running_headline(state: Any, progress: Optional[Dict[str, Any]]) -> str:
    if progress and progress.get("current_label"):
        return str(progress["current_label"]).upper()
    return _PHASE_HEADLINE["running"]


def _mode_chip(state: Any) -> Optional[Dict[str, Any]]:
    mode = getattr(state, "device_mode", None)
    config = getattr(state, "mode_config", None) or {}
    if not mode:
        return None
    return {
        "mode": mode,
        "hostname": config.get("hostname"),
        "link_id": getattr(state, "ptp_link_id", None),
    }


def presentation_for_port(
    state: Any,
    mode_config_enabled: bool,
    now: Optional[float] = None,
    workflow: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return the single presentation state for one port.

    The evaluation order encodes the post-config link-loss rule from
    ``STANDARDS.md``: ``waiting_for_boot`` outranks a preserved result,
    ``needs_credentials`` outranks a generic failure, and ``last_result``
    outranks ``link_up``, so a device that changed networks after config still
    shows its result.
    """
    now = time.time() if now is None else now
    workflow = workflow or workflow_for_port(state, mode_config_enabled)
    reprovision_wait = getattr(state, "reprovision_wait", None)
    if reprovision_wait is None and getattr(state, "last_provisioned_at", None) and not getattr(state, "last_result", None):
        cooldown = getattr(state, "reprovision_cooldown", 1800)
        reprovision_wait = max(0, int(cooldown - (now - state.last_provisioned_at)))
        try:
            state.reprovision_wait = reprovision_wait
        except AttributeError:
            pass
    checklist = getattr(state, "checklist", None)
    link_qualification = _checklist_value(state, "link_qualification")
    progress = None
    detail = None
    reset_hint = False
    mode_job = getattr(state, "mode_job", None)

    if link_qualification:
        value = str(link_qualification).upper()
        phase = {
            "PASS": "qualified_pass",
            "CAUTION": "qualified_caution",
            "FAIL": "qualified_fail",
        }.get(value, "qualifying")
        detail = getattr(state, "last_error", None) if phase != "qualifying" else "Watching link"
    elif getattr(state, "waiting_for_boot", False):
        phase = "booting"
        remaining = getattr(state, "boot_wait_until", None)
        if remaining:
            detail = "%ds remaining" % max(0, int(remaining - now))
        started = getattr(state, "boot_wait_started", None)
        reset_hint = started is not None and (now - started) > BOOT_RESET_HINT_AFTER
    elif mode_job:
        phase = "mode_changing"
        steps = mode_job.get("steps") or []
        status = mode_job.get("status") or {}
        done = sum(1 for step in steps if status.get(step.get("key")) not in (None, "loading"))
        current = next((step for step in steps if status.get(step.get("key")) in (None, "loading")), None)
        progress = {
            "done": done,
            "total": len(steps),
            "current_key": current.get("key") if current else None,
            "current_label": current.get("label") if current else None,
        }
        detail = "Applying %s" % str(mode_job.get("mode", "")).upper()
    elif getattr(state, "provisioning", False):
        phase = "running"
        progress = _progress(state)
        if progress:
            detail = "Step %d of %d" % (min(progress["done"] + 1, progress["total"]), progress["total"])
    elif getattr(state, "last_result", None) in ("success", "complete"):
        workflow_state = workflow.get("state")
        if workflow_state in ("config_required", "config_unverified", "action_required"):
            phase = workflow_state
        elif getattr(state, "device_mode", None):
            phase = "deployed"
        else:
            phase = "complete"
        progress = _progress(state)
    elif getattr(state, "needs_credentials", False):
        # A login failure sets both needs_credentials and a failed result.
        # The credential prompt is the useful state.
        phase = "needs_credentials"
        detail = getattr(state, "last_error", None)
    elif getattr(state, "last_result", None) == "failed":
        phase = "failed"
        detail = getattr(state, "last_error", None)
        progress = _progress(state)
    elif not getattr(state, "link_up", False):
        phase = "no_link"
    elif getattr(state, "device_detected", False):
        phase = "detected"
        wait = getattr(state, "reprovision_wait", None)
        if wait is None and hasattr(state, "last_provisioned_at"):
            wait = 0
        if wait:
            minutes = max(1, int(round(wait / 60.0)))
            detail = "Provisioned earlier. Auto-retry in %dm. Tap to provision now." % minutes
    else:
        phase = "idle"

    tone = _PHASE_TONE[phase]
    headline = _running_headline(state, progress) if phase == "running" else _PHASE_HEADLINE[phase]
    if detail and isinstance(detail, str) and len(detail) > 120:
        detail = detail[:117] + "..."
    return {
        "phase": phase,
        "tone": tone,
        "icon": _TONE_ICON[tone],
        "headline": headline,
        "detail": detail,
        "progress": progress,
        "reset_hint": reset_hint,
        "mode_chip": _mode_chip(state),
    }
