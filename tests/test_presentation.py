"""One server-owned presentation state per port."""

from types import SimpleNamespace

from provisioner.workflow_actions import presentation_for_port


def _state(**overrides):
    values = {
        "device_type": "cambium",
        "device_model": "ePMP 4616",
        "firmware_version": "5.11.1",
        "device_detected": True,
        "link_up": True,
        "provisioning": False,
        "waiting_for_boot": False,
        "boot_wait_until": None,
        "boot_wait_started": None,
        "last_result": None,
        "last_error": None,
        "needs_credentials": False,
        "device_mode": None,
        "mode_config": None,
        "ptp_link_id": None,
        "mode_job": None,
        "mode_selection_required": False,
        "checklist": {"config_upload": True, "config_verify": True},
        "step_plan": [],
        "step_status": {},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_boot_wait_outranks_a_preserved_result():
    p = presentation_for_port(_state(waiting_for_boot=True, last_result="success", boot_wait_until=1100), True, now=1000)
    assert p["phase"] == "booting"
    assert p["tone"] == "active"
    assert p["detail"] == "100s remaining"
    assert p["reset_hint"] is False
    late = presentation_for_port(_state(waiting_for_boot=True, boot_wait_started=0), True, now=400)
    assert late["reset_hint"] is True


def test_result_outranks_link_down():
    p = presentation_for_port(_state(link_up=False, last_result="success"), True)
    assert p["phase"] == "complete"
    assert p["tone"] == "success"
    assert p["icon"] == "check"
    f = presentation_for_port(_state(link_up=False, last_result="failed", last_error="boom"), True)
    assert f["phase"] == "failed"
    assert f["detail"] == "boom"


def test_no_link_then_credentials_then_detected_then_idle():
    assert presentation_for_port(_state(link_up=False), True)["phase"] == "no_link"
    assert presentation_for_port(_state(needs_credentials=True), True)["phase"] == "needs_credentials"
    # A login failure records a failed result too; the credential prompt wins.
    p = presentation_for_port(_state(needs_credentials=True, last_result="failed", last_error="401"), True)
    assert p["phase"] == "needs_credentials"
    assert p["detail"] == "401"
    assert presentation_for_port(_state(), True)["phase"] == "detected"
    assert presentation_for_port(_state(device_detected=False), True)["phase"] == "idle"


def test_running_shows_the_current_step_and_progress():
    p = presentation_for_port(
        _state(
            provisioning=True,
            step_plan=[{"key": "login", "label": "Login"}, {"key": "config_upload", "label": "Config"}],
            step_status={"login": True, "config_upload": "loading"},
        ),
        True,
    )
    assert p["phase"] == "running"
    assert p["headline"] == "CONFIG"
    assert p["progress"] == {"done": 1, "total": 2, "current_key": "config_upload", "current_label": "Config"}
    assert p["detail"] == "Step 2 of 2"


def test_success_follows_the_workflow_state():
    missing = presentation_for_port(_state(last_result="success", checklist={"config_upload": "skipped"}), True)
    assert missing["phase"] == "config_required"
    assert missing["tone"] == "warning"
    unverified = presentation_for_port(_state(last_result="success", checklist={"config_upload": True, "config_verify": "unverified"}), True)
    assert unverified["phase"] == "config_unverified"
    deployed = presentation_for_port(_state(last_result="success", device_mode="ptp-a", mode_config={"hostname": "tw05a-tw12"}, ptp_link_id="tw05-tw12"), True)
    assert deployed["phase"] == "deployed"
    assert deployed["mode_chip"] == {"mode": "ptp-a", "hostname": "tw05a-tw12", "link_id": "tw05-tw12"}


def test_mode_job_shows_mode_change_progress():
    p = presentation_for_port(
        _state(
            last_result="success",
            mode_job={"mode": "ap", "steps": [{"key": "apply", "label": "Apply"}, {"key": "verify", "label": "Verify"}], "status": {"apply": True}},
        ),
        True,
    )
    assert p["phase"] == "mode_changing"
    assert p["headline"] == "MODE CHANGE"
    assert p["progress"]["done"] == 1
    assert p["progress"]["current_key"] == "verify"


def test_evolution_digital_qualification_phases():
    for value, phase in (("PASS", "qualified_pass"), ("CAUTION", "qualified_caution"), ("FAIL", "qualified_fail"), ("loading", "qualifying")):
        p = presentation_for_port(_state(device_type="evolution_digital", checklist={"link_qualification": value}), True)
        assert p["phase"] == phase


def test_tone_icon_and_headline_come_from_one_table():
    from provisioner.workflow_actions import _PHASE_HEADLINE, _PHASE_TONE, _TONE_ICON

    assert set(_PHASE_HEADLINE) == set(_PHASE_TONE)
    assert set(_PHASE_TONE.values()) <= set(_TONE_ICON)


def test_detected_during_cooldown_explains_the_wait():
    p = presentation_for_port(_state(reprovision_wait=291), True)
    assert p["phase"] == "detected"
    assert p["detail"] == "Provisioned earlier. Auto-retry in 5m. Tap to provision now."
    assert presentation_for_port(_state(reprovision_wait=0), True)["detail"] is None
