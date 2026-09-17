"""Server-owned per-port timeline: bounded, persisted, secret-free."""

import json

from provisioner.port_manager import ManagementConfig, PortManager


def _manager(tmp_path, events=True):
    pm = PortManager(
        base_interface="eth0",
        vlan_start=1991,
        num_ports=2,
        management=ManagementConfig(enabled=False),
        setup_vlans=True,
        mode_config_enabled=True,
        events_path=str(tmp_path / "port_events") if events else None,
    )
    from provisioner.port_manager import PortState

    pm.port_states = {1: PortState(port_number=1, vlan_id=1991), 2: PortState(port_number=2, vlan_id=1992)}
    return pm


def test_events_are_sequenced_and_bounded(tmp_path):
    pm = _manager(tmp_path)
    for i in range(250):
        pm.record_event(1, "step_finished", "Step", key="k%d" % i, status=True, broadcast=False)
    events = pm.get_events(1)
    assert events["latest_seq"] == 250
    assert len(events["events"]) == 200
    assert events["events"][0]["seq"] == 51
    assert pm.get_events(1, since=248)["events"] == [
        {"seq": 249, "ts": events["events"][-2]["ts"], "kind": "step_finished", "key": "k248", "label": "Step", "status": True, "detail": None, "run_id": None},
        events["events"][-1],
    ]
    assert pm.get_events(2)["events"] == []


def test_events_persist_and_reload(tmp_path):
    pm = _manager(tmp_path)
    pm.record_event(1, "link_up", "Link up", detail="1Gbps", broadcast=False)
    pm.record_event(1, "run_finished", "Provisioning complete", status="success", broadcast=False)
    path = tmp_path / "port_events" / "port1.jsonl"
    assert path.is_file()
    assert len(path.read_text().splitlines()) == 2

    reloaded = _manager(tmp_path)
    events = reloaded.get_events(1)
    assert [e["kind"] for e in events["events"]] == ["link_up", "run_finished"]
    assert events["latest_seq"] == 2
    reloaded.record_event(1, "link_down", "Link down", broadcast=False)
    assert reloaded.get_events(1)["latest_seq"] == 3


def test_checklist_updates_and_plan_create_events(tmp_path):
    pm = _manager(tmp_path)
    pm.mark_port_provisioning(1, True)
    pm.set_step_plan(1, [{"key": "login", "label": "Login"}, {"key": "config_verify", "label": "Config verify"}])
    pm.update_checklist(1, "login", "loading")
    pm.update_checklist(1, "login", True)
    pm.update_checklist(1, "config_verify", False, detail="mismatch: mgmtVLANVID")
    pm.mark_port_provisioning(1, False, success=False, error="Config verification failed: mismatch mgmtVLANVID")
    kinds = [(e["kind"], e["key"], e["status"]) for e in pm.get_events(1)["events"]]
    assert kinds == [
        ("run_started", None, None),
        ("plan", None, None),
        ("step_started", "login", "loading"),
        ("step_finished", "login", True),
        ("step_finished", "config_verify", False),
        ("run_finished", None, "failed"),
    ]
    run_ids = {e["run_id"] for e in pm.get_events(1)["events"]}
    assert len(run_ids) == 1 and None not in run_ids
    assert pm.get_events(1)["events"][4]["detail"] == "mismatch: mgmtVLANVID"


def test_details_are_truncated_and_never_values(tmp_path):
    pm = _manager(tmp_path)
    pm.record_event(1, "note", "Note", detail="x" * 500, broadcast=False)
    assert len(pm.get_events(1)["events"][0]["detail"]) == 160


def test_mode_job_lifecycle(tmp_path):
    pm = _manager(tmp_path)
    job_id = pm.begin_mode_job(1, "ptp-a", [{"key": "apply", "label": "Apply"}, {"key": "verify", "label": "Verify"}])
    assert pm.port_states[1].mode_job["id"] == job_id
    status = pm._get_single_port_status(1)
    assert status["presentation"]["phase"] == "mode_changing"
    assert status["workflow"]["state"] == "running"
    pm.update_mode_job(1, "apply", "loading")
    pm.update_mode_job(1, "apply", True)
    pm.update_mode_job(1, "verify", False, "mismatch: wirelessInterfaceMode")
    pm.finish_mode_job(1, False, "mismatch: wirelessInterfaceMode")
    assert pm.port_states[1].mode_job is None
    kinds = [e["kind"] for e in pm.get_events(1)["events"]]
    assert kinds == ["mode_change_requested", "step_started", "step_finished", "step_finished", "mode_change_failed"]
    assert all(e["run_id"] == job_id for e in pm.get_events(1)["events"])


def test_no_events_path_keeps_events_in_memory_only(tmp_path):
    pm = _manager(tmp_path, events=False)
    pm.record_event(1, "link_up", "Link up", broadcast=False)
    assert pm.get_events(1)["latest_seq"] == 1
    assert not (tmp_path / "port_events").exists()


def test_port_status_reports_reprovision_wait(tmp_path):
    import time

    pm = _manager(tmp_path)
    state = pm.port_states[1]
    state.link_up = True
    state.device_detected = True
    state.device_mac = "aa"
    state.last_provisioned_mac = "aa"
    state.last_provisioned_at = time.time() - 60
    status = pm._get_single_port_status(1)
    assert 1700 < status["reprovision_wait"] <= 1740
    assert "Auto-retry" in status["presentation"]["detail"]
    state.device_mac = "bb"
    assert pm._get_single_port_status(1)["reprovision_wait"] == 0
