"""Tests for the Evolution Digital qualification handler."""

import asyncio

import pytest

from provisioner.handlers.evolution_digital import EvolutionDigitalHandler
from provisioner.port_manager import PortManager


def _make_manager_with_ports() -> PortManager:
    manager = PortManager(num_ports=6)
    manager._generate_port_configs()
    return manager


def test_partner_port_pairs_two_ports_with_same_mac():
    """Two ports running ED with the same observed MAC should pair as partners.

    ED refurb routers internally bridge their WAN and LAN ethernet ports,
    so a single physical device plugged into two Pi ports surfaces the same
    source MAC on both VLANs. The qualification handler relies on this to
    pair them and run co-flap detection.
    """
    manager = _make_manager_with_ports()
    mac = "84:01:12:42:95:fe"

    for port_num in (3, 5):
        state = manager.port_states[port_num]
        state.link_up = True
        state.device_detected = True
        state.device_type = "evolution_digital"
        state.device_mac = mac

    handler_3 = EvolutionDigitalHandler(manager, port_num=3)
    handler_5 = EvolutionDigitalHandler(manager, port_num=5)

    assert handler_3._get_partner_port() == 5
    assert handler_5._get_partner_port() == 3


def test_partner_port_match_is_case_insensitive():
    """MAC casing differs between sources; comparison must normalise."""
    manager = _make_manager_with_ports()

    manager.port_states[3].device_type = "evolution_digital"
    manager.port_states[3].device_mac = "84:01:12:42:95:fe"
    manager.port_states[5].device_type = "evolution_digital"
    manager.port_states[5].device_mac = "84:01:12:42:95:FE"

    assert EvolutionDigitalHandler(manager, port_num=3)._get_partner_port() == 5


def test_partner_port_skips_non_ed_ports():
    """Other vendors with the same MAC (test fixtures, mocks) must not pair."""
    manager = _make_manager_with_ports()
    mac = "84:01:12:42:95:fe"

    manager.port_states[3].device_type = "evolution_digital"
    manager.port_states[3].device_mac = mac
    manager.port_states[5].device_type = "mikrotik"
    manager.port_states[5].device_mac = mac

    assert EvolutionDigitalHandler(manager, port_num=3)._get_partner_port() is None


def test_partner_port_returns_none_when_alone():
    """A single ED port with no twin should return None, not raise."""
    manager = _make_manager_with_ports()
    manager.port_states[3].device_type = "evolution_digital"
    manager.port_states[3].device_mac = "84:01:12:42:95:fe"

    assert EvolutionDigitalHandler(manager, port_num=3)._get_partner_port() is None


def test_partner_port_returns_none_when_own_mac_missing():
    """If detection didn't capture our own MAC yet, no partner can be inferred."""
    manager = _make_manager_with_ports()
    manager.port_states[3].device_type = "evolution_digital"
    manager.port_states[3].device_mac = None
    manager.port_states[5].device_type = "evolution_digital"
    manager.port_states[5].device_mac = "84:01:12:42:95:fe"

    assert EvolutionDigitalHandler(manager, port_num=3)._get_partner_port() is None


@pytest.mark.asyncio
async def test_run_window_re_checks_partner_after_watch_period(monkeypatch):
    """Partner re-evaluation must happen at the END of the watch window.

    If port 5 starts qualifying before port 3 has been passive-detected, a
    one-shot partner check at window-start would lock in partner_present=False
    for port 5 — and downstream logic promotes "passed but solo" to CAUTION.
    Port 3, detected mid-window, would later see port 5 already detected and
    end with partner_present=True → PASS. Same physical device, two different
    verdicts. Re-checking at window-end keeps both ports symmetric.
    """
    manager = _make_manager_with_ports()
    mac = "18:34:af:ab:b3:3f"

    # Port 5 is detected first; port 3 is not yet.
    manager.port_states[5].link_up = True
    manager.port_states[5].link_speed = "1Gbps"
    manager.port_states[5].device_detected = True
    manager.port_states[5].device_type = "evolution_digital"
    manager.port_states[5].device_mac = mac

    manager.port_states[3].link_up = True
    manager.port_states[3].link_speed = "1Gbps"
    # Note: not yet detected as ED.

    handler = EvolutionDigitalHandler(manager, port_num=5)

    # Skip real timing — make sleeps instantaneous, and have the watch-period
    # sleep simulate "partner port 3 finishes its passive sniff mid-window".
    sleep_count = {"n": 0}

    async def fake_sleep(seconds):
        sleep_count["n"] += 1
        if sleep_count["n"] == 2:
            # Second sleep is the WATCH_WINDOW; partner gets detected during it.
            manager.port_states[3].device_detected = True
            manager.port_states[3].device_type = "evolution_digital"
            manager.port_states[3].device_mac = mac

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def notify(*_args, **_kwargs):
        pass

    verdict, reason, flap_count, partner_present = await handler._run_window(
        notify, attempt=1
    )

    assert partner_present is True, (
        "partner_present must be re-evaluated after the watch window so the "
        "first-qualifying port doesn't get penalised when its partner shows "
        "up mid-window"
    )
    assert verdict == "CLEAN"


@pytest.mark.asyncio
async def test_run_window_partner_remains_false_when_truly_alone(monkeypatch):
    """Symmetric counterpart: a genuine single-cable plug-in still flags partner=False."""
    manager = _make_manager_with_ports()
    mac = "18:34:af:ab:b3:3f"

    manager.port_states[5].link_up = True
    manager.port_states[5].link_speed = "1Gbps"
    manager.port_states[5].device_detected = True
    manager.port_states[5].device_type = "evolution_digital"
    manager.port_states[5].device_mac = mac
    # No second port is ever detected.

    handler = EvolutionDigitalHandler(manager, port_num=5)

    async def fake_sleep(_seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def notify(*_args, **_kwargs):
        pass

    _verdict, _reason, _flaps, partner_present = await handler._run_window(
        notify, attempt=1
    )

    assert partner_present is False


def _capture_notify():
    """Build an async notify callback plus a list it appends every call into."""
    calls = []

    async def notify(step, status, detail=None):
        calls.append((step, status, detail))

    return notify, calls


@pytest.mark.asyncio
async def test_provision_passed_with_partner_emits_pass_status(monkeypatch):
    """A CLEAN verdict with partner_present=True must surface as 'PASS'.

    The status label is what the bench tech reads in the UI; it must reflect
    a healthy two-cable plug-in unambiguously.
    """
    manager = _make_manager_with_ports()
    mac = "18:34:af:ab:b3:3f"
    for port_num in (3, 5):
        s = manager.port_states[port_num]
        s.link_up = True
        s.link_speed = "1Gbps"
        s.device_detected = True
        s.device_type = "evolution_digital"
        s.device_mac = mac

    handler = EvolutionDigitalHandler(manager, port_num=5)

    async def fake_sleep(_seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    notify, calls = _capture_notify()
    result = await handler.provision(on_progress=notify)

    qual = [c for c in calls if c[0] == "link_qualification"]
    assert qual, "expected at least one link_qualification notify call"
    final_status = qual[-1][1]
    assert final_status == "PASS"
    assert result.passed is True
    assert result.caution is False


@pytest.mark.asyncio
async def test_provision_passed_without_partner_emits_caution_status(monkeypatch):
    """A CLEAN verdict with partner_present=False must surface as 'CAUTION'.

    Single-cable plug-ins look healthy on link metrics alone but might mean
    the second LAN jack is dead. The CAUTION banner exists so a tech doesn't
    ship a half-broken router on a bare green PASS.
    """
    manager = _make_manager_with_ports()
    mac = "18:34:af:ab:b3:3f"
    s = manager.port_states[5]
    s.link_up = True
    s.link_speed = "1Gbps"
    s.device_detected = True
    s.device_type = "evolution_digital"
    s.device_mac = mac
    # No second port present.

    handler = EvolutionDigitalHandler(manager, port_num=5)

    async def fake_sleep(_seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    notify, calls = _capture_notify()
    result = await handler.provision(on_progress=notify)

    qual = [c for c in calls if c[0] == "link_qualification"]
    assert qual, "expected at least one link_qualification notify call"
    final_status = qual[-1][1]
    final_detail = qual[-1][2]
    assert final_status == "CAUTION"
    assert "both cables" in (final_detail or "").lower()
    assert result.passed is True
    assert result.caution is True
