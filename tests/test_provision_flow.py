"""Regression tests for the provision() flow in handlers/base.py.

Each handler property (``supports_dual_bank``, ``update_triggers_reboot``,
``verify_active_bank``, ``config_after_all_firmware``, ``fw2_skips_reboot``)
controls one branch in the provisioning flow. These tests use ``SpyHandler``
(see ``conftest.py``) to assert the exact sequence of method calls that the
flow makes for each property toggle, plus a few canonical real-handler
combinations.
"""

import pytest


PROVISION_KWARGS = dict(
    config={"key": "value"},
    firmware_path="/tmp/fw.bin",
    expected_firmware="new",
    dual_bank=True,
)


# ---------------------------------------------------------------------------
# supports_dual_bank
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_bank_skips_fw2_phase(spy_handler_factory):
    """supports_dual_bank=False ⇒ update_firmware called once with bank=None and no FW2 phase."""
    spy = spy_handler_factory(supports_dual_bank=False)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    update_calls = [c for c in spy.calls if c[0] == "update_firmware"]
    assert len(update_calls) == 1
    assert update_calls[0][1]["bank"] is None
    upload_calls = [c for c in spy.calls if c[0] == "upload_firmware"]
    assert len(upload_calls) == 1


@pytest.mark.asyncio
async def test_dual_bank_runs_fw2_phase(spy_handler_factory):
    """supports_dual_bank=True ⇒ FW1 (bank=1) and FW2 (bank=2) both run."""
    spy = spy_handler_factory(supports_dual_bank=True)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    update_calls = [c for c in spy.calls if c[0] == "update_firmware"]
    assert [c[1]["bank"] for c in update_calls] == [1, 2]
    upload_calls = [c for c in spy.calls if c[0] == "upload_firmware"]
    assert len(upload_calls) == 2


# ---------------------------------------------------------------------------
# update_triggers_reboot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_triggers_reboot_skips_reboot_call(spy_handler_factory):
    """update_triggers_reboot=True ⇒ reboot() is never called; wait_for_reboot still is."""
    spy = spy_handler_factory(update_triggers_reboot=True)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    assert "reboot" not in spy.call_names
    assert "wait_for_reboot" in spy.call_names


@pytest.mark.asyncio
async def test_default_calls_reboot_explicitly(spy_handler_factory):
    """update_triggers_reboot=False (default) ⇒ reboot() is called."""
    spy = spy_handler_factory()

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    assert "reboot" in spy.call_names


# ---------------------------------------------------------------------------
# config_after_all_firmware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_config_default_runs_between_firmware_phases(spy_handler_factory):
    """config_after_all_firmware=False ⇒ apply_config + verify_config run between FW1 and FW2."""
    spy = spy_handler_factory(supports_dual_bank=True)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    names = spy.call_names
    apply_idx = names.index("apply_config")
    verify_cfg_idx = names.index("verify_config")
    fw2_update_idx = next(
        i for i, c in enumerate(spy.calls) if c[0] == "update_firmware" and c[1]["bank"] == 2
    )
    final_fw_idx = names.index("get_firmware_version")
    assert apply_idx < verify_cfg_idx < fw2_update_idx < final_fw_idx


@pytest.mark.asyncio
async def test_config_after_all_firmware_defers_config(spy_handler_factory):
    """config_after_all_firmware=True ⇒ apply_config runs after FW2 verify, no verify_config."""
    spy = spy_handler_factory(
        supports_dual_bank=True,
        config_after_all_firmware=True,
    )

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    names = spy.call_names
    fw2_update_idx = next(
        i for i, c in enumerate(spy.calls) if c[0] == "update_firmware" and c[1]["bank"] == 2
    )
    final_fw_idx = names.index("get_firmware_version")
    apply_idx = names.index("apply_config")
    assert fw2_update_idx < final_fw_idx < apply_idx
    assert "verify_config" not in names


# ---------------------------------------------------------------------------
# fw2_skips_reboot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fw2_skips_reboot_omits_reboot_after_fw2(spy_handler_factory):
    """fw2_skips_reboot=True ⇒ exactly one reboot/wait_for_reboot, both from FW1."""
    spy = spy_handler_factory(supports_dual_bank=True, fw2_skips_reboot=True)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    names = spy.call_names
    assert names.count("reboot") == 1
    assert names.count("wait_for_reboot") == 1
    fw1_update_idx = next(
        i for i, c in enumerate(spy.calls) if c[0] == "update_firmware" and c[1]["bank"] == 1
    )
    reboot_idx = names.index("reboot")
    assert fw1_update_idx < reboot_idx


@pytest.mark.asyncio
async def test_fw2_with_reboot_default_calls_reboot_twice(spy_handler_factory):
    """fw2_skips_reboot=False (default) on a dual-bank device ⇒ reboot called for FW1 and FW2."""
    spy = spy_handler_factory(supports_dual_bank=True)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    assert spy.call_names.count("reboot") == 2
    assert spy.call_names.count("wait_for_reboot") == 2


# ---------------------------------------------------------------------------
# verify_active_bank
# ---------------------------------------------------------------------------


def _install_active_bank_flip(spy, monkeypatch):
    """Model a Tachyon-style device: update_firmware writes to the inactive bank
    and the post-update reboot flips active to the freshly-written bank.
    """

    async def update_flips_active(bank=None):
        spy.calls.append(("update_firmware", {"bank": bank}))
        inactive = 1 if spy._active == 2 else 2
        if inactive == 1:
            spy._bank1 = "new"
        else:
            spy._bank2 = "new"
        spy._active = inactive
        return True

    monkeypatch.setattr(spy, "update_firmware", update_flips_active)


@pytest.mark.asyncio
async def test_verify_active_bank_uses_active_for_fw1_check(spy_handler_factory, monkeypatch):
    """verify_active_bank=True passes verification when the active bank matches."""
    spy = spy_handler_factory(
        supports_dual_bank=True,
        verify_active_bank=True,
        active_bank=1,
        initial_bank1="garbage",
        initial_bank2="old",
    )
    _install_active_bank_flip(spy, monkeypatch)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message


@pytest.mark.asyncio
async def test_verify_active_bank_false_fails_when_only_active_matches(
    spy_handler_factory, monkeypatch
):
    """verify_active_bank=False with the same setup fails FW1 verify (checks bank1)."""
    spy = spy_handler_factory(
        supports_dual_bank=True,
        verify_active_bank=False,
        active_bank=1,
        initial_bank1="garbage",
        initial_bank2="old",
    )
    _install_active_bank_flip(spy, monkeypatch)

    result = await spy.provision(**PROVISION_KWARGS)

    assert not result.success
    assert "verification failed" in (result.error_message or "").lower()


# ---------------------------------------------------------------------------
# Canonical real-handler combos (smoke tests)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cambium_pattern_dual_bank_only(spy_handler_factory):
    """Cambium-like: dual-bank, default config order, explicit reboots."""
    spy = spy_handler_factory(supports_dual_bank=True)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    names = spy.call_names
    assert names.count("reboot") == 2
    assert names.count("wait_for_reboot") == 2
    apply_idx = names.index("apply_config")
    fw2_idx = next(
        i for i, c in enumerate(spy.calls) if c[0] == "update_firmware" and c[1]["bank"] == 2
    )
    assert apply_idx < fw2_idx
    assert "verify_config" in names


@pytest.mark.asyncio
async def test_tachyon_pattern_auto_reboot_deferred_config(spy_handler_factory, monkeypatch):
    """Tachyon-like: update auto-reboots, config deferred until after all firmware."""
    spy = spy_handler_factory(
        supports_dual_bank=True,
        update_triggers_reboot=True,
        config_after_all_firmware=True,
        verify_active_bank=True,
        active_bank=1,
    )

    _install_active_bank_flip(spy, monkeypatch)

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    names = spy.call_names
    assert "reboot" not in names  # auto-reboot
    assert "verify_config" not in names  # deferred config skips verify
    fw2_idx = next(
        i for i, c in enumerate(spy.calls) if c[0] == "update_firmware" and c[1]["bank"] == 2
    )
    apply_idx = names.index("apply_config")
    assert fw2_idx < apply_idx


@pytest.mark.asyncio
async def test_tarana_pattern_verify_active_skip_fw2_reboot(spy_handler_factory, monkeypatch):
    """Tarana-like: verify_active_bank + fw2_skips_reboot, default config order."""
    spy = spy_handler_factory(
        supports_dual_bank=True,
        verify_active_bank=True,
        fw2_skips_reboot=True,
        active_bank=1,
    )

    result = await spy.provision(**PROVISION_KWARGS)

    assert result.success, result.error_message
    names = spy.call_names
    assert names.count("reboot") == 1  # only FW1 reboot
    assert names.count("wait_for_reboot") == 1
    apply_idx = names.index("apply_config")
    fw2_idx = next(
        i for i, c in enumerate(spy.calls) if c[0] == "update_firmware" and c[1]["bank"] == 2
    )
    assert apply_idx < fw2_idx
    assert "verify_config" in names
