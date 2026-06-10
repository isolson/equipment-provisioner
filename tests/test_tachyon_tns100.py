"""Regression test for the deferred-config (TNS-100) path.

When ``config_after_all_firmware`` is set (Tachyon TNS-100 switches, which
change their management VLAN/DHCP and leave the provisioning link), the config
is applied after all firmware and cannot be read back in-band. The flow used to
report this step as ``"skipped"`` — which reads as "all good, we chose not to
check". That is the dishonest signal the rework targets: it must be reported as
the distinct amber ``"unverified"`` state ("sent, not confirmed"), never as a
green success.
"""

PROVISION_KWARGS = dict(
    config={"key": "value"},
    firmware_path="/tmp/fw.bin",
    expected_firmware="new",
    dual_bank=True,
)


async def test_deferred_config_reports_unverified_not_skipped(spy_handler_factory):
    events = []

    async def recorder(step, success, detail):
        events.append((step, success, detail))

    spy = spy_handler_factory(supports_dual_bank=True, config_after_all_firmware=True)

    result = await spy.provision(**PROVISION_KWARGS, on_progress=recorder)

    assert result.success, result.error_message

    config_verify_values = [val for (step, val, _detail) in events if step == "config_verify"]

    # The deferred path must emit exactly the honest amber state...
    assert "unverified" in config_verify_values
    # ...and must never report the step as a green success or a benign skip.
    assert True not in config_verify_values
    assert "skipped" not in config_verify_values


async def test_unverified_survives_naive_progress_sink(spy_handler_factory):
    """The UNVERIFIED status must reach the checklist intact even through the
    web/api.py progress sink, which stores ``detail if detail else success``.

    If the notify carried a detail message, that string would be stored in place
    of "unverified" and the UI's value==='unverified' guard would never fire —
    the step would render green. So config_verify status notifies send no detail.
    """
    stored = {}

    async def naive_sink(step, success, detail=None):
        # Mirrors provisioner/web/api.py on_progress exactly.
        stored[step] = detail if detail else success

    spy = spy_handler_factory(supports_dual_bank=True, config_after_all_firmware=True)

    await spy.provision(**PROVISION_KWARGS, on_progress=naive_sink)

    assert stored.get("config_verify") == "unverified"
