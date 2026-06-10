"""Regression tests for the BASE default verify_config.

The default ``BaseHandler.verify_config`` returned ``True`` as soon as it could
reconnect to the device — confirming accessibility, not that any config was
applied. Handlers that don't override it (ubiquiti/tarana/mikrotik) therefore
reported "config verified" with zero evidence.

The fix (Wave 2) adds a polymorphic ``_read_back_config`` hook: the default
must NOT claim success when expected values were requested but the handler has
no way to read device state back.
"""

from provisioner.handlers.base import BaseHandler


async def test_default_verify_config_does_not_claim_success_without_readback(
    spy_handler_factory, fast_sleep
):
    """RED today: with expected_values but no read-back capability, the default
    verify_config must not return True (it should signal unverified / fail)."""
    spy = spy_handler_factory()  # SpyHandler has no _read_back_config override

    # Call the BASE implementation directly with the spy as ``self`` — the spy
    # overrides verify_config with a stub, so we exercise the real default.
    result = await BaseHandler.verify_config(spy, expected_values={"hostname": "AP-1"})

    assert result is not True


async def test_default_verify_config_fails_on_readback_mismatch(
    spy_handler_factory, fast_sleep
):
    """RED today: when a handler CAN read back and the value mismatches, the
    default must fail rather than pass on mere connectivity."""
    spy = spy_handler_factory()

    async def readback():
        return {"hostname": "WRONG"}

    # Give the spy a read-back capability the base default should consult.
    spy._read_back_config = readback

    result = await BaseHandler.verify_config(spy, expected_values={"hostname": "AP-1"})

    assert result is False
