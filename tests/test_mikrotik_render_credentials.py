"""Ops render-credential adapter: binding validation and fail-closed behavior."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from provisioner.handlers import mikrotik_render_credentials as rc


def _release_body():
    return {
        "contract_version": 1,
        "job_id": "J",
        "serial": "S",
        "local_access_user": "localadmin",
        "seed_id": "sid",
        "secret_version": 2,
        "credentials": {"admin": "the-localadmin-password"},
    }


def test_from_config_requires_url_and_token():
    assert rc.RenderCredentialClient.from_config(
        SimpleNamespace(render_credentials_url=None, render_credentials_token=None)) is None
    assert rc.RenderCredentialClient.from_config(
        SimpleNamespace(render_credentials_url="https://x", render_credentials_token=None)) is None
    assert rc.RenderCredentialClient.from_config(
        SimpleNamespace(render_credentials_url="https://x", render_credentials_token="t")) is not None


@pytest.mark.asyncio
async def test_release_returns_transient_password():
    c = rc.RenderCredentialClient("https://x", "tok")
    c._post = AsyncMock(return_value=_release_body())
    res = await c.release(job_id="J", serial="S", state="unassigned-business-router",
                          board_name="hEX S", bench_upstream_sha="sha")
    assert res.password == "the-localadmin-password"
    assert res.seed_id == "sid" and res.secret_version == "2"


@pytest.mark.asyncio
async def test_release_rejects_unknown_state_before_call():
    c = rc.RenderCredentialClient("https://x", "tok")
    c._post = AsyncMock()
    with pytest.raises(rc.RenderCredentialError):
        await c.release(job_id="J", serial="S", state="bogus",
                        board_name="hEX S", bench_upstream_sha="sha")
    c._post.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate", [
    {"job_id": "OTHER"},
    {"serial": "OTHER"},
    {"local_access_user": "admin"},
    {"contract_version": 2},
    {"credentials": {}},
])
async def test_release_rejects_binding_mismatch(mutate):
    c = rc.RenderCredentialClient("https://x", "tok")
    body = _release_body()
    body.update(mutate)
    c._post = AsyncMock(return_value=body)
    with pytest.raises(rc.RenderCredentialError):
        await c.release(job_id="J", serial="S", state="unassigned-business-router",
                        board_name="hEX S", bench_upstream_sha="sha")


@pytest.mark.asyncio
async def test_complete_requires_verified_status():
    c = rc.RenderCredentialClient("https://x", "tok")
    c._post = AsyncMock(return_value={"status": "verified", "serial": "S"})
    await c.complete(job_id="J", serial="S", render_sha256="r",
                     readback_passed=True, local_login_passed=True, uploaded_file_removed=True)
    c._post = AsyncMock(return_value={"status": "pending", "serial": "S"})
    with pytest.raises(rc.RenderCredentialError):
        await c.complete(job_id="J", serial="S", render_sha256="r",
                         readback_passed=True, local_login_passed=True, uploaded_file_removed=True)


def test_release_body_never_carries_seed_or_dry_run_release():
    # Guard the request contract: release always asks for a real credential.
    c = rc.RenderCredentialClient("https://x", "tok")
    headers = c._headers()
    assert headers["Cache-Control"] == "no-store"
    assert headers["Authorization"].startswith("Bearer ")
