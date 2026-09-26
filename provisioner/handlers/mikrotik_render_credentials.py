"""Adapter for the Ops per-device render-credential contract.

This is the one place that knows the wire shape of the trusted Ops
render-credential service (sixtyops/treehouse-architecture:
``docs/api-reference/ops-render-credentials.md``). The MikroTik business flow
consumes per-device login credentials transiently through this adapter and
never persists them. When Ops finalizes a field, update the mapping here and
nowhere else.

Contract facts this adapter encodes:

- The provisioner is a pure consumer. It never derives a password and never
  receives seed material; custody of the admin seed is an OpenBao Transit key.
  Release returns only ``credentials["admin"]`` — the serial-bound
  ``localadmin`` password — for transient local render/apply.
- The endpoints are a *proposed* contract. Until Ops deploys them, this client
  fails closed: an unconfigured URL/token means no credential acceptance runs,
  and a non-2xx response raises without exposing a body that could carry a
  secret.
- RoMON and WireGuard are out of this contract's scope (remote-management,
  sixtyops #666); this adapter deals only with the ``localadmin`` login.
"""
import logging
from dataclasses import dataclass
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

CONTRACT_VERSION = 1
LOCAL_ACCESS_USER = "localadmin"
VALID_STATES = ("unassigned-business-router", "assigned-business-router")

RELEASE_PATH = "/provisioning/render-credentials/v1"
COMPLETE_PATH = "/provisioning/render-credentials/v1/complete"

# The service returns quickly; a per-device secret release must not hang the
# bench operation behind a slow or unreachable endpoint.
REQUEST_TIMEOUT = 15


@dataclass(frozen=True)
class ReleaseResult:
    """The transient outcome of a credential release.

    ``password`` is the ``localadmin`` password for immediate render/apply. It
    is never logged and never stored. ``seed_id``/``secret_version`` are
    non-secret identifiers echoed back on completion.
    """
    password: str
    seed_id: str
    secret_version: str


class RenderCredentialError(RuntimeError):
    """The render-credential service could not release/complete safely.

    The message never contains a credential value or a raw response body.
    """


class RenderCredentialClient:
    """Thin client for the Ops render-credential contract.

    Constructed only when both a base URL and a bearer token are configured;
    see :meth:`from_config`. Callers treat a ``None`` client as "credential
    acceptance is not configured" and skip it (dormant by default).
    """

    def __init__(self, base_url: str, token: str):
        self._base = base_url.rstrip("/")
        # Bound to an operator-approved bench job; never logged.
        self._token = token

    @classmethod
    def from_config(cls, mikrotik_config) -> Optional["RenderCredentialClient"]:
        """Build a client from ``MikrotikDeviceConfig``, or ``None``.

        Returns ``None`` (feature dormant) unless both the URL and the token
        are configured, so an un-provisioned bench never attempts a release.
        """
        url = getattr(mikrotik_config, "render_credentials_url", None)
        token = getattr(mikrotik_config, "render_credentials_token", None)
        if url and token:
            return cls(url, token)
        return None

    def _headers(self) -> dict:
        # Cache-Control: no-store mirrors the contract's handling rule so no
        # intermediary caches a credential-bearing response.
        return {
            "Authorization": "Bearer %s" % self._token,
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
        }

    async def release(
        self,
        *,
        job_id: str,
        serial: str,
        state: str,
        board_name: str,
        bench_upstream_sha: str,
    ) -> ReleaseResult:
        """Release the per-device ``localadmin`` password for this bench job.

        Raises :class:`RenderCredentialError` on any binding mismatch or
        non-success status. The returned password is transient — apply it and
        drop it; do not persist it.
        """
        if state not in VALID_STATES:
            raise RenderCredentialError("Unsupported render-credential state")
        body = {
            "job_id": job_id,
            "serial": serial,
            "state": state,
            "board_name": board_name,
            "bench_upstream_sha": bench_upstream_sha,
            "dry_run": False,
        }
        data = await self._post(RELEASE_PATH, body)

        # Validate response bindings before trusting any released value.
        if data.get("contract_version") != CONTRACT_VERSION:
            raise RenderCredentialError("Unexpected render-credential contract version")
        if data.get("job_id") != job_id or data.get("serial") != serial:
            raise RenderCredentialError("Render-credential response bindings did not match the request")
        if data.get("local_access_user") != LOCAL_ACCESS_USER:
            raise RenderCredentialError("Render-credential response named an unexpected local user")

        credentials = data.get("credentials") or {}
        password = credentials.get("admin")
        seed_id = data.get("seed_id")
        secret_version = data.get("secret_version")
        if not password or not seed_id or secret_version is None:
            raise RenderCredentialError("Render-credential release was incomplete")
        return ReleaseResult(password=password, seed_id=str(seed_id),
                             secret_version=str(secret_version))

    async def complete(
        self,
        *,
        job_id: str,
        serial: str,
        render_sha256: str,
        readback_passed: bool,
        local_login_passed: bool,
        uploaded_file_removed: bool,
    ) -> None:
        """Attest the verified apply so Ops marks the version installed.

        These are trusted-executor attestations, not proof from an arbitrary
        caller. Only call this after the device read-back, a successful
        ``localadmin`` login, and confirmed removal of the uploaded file.
        """
        body = {
            "job_id": job_id,
            "serial": serial,
            "render_sha256": render_sha256,
            "readback_passed": readback_passed,
            "local_login_passed": local_login_passed,
            "uploaded_file_removed": uploaded_file_removed,
        }
        data = await self._post(COMPLETE_PATH, body)
        if data.get("status") != "verified" or data.get("serial") != serial:
            raise RenderCredentialError("Render-credential completion was not verified")

    async def _post(self, path: str, body: dict) -> dict:
        url = self._base + path
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=body, headers=self._headers()) as resp:
                    # Never surface the raw body: a release response carries a
                    # credential. Log status only.
                    if resp.status < 200 or resp.status >= 300:
                        logger.error("render-credential POST %s returned %s", path, resp.status)
                        raise RenderCredentialError(
                            "Render-credential service returned status %s" % resp.status
                        )
                    return await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            # Message may include the URL but never a request/response body.
            raise RenderCredentialError("Render-credential service unreachable: %s" % type(exc).__name__)
