"""Reusable test doubles for the two outbound transports every handler uses.

Handlers reach a device exactly two ways, and both are interceptable without
touching production code:

  - ``aiohttp.ClientSession`` — faked by :class:`StubSession` /
    :class:`StubResponse` (promoted here from ``test_mikrotik_contract.py`` so
    there is a single source of truth; the project deliberately avoids an
    ``aioresponses``/``respx`` dependency).
  - ``curl`` via ``asyncio.create_subprocess_exec(...).communicate()`` — faked
    by :class:`FakeCurl`, which records every argv and returns a scripted
    ``(returncode, stdout, stderr)`` so a single test can give different
    answers to the POST and to the read-back GET.

These are wired into ``conftest.py`` as the ``stub_aiohttp`` and ``fake_curl``
fixtures.
"""

import json
from typing import Any, Callable, Dict, List, Optional

_UNSET = object()


# ---------------------------------------------------------------------------
# aiohttp stub
# ---------------------------------------------------------------------------


class StubResponse:
    """Stand-in for an aiohttp response used inside an ``async with`` block.

    ``body`` may be a raw string, or pass ``json_body`` to have ``.text()`` /
    ``.json()`` serialise a Python object.
    """

    def __init__(self, status: int = 200, body: str = "", json_body: Any = _UNSET):
        self.status = status
        self._body = body
        self._json = json_body

    async def text(self) -> str:
        if self._json is not _UNSET and not self._body:
            return json.dumps(self._json)
        return self._body

    async def json(self, content_type: Optional[str] = None) -> Any:
        if self._json is not _UNSET:
            return self._json
        return json.loads(self._body)

    async def __aenter__(self) -> "StubResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


# Router signature: (method, url, kwargs) -> Optional[StubResponse]
Router = Callable[[str, str, Dict[str, Any]], Optional[StubResponse]]


class StubSession:
    """Stand-in for ``aiohttp.ClientSession``.

    Records every call (``calls`` / ``last_call``) and returns a response from
    an optional ``router`` callback, falling back to ``default``. Works both as
    a context manager (``async with ClientSession() as s``) and as a long-lived
    session held on a handler (``self._session``).
    """

    def __init__(self, router: Optional[Router] = None, default: Optional[StubResponse] = None):
        self._router = router
        self._default = default if default is not None else StubResponse(200, "{}")
        self.calls: List[Dict[str, Any]] = []
        self.last_call: Optional[Dict[str, Any]] = None

    def _resolve(self, method: str, url: str, kwargs: Dict[str, Any]) -> StubResponse:
        self.last_call = {"method": method, "url": url}
        self.last_call.update(kwargs)
        self.calls.append(self.last_call)
        if self._router is not None:
            resp = self._router(method, url, kwargs)
            if resp is not None:
                return resp
        return self._default

    def request(self, method: str, url: str, **kwargs: Any) -> StubResponse:
        return self._resolve(method.upper(), url, kwargs)

    def get(self, url: str, **kwargs: Any) -> StubResponse:
        return self._resolve("GET", url, kwargs)

    def post(self, url: str, **kwargs: Any) -> StubResponse:
        return self._resolve("POST", url, kwargs)

    def put(self, url: str, **kwargs: Any) -> StubResponse:
        return self._resolve("PUT", url, kwargs)

    def delete(self, url: str, **kwargs: Any) -> StubResponse:
        return self._resolve("DELETE", url, kwargs)

    async def close(self) -> None:
        return None

    async def __aenter__(self) -> "StubSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


# ---------------------------------------------------------------------------
# curl (subprocess) stub
# ---------------------------------------------------------------------------


class _FakeProc:
    """Stand-in for the process returned by ``create_subprocess_exec``."""

    def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    # allow dict/list shorthand — serialise to JSON
    return json.dumps(value).encode("utf-8")


def curl_method(argv: List[str]) -> str:
    """Return the HTTP method from a curl argv (the value after ``-X``)."""
    if "-X" in argv:
        idx = argv.index("-X")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return "GET"


# Handler signature: (argv) -> (returncode, stdout, stderr) | (returncode, stdout)
CurlHandler = Callable[[List[str]], Any]


class FakeCurl:
    """Intercepts ``asyncio.create_subprocess_exec`` for curl-based paths.

    Register a handler with :meth:`set_handler` (receives the full argv and
    returns ``(returncode, stdout[, stderr])``) or use :meth:`route_by_method`
    for the common "different answer per HTTP method" case. ``stdout`` may be a
    str, bytes, or a JSON-serialisable object.
    """

    def __init__(self):
        self.calls: List[List[str]] = []
        self._handler: Optional[CurlHandler] = None

    def set_handler(self, fn: CurlHandler) -> "FakeCurl":
        self._handler = fn
        return self

    def route_by_method(self, mapping: Dict[str, Any]) -> "FakeCurl":
        def _handler(argv: List[str]):
            method = curl_method(argv)
            if method not in mapping:
                raise AssertionError(
                    "fake_curl has no response for method %s: %r" % (method, argv)
                )
            return mapping[method]

        self._handler = _handler
        return self

    async def __call__(self, *argv: Any, **kwargs: Any) -> _FakeProc:
        args = list(argv)
        self.calls.append(args)
        if self._handler is None:
            raise AssertionError(
                "fake_curl received an unexpected subprocess call: %r" % (args,)
            )
        result = self._handler(args)
        if len(result) == 3:
            rc, out, err = result
        else:
            rc, out = result
            err = b""
        return _FakeProc(rc, _to_bytes(out), _to_bytes(err))

    @property
    def methods(self) -> List[str]:
        """The HTTP method of each intercepted curl call, in order."""
        return [curl_method(argv) for argv in self.calls]
