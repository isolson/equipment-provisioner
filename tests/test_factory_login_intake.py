import pytest

from provisioner import equipment_registry


class FakeResponse:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeSession:
    def __init__(self, response, calls):
        self.response = response
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


@pytest.mark.parametrize(
    ("status", "expected"),
    [(201, "stored"), (409, "already stored"), (503, "503")],
)
async def test_post_factory_login_sends_only_intake_fields(monkeypatch, status, expected):
    calls = []
    response = FakeResponse(status)
    monkeypatch.setattr(
        equipment_registry.aiohttp,
        "ClientSession",
        lambda **kwargs: FakeSession(response, calls),
    )

    result = await equipment_registry.post_factory_login(
        "https://ops.example/",
        "route-key",
        "UNIT-1",
        "router",
        "hEX S",
        "label-user",
        "label-password",
    )

    assert result == expected
    assert calls == [
        (
            "https://ops.example/internal/factory-logins",
            {
                "json": {
                    "serial": "UNIT-1",
                    "role": "router",
                    "model": "hEX S",
                    "username": "label-user",
                    "password": "label-password",
                },
                "headers": {"X-API-Key": "route-key"},
            },
        )
    ]


async def test_post_factory_login_does_not_request_without_configuration(monkeypatch):
    monkeypatch.setattr(
        equipment_registry.aiohttp,
        "ClientSession",
        lambda **kwargs: pytest.fail("intake must not be called without configuration"),
    )

    result = await equipment_registry.post_factory_login(
        "https://ops.example",
        None,
        "UNIT-1",
        "router",
        "hEX S",
        "label-user",
        "label-password",
    )

    assert result == "intake not configured"
