import pytest

from provisioner.handlers.mikrotik_swos_lite import (
    MikrotikSwosLiteHandler,
    SwosMovedAddressError,
)

CREDS = {"username": "admin", "password": ""}


def test_swos_page_codec_preserves_device_format():
    assert MikrotikSwosLiteHandler._parse_page(
        "{i07:'4750454e3231',i15:[0x02,0x02,0x02],i09:0x040aa8c0}"
    ) == {"i07": "4750454e3231", "i15": [2, 2, 2], "i09": 0x040AA8C0}
    assert (
        MikrotikSwosLiteHandler._encode_fields([{"i01": 10, "i02": 7}, {"i01": 20, "i02": 7}])
        == "[{i01:0x0a,i02:0x07},{i01:0x14,i02:0x07}]"
    )
    assert MikrotikSwosLiteHandler._address_from_little_endian(0x040AA8C0) == "192.168.10.4"


@pytest.mark.asyncio
async def test_profile_writes_pages_in_order_and_reconnects_after_address_move(monkeypatch):
    handler = MikrotikSwosLiteHandler("192.168.88.1", CREDS, interface="enp3s0.1991")
    handler.business_switch_site = "abc"
    handler.business_switch_unit = 3
    fwd = {key: 0 for key in handler._FWD_FIELDS}
    fwd.update(
        {
            "i1a": [0, 0, 0],
            "i1d": [0, 0, 0],
            "i1e": [0, 0, 0],
            "i15": [1, 1, 1],
            "i17": [0, 0, 0],
            "i18": [1, 1, 1],
        }
    )
    sys_page = {key: 0 for key in handler._SYS_FIELDS}
    sys_page.update({"i05": "", "i09": 0x0158A8C0})
    pages = {
        "fwd.b": fwd,
        "snmp.b": {"i01": 1, "i02": "636f6d6d756e697479", "i03": "", "i04": ""},
        "sys.b": sys_page,
    }
    posts = []

    async def get_page(page):
        return dict(pages[page])

    async def post_page(page, fields):
        posts.append((page, fields))
        if page == "sys.b" and len([item for item in posts if item[0] == page]) == 1:
            raise SwosMovedAddressError("address moved")
        return 200, ""

    async def no_op():
        return None

    async def connected(_reason):
        return True

    monkeypatch.setattr(handler, "_get_page", get_page)
    monkeypatch.setattr(handler, "_post_page", post_page)
    monkeypatch.setattr(handler, "disconnect", no_op)
    monkeypatch.setattr(handler, "ensure_connected", connected)
    assert await handler.apply_config({})
    assert [page for page, _fields in posts] == ["vlan.b", "fwd.b", "snmp.b", "sys.b", "sys.b"]
    assert posts[0][1] == [
        {"i01": 10, "i02": 7},
        {"i01": 20, "i02": 7},
        {"i01": 40, "i02": 7},
        {"i01": 70, "i02": 7},
    ]
    assert posts[1][1]["i1f"] == 4
    assert posts[1][1]["i15"] == [2, 2, 2]
    assert posts[1][1]["i17"] == [0, 0, 0]
    assert posts[1][1]["i18"] == [10, 10, 10]
    assert posts[2][1]["i01"] == 0
    assert posts[3][1]["i1c"] == 0
    assert posts[3][1]["i1b"] == 10
    assert handler.ip == "192.168.10.4"
    assert posts[4][1]["i05"] == "74682e6162632e73773033"


@pytest.mark.asyncio
async def test_profile_verification_runs_all_nine_checks_twice(monkeypatch):
    handler = MikrotikSwosLiteHandler("192.168.10.4", CREDS, interface="enp3s0.1991")
    handler.business_switch_site = "abc"
    handler.business_switch_unit = 3
    pages = {
        "sys.b": {
            "i05": "74682e6162632e73773033",
            "i0a": 1,
            "i09": 0x040AA8C0,
            "i1b": 10,
            "i1c": 0,
        },
        "fwd.b": {"i1f": 4, "i15": [2, 2, 2], "i18": [10, 10, 10]},
        "snmp.b": {"i01": 0},
        "vlan.b": {
            "rows": [
                {"i01": 10, "i02": 7, "i03": 0},
                {"i01": 20, "i02": 7, "i03": 0},
                {"i01": 40, "i02": 7, "i03": 0},
                {"i01": 70, "i02": 7, "i03": 0},
            ]
        },
    }
    calls = []

    async def get_page(page):
        calls.append(page)
        return pages[page]

    async def connected(_reason):
        return True

    monkeypatch.setattr(handler, "_get_page", get_page)
    monkeypatch.setattr(handler, "ensure_connected", connected)
    assert await handler.verify_config({}) is True
    assert calls == ["sys.b", "fwd.b", "snmp.b", "vlan.b"] * 2
