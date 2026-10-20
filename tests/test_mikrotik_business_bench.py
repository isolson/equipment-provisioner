"""The bench tool renders from the handler-owned profile; it adds no policy copy."""
import importlib.util
from pathlib import Path

import pytest

from provisioner.handlers import mikrotik_business

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mikrotik_business_bench.py"
spec = importlib.util.spec_from_file_location("mikrotik_business_bench", str(SCRIPT))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


@pytest.mark.parametrize("mode", sorted(mikrotik_business.MANAGEMENT_IPS))
def test_render_matches_handler_profile(mode):
    text, checks, mgmt_ip = bench.render(mode, None)
    assert text == mikrotik_business.profile_text(mode)
    assert checks == mikrotik_business.check_expressions(mode)
    assert mgmt_ip == mikrotik_business.MANAGEMENT_IPS[mode]


def test_pin_poe_adds_one_line_and_one_check():
    base = mikrotik_business.profile_text("router")
    text, checks, _ = bench.render("router", "ether5")
    added = [line for line in text.splitlines() if line not in base.splitlines()]
    assert added == ['/interface ethernet poe set [find where name="ether5"] poe-out=auto-on']
    assert set(checks) - set(mikrotik_business.check_expressions("router")) == {"poe_ether5"}


def test_pin_poe_is_not_duplicated_for_sfp_router():
    text, _, _ = bench.render("router-sfp", "ether5")
    assert text == mikrotik_business.profile_text("router-sfp")


def test_password_is_never_a_cli_argument():
    parser_help = SCRIPT.read_text()
    assert "--password" not in parser_help
    assert "MIKROTIK_PASS" in parser_help
