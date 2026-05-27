"""Static checks for JS temporal-dead-zone bugs in templates.

Catches the pattern that broke /firmware?vendor=tachyon on 2026-05-26:
`let activeVendor = initialVendor()` ran before `const VENDORS = [...]`,
and `initialVendor()` referenced VENDORS, throwing a TDZ ReferenceError
before DOMContentLoaded was registered.  The page silently stuck at
"Loading...".
"""

import re
from pathlib import Path

import pytest

TEMPLATES = sorted(Path("provisioner/web/templates").glob("*.html"))


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_vendors_declared_before_activevendor(template):
    """If a template declares both `const VENDORS = [...]` and
    `let activeVendor = initialVendor()`, VENDORS must come first.

    Otherwise `initialVendor()` hits the TDZ and the page silently
    breaks for every user.
    """
    src = template.read_text()
    m_vendors = re.search(r"^\s*const\s+VENDORS\s*=", src, re.M)
    m_active = re.search(r"^\s*let\s+activeVendor\s*=\s*initialVendor\s*\(\)", src, re.M)
    if not (m_vendors and m_active):
        pytest.skip("template doesn't use both VENDORS and initialVendor()")
    assert m_vendors.start() < m_active.start(), (
        f"{template.name}: `const VENDORS` must be declared BEFORE "
        f"`let activeVendor = initialVendor()` — initialVendor() reads "
        f"VENDORS and will throw a TDZ ReferenceError otherwise, "
        f"silently breaking the page."
    )
