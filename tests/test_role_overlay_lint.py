"""Lint: role overlays must never contain secrets or identity fields.

Design rule (docs/design-config-resolution.md §2.2 rule 2): role overlays
are for site-role settings (services, VLAN plans, SNMP toggles, routing
posture). Secrets and identity material (PSKs, passwords, keys, SNMP
communities) may only ever live in snapshots and job-scoped data-dir
artifacts — never anywhere under ``configs/templates/**``, which is
git-committed.

This test walks every shipped role overlay
(``configs/templates/*/roles/{role}/*.json``) and fails if any key path
looks sensitive. The name heuristic (borrowed from the handler-side
``_is_sensitive_path`` filter) is a guard, not the correctness mechanism —
overlay review must still check content. The tree ships no overlays today
(the role vocabulary is an open product decision); the walk is the
enforcement hook for when they land. All fixture values below are fakes.
"""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "configs" / "templates"

# Superset of the handler-side _is_sensitive_path tokens, plus the obvious
# wireless-secret spellings. Matched against key names, case-insensitive.
SENSITIVE_KEY_TOKENS = (
    "password",
    "passphrase",
    "private_key",
    "public_key",
    "community",
    "psk",
    "secret",
    "wpa_key",
    "encryption_key",
    "encryptionkey",
)


def find_sensitive_paths(value, path="$"):
    """Return every key path whose key name looks secret-shaped."""
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            key_lower = str(key).lower()
            if any(token in key_lower for token in SENSITIVE_KEY_TOKENS):
                found.append(child_path)
            found.extend(find_sensitive_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_sensitive_paths(child, f"{path}[{index}]"))
    return found


def shipped_role_overlays():
    if not TEMPLATES_DIR.exists():
        return []
    return sorted(TEMPLATES_DIR.glob("*/roles/*/*"))


def test_shipped_role_overlays_contain_no_sensitive_keys():
    offenders = {}
    for overlay in shipped_role_overlays():
        if not overlay.is_file():
            continue
        # Only JSON overlays are composable; anything else in a role dir is
        # itself a mistake (checked below).
        with open(overlay) as handle:
            config = json.load(handle)
        paths = find_sensitive_paths(config)
        if paths:
            offenders[str(overlay.relative_to(REPO_ROOT))] = paths

    assert not offenders, (
        "Role overlays must never carry secrets or identity fields "
        "(design §2.2 rule 2). Secret-shaped keys found: {}".format(offenders)
    )


def test_shipped_role_overlays_are_json_only():
    non_json = [
        str(p.relative_to(REPO_ROOT))
        for p in shipped_role_overlays()
        if p.is_file() and p.suffix.lower() != ".json"
    ]
    assert not non_json, (
        "Role overlays are dict deltas deep-merged over a JSON base; "
        "non-JSON files cannot be composed and will be silently ignored: "
        "{}".format(non_json)
    )


# ---------------------------------------------------------------------------
# Self-test the heuristic (fixture role content, fake values only)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "overlay,expect_flagged",
    [
        # Legitimate site-role content: services / SNMP toggles / VLAN plan.
        ({"services": {"snmp": {"enabled": True}}, "network": {"vlan": 12}}, False),
        # PSK embedded in a "complete list value" — the exact §2.2 hazard.
        ({"wireless": {"vaps": [{"ssid": "TOWER-A", "psk": "fake-not-real"}]}}, True),
        ({"system": {"users": [{"name": "x", "password": "fake-not-real"}]}}, True),
        ({"snmp": {"community": "fake-not-real"}}, True),
        ({"mgmt": {"encryptionKey": "fake-not-real"}}, True),
        ({"radius": {"shared_secret": "fake-not-real"}}, True),
    ],
)
def test_sensitive_key_heuristic(overlay, expect_flagged):
    assert bool(find_sensitive_paths(overlay)) == expect_flagged
