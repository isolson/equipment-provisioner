#!/usr/bin/env python3
"""Write a redacted structure fixture (v2) from a raw device backup.

The fixture carries the document shape plus a ``values`` map. The map holds
only fields that the vendor handler's field ownership contract classifies as
``fleet_policy``, ``role``, or ``device_default`` and whose key does not look
dynamic (address, name, serial, MAC, identity, location). Secrets and
unclassified fields are never written. Every template value and every
handler table value must trace to one of these fixture paths.

Usage:
    python scripts/redact_bench_fixture.py --vendor cambium --model "ePMP 4518" \
        --firmware 5.11.1 --kind known-good --source /secure/known-good.device-backup.json

The fixture is written to ``bench-evidence/<vendor>/<model>/<firmware>/`` in
the repository unless ``--out`` names another directory. The script prints
field names and counts only.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from provisioner.config_templates import load_config_template  # noqa: E402
from provisioner.field_ownership import (  # noqa: E402
    Owner,
    classify,
    flatten,
    format_path,
    is_classified,
)
from provisioner.vendor_registry import spec_for  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_bench_evidence import evidence_dir  # noqa: E402

FIXTURE_VERSION = 2
VALUE_OWNERS = (Owner.FLEET_POLICY, Owner.ROLE, Owner.DEVICE_DEFAULT)
DYNAMIC_KEY_RE = re.compile(
    r"(?:ip|addr|gateway|hostname|name|ssid|frequency|serial|mac|identity|location|agentid|\bid$)",
    re.IGNORECASE,
)
KINDS = ("known-good", "no-config")


def _required_paths(config: Any) -> Dict[str, str]:
    """Return top-level and second-level container paths with their types."""
    paths = {}  # type: Dict[str, str]
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(value, dict):
                paths[key] = "object"
                for child, grand in value.items():
                    if isinstance(grand, dict):
                        paths["%s.%s" % (key, child)] = "object"
            elif isinstance(value, list):
                paths[key] = "array"
    return paths


def _values(contract, config: Any) -> Tuple[Dict[str, Any], List[str]]:
    device_fields = contract.device_fields(config)
    values = {}  # type: Dict[str, Any]
    skipped = []  # type: List[str]
    for path, value in flatten(device_fields):
        if not isinstance(value, (str, int, float, bool)) or value is None:
            continue
        display = format_path(path)
        owner = classify(contract, path)
        if owner not in VALUE_OWNERS or not is_classified(contract, path):
            continue
        # Fleet policy and role values are the shared baseline by definition.
        # The dynamic-key guard protects device defaults, which can carry a
        # unit's own address or identity.
        if owner is Owner.DEVICE_DEFAULT and any(
            isinstance(part, str) and DYNAMIC_KEY_RE.search(part) for part in path
        ):
            skipped.append(display)
            continue
        values[display] = value
    return values, skipped


def build_fixture(vendor: str, source: Path, kind: str) -> Dict[str, Any]:
    spec = spec_for(vendor)
    if spec is None or spec.handler_cls is None:
        raise SystemExit("no handler registered for vendor %s" % vendor)
    contract = getattr(spec.handler_cls, "FIELD_OWNERSHIP", None)
    if contract is None:
        raise SystemExit("vendor %s has no field ownership contract" % vendor)
    config = load_config_template(str(source)).config
    leaves = list(flatten(config))
    values, skipped = _values(contract, config)
    return {
        "fixture_version": FIXTURE_VERSION,
        "source": "secure %s device backup" % kind,
        "artifact_purpose": "process-evidence",
        "reusable_template": False,
        "identity_status": "secure source may contain device/site-specific values",
        "root_type": "object" if isinstance(config, dict) else "array",
        "top_level_keys": sorted(config.keys()) if isinstance(config, dict) else [],
        "leaf_count": len(leaves),
        "required_paths": _required_paths(config),
        "values_policy": "fleet_policy and role fields; device_default fields unless the key is dynamic",
        "values_skipped_dynamic": sorted(skipped),
        "values": dict(sorted(values.items())),
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--kind", required=True, choices=KINDS)
    parser.add_argument("--source", required=True, help="raw device backup (JSON or tar)")
    parser.add_argument("--out", help="destination directory (default: repo bench-evidence)")
    args = parser.parse_args(argv[1:])

    fixture = build_fixture(args.vendor, Path(args.source), args.kind)
    repo_root = Path(__file__).resolve().parent.parent / "bench-evidence"
    out_dir = Path(args.out) if args.out else evidence_dir(repo_root, args.vendor, args.model, args.firmware)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / ("%s.structure.json" % args.kind)
    out_path.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    print("wrote %s: %d leaves, %d values, %d dynamic keys skipped" % (
        out_path, fixture["leaf_count"], len(fixture["values"]), len(fixture["values_skipped_dynamic"])
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
