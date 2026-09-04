#!/usr/bin/env python3
"""Build a tracked baseline from a device export, reduced by the contract.

Keeps only the leaves the role may own (SM: fleet policy and role; AP/PTP
also mode action). Secrets, device defaults, identity, and unclassified
leaves are dropped, so the result passes ``scripts/check_templates.py``.
Writes a JSON file or a tar (config.json plus CONTROL copied from the
source tar). Prints leaf counts only.

Usage:
    python scripts/build_baseline.py --vendor tachyon --role SM \
        --source /secure/known-good.device-backup.tar \
        --out configs/templates/tachyon/TNA-303L-65/SM/default.tar
"""

import argparse
import io
import json
import sys
import tarfile
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from provisioner.config_templates import load_config_template  # noqa: E402
from provisioner.field_ownership import flatten, reduce_to_baseline  # noqa: E402
from provisioner.vendor_registry import spec_for  # noqa: E402


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv[1:])
    spec = spec_for(args.vendor)
    contract = getattr(spec.handler_cls, "FIELD_OWNERSHIP", None) if spec and spec.handler_cls else None
    if contract is None:
        raise SystemExit("vendor %s has no field ownership contract" % args.vendor)
    loaded = load_config_template(args.source)
    reduced = reduce_to_baseline(contract, loaded.config, args.role)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix == ".json":
        out.write_text(json.dumps(reduced, indent=2) + "\n")
    else:
        control = b""
        if loaded.source_type == "tar":
            with tarfile.open(args.source, "r:*") as src:
                member = next((m for m in src.getmembers() if Path(m.name).name == "CONTROL"), None)
                if member is not None:
                    handle = src.extractfile(member)
                    control = handle.read() if handle else b""
        with tarfile.open(str(out), "w") as tar:
            if control:
                info = tarfile.TarInfo("CONTROL"); info.size = len(control); tar.addfile(info, io.BytesIO(control))
            payload = json.dumps(reduced, indent=2).encode("utf-8")
            info = tarfile.TarInfo("config.json"); info.size = len(payload); tar.addfile(info, io.BytesIO(payload))
    print("wrote %s: %d leaves kept of %d" % (out, len(list(flatten(reduced))), len(list(flatten(loaded.config)))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
