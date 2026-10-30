#!/usr/bin/env python3
"""Set, show, or clear the time-boxed bench qualification override.

The override opens post-provision modes (AP, PTP) for one exact model and
firmware before the bench has recorded its transitions. It expires after at
most 24 hours. The provisioner deletes the file at the first check after the
expiry, so the matrix re-locks by itself.

Usage:
    sudo python scripts/qualification_override.py set --vendor tachyon \\
        --model TNA-303L-65 --firmware "1.15.1 rev 8541" --modes ptp \\
        --hours 4 --by isaac --reason "first PTP bench run"
    python scripts/qualification_override.py status
    sudo python scripts/qualification_override.py clear

Set ``PROVISIONER_QUALIFICATION_OVERRIDE`` to use a file other than
``/var/lib/provisioner/qualification-override.json``.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from provisioner import qualification  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    set_cmd = sub.add_parser("set", help="write an override")
    set_cmd.add_argument("--vendor", required=True)
    set_cmd.add_argument("--model", required=True)
    set_cmd.add_argument("--firmware", required=True)
    set_cmd.add_argument("--modes", required=True, help="comma-separated: ap, ptp")
    set_cmd.add_argument("--hours", type=float, required=True, help="at most 24")
    set_cmd.add_argument("--by", required=True, help="who sets the override")
    set_cmd.add_argument("--reason", default="")
    set_cmd.add_argument("--dry-run", action="store_true", help="validate and print, write nothing")
    sub.add_parser("status", help="show the active override")
    sub.add_parser("clear", help="remove the override now")
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args()
    if args.command == "set":
        modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]
        try:
            record = qualification.write_override(
                args.vendor, args.model, args.firmware, modes, args.by, args.hours, args.reason,
                dry_run=args.dry_run,
            )
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        print(("dry run, nothing written:\n" if args.dry_run else "") + json.dumps(record, indent=2))
        return 0
    if args.command == "status":
        record = qualification.active_override()
        print(json.dumps(record, indent=2) if record else "no active override")
        return 0
    print("removed" if qualification.clear_override("cleared by operator") else "no override")
    return 0


if __name__ == "__main__":
    sys.exit(main())
