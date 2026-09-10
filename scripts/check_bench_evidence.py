#!/usr/bin/env python3
"""Check the evidence set for one exact model and firmware.

The repository copy contains a manifest and redacted structure fixtures. The
bench copy contains those files plus the raw HAR and device backups. This
script prints names and sizes only. It never prints evidence contents.

Usage:
    python scripts/check_bench_evidence.py --vendor tachyon \
        --model TNA-303L-65 --firmware 1.15.1-rev-8541
    python scripts/check_bench_evidence.py --repo-only --vendor tachyon \
        --model TNA-303L-65 --firmware 1.15.1-rev-8541
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import yaml


RAW_FILES = (
    "upgrade.har",
    "config-apply.har",
    "no-config.device-backup.json",
    "known-good.device-backup.json",
)
COMBINED_HAR = "workflow.har"
OPTIONAL_RAW_FILES = ("reset.har",)
REPO_FILES = (
    "manifest.yaml",
    "no-config.structure.json",
    "known-good.structure.json",
)
#: A manifest may declare ``no_config_backup: missing`` while the exact
#: pre-first-apply backup is still outstanding. The record then needs no
#: ``no-config`` fixture, and the qualification matrix treats ``fresh->sm``
#: as not proven.
NO_CONFIG_MISSING = "missing"
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]*$")
CONFIG_ROLES = ("AP", "SM", "PTP")
ARTIFACT_PURPOSES = ("process-evidence", "hardware-validation")
#: Bench transitions that the qualification matrix reads.
TRANSITION_STATES = ("fresh", "sm", "ap", "ptp")
TRANSITION_RESULTS = ("success", "failure")


def slug(value: str) -> str:
    """Map a display value to the stable evidence directory component."""

    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")


def validate_component(name: str, value: str) -> Optional[str]:
    if not value or value in (".", "..") or not SAFE_COMPONENT.match(value):
        return "%s is not a safe evidence path component" % name
    return None


def evidence_dir(root: Path, vendor: str, model: str, firmware: str) -> Path:
    return root / slug(vendor.lower()) / slug(model) / slug(firmware)


def file_status(directory: Path, names: Iterable[str]) -> Tuple[List[str], List[str]]:
    present = []
    missing = []
    for name in names:
        path = directory / name
        if path.is_file():
            present.append("%s (%d bytes)" % (name, path.stat().st_size))
        else:
            missing.append(name)
    return present, missing


def check_private_permissions(path: Path) -> Optional[str]:
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        return "%s permissions cannot be checked: %s" % (path, exc)
    if mode & 0o077:
        return "%s is accessible by group or other users (mode %03o)" % (path, mode)
    return None


def check_json_fixture(path: Path) -> Optional[str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as exc:
        return "%s cannot be read as JSON: %s" % (path.name, exc)
    if not isinstance(value, (dict, list)):
        return "%s must contain a JSON object or array" % path.name
    return None


def check_manifest(path: Path) -> Optional[str]:
    """Require the captured upload role without exposing manifest values."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        return "%s cannot be read as YAML: %s" % (path.name, exc)
    if not isinstance(value, dict):
        return "%s must contain a YAML object" % path.name
    role = str(value.get("config_role", "")).upper()
    if role not in CONFIG_ROLES:
        return "%s must declare config_role as AP, SM, or PTP" % path.name
    purpose = str(value.get("artifact_purpose", "")).strip().lower()
    if purpose not in ARTIFACT_PURPOSES:
        return "%s must declare artifact_purpose" % path.name
    if value.get("reusable_template") is not False:
        return "%s must set reusable_template to false" % path.name
    if not str(value.get("canonical_template_status", "")).strip():
        return "%s must declare canonical_template_status" % path.name
    transitions = value.get("transitions", [])
    if not isinstance(transitions, list):
        return "%s transitions must be a list" % path.name
    for index, item in enumerate(transitions):
        if not isinstance(item, dict):
            return "%s transitions[%d] must be an object" % (path.name, index)
        source = str(item.get("from", "")).lower()
        target = str(item.get("to", "")).lower()
        result = str(item.get("result", "")).lower()
        if source not in TRANSITION_STATES or target not in TRANSITION_STATES:
            return "%s transitions[%d] must use from/to in %s" % (
                path.name, index, ", ".join(TRANSITION_STATES)
            )
        if result not in TRANSITION_RESULTS:
            return "%s transitions[%d] must record result success or failure" % (path.name, index)
    return None


def manifest_declares_missing_no_config(path: Path) -> bool:
    """Return whether the manifest declares the no-config backup as missing."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError):
        return False
    return isinstance(value, dict) and str(value.get("no_config_backup", "")).lower() == NO_CONFIG_MISSING


def required_repo_files(directory: Path) -> Tuple[str, ...]:
    if manifest_declares_missing_no_config(directory / "manifest.yaml"):
        return tuple(name for name in REPO_FILES if name != "no-config.structure.json")
    return REPO_FILES


def required_raw_files(directory: Path, manifest: Path) -> Tuple[str, ...]:
    if manifest_declares_missing_no_config(manifest):
        return tuple(name for name in RAW_FILES if name != "no-config.device-backup.json")
    return RAW_FILES


def check_raw_files(directory: Path, manifest: Optional[Path] = None) -> List[str]:
    """Require separate operation captures or one combined workflow capture."""
    problems = []
    manifest = manifest or (directory / "manifest.yaml")
    operation_files = RAW_FILES[:2]
    if not (directory / COMBINED_HAR).is_file():
        missing_operations = [name for name in operation_files if not (directory / name).is_file()]
        if missing_operations:
            problems.append("missing raw evidence: %s" % " or ".join(missing_operations))
    for name in required_raw_files(directory, manifest)[2:]:
        if not (directory / name).is_file():
            problems.append("missing raw evidence: %s" % name)
    return problems


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--all", action="store_true", help="check every committed evidence set")
    target.add_argument("--vendor", help="vendor for one exact model check")
    parser.add_argument("--model", help="model for one exact model check")
    parser.add_argument("--firmware", help="firmware for one exact model check")
    parser.add_argument(
        "--repo-root",
        default="bench-evidence",
        help="repository evidence root (default: bench-evidence)",
    )
    parser.add_argument(
        "--raw-root",
        default=os.environ.get(
            "PROVISIONER_BENCH_EVIDENCE_ROOT", "/var/lib/provisioner/bench-evidence"
        ),
        help="secure raw evidence root (default: environment or bench path)",
    )
    parser.add_argument(
        "--repo-only",
        action="store_true",
        help="check only the manifest and redacted fixtures in the checkout",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.all:
        return check_all(args)
    if not args.model or not args.firmware:
        print("bench evidence: --model and --firmware are required with --vendor", file=sys.stderr)
        return 2

    return check_one(args)


def check_one(args: argparse.Namespace) -> int:
    for name, value in (
        ("vendor", args.vendor),
        ("model", args.model),
        ("firmware", args.firmware),
    ):
        problem = validate_component(name, value)
        if problem:
            print("bench evidence: %s" % problem, file=sys.stderr)
            return 2

    repo_dir = evidence_dir(Path(args.repo_root), args.vendor, args.model, args.firmware)
    raw_dir = evidence_dir(Path(args.raw_root), args.vendor, args.model, args.firmware)
    problems = []

    if not repo_dir.is_dir():
        problems.append("repository evidence directory does not exist: %s" % repo_dir)
    else:
        _, missing = file_status(repo_dir, required_repo_files(repo_dir))
        if missing:
            problems.append("missing repository evidence: %s" % ", ".join(missing))
        manifest = repo_dir / "manifest.yaml"
        if manifest.is_file():
            problem = check_manifest(manifest)
            if problem:
                problems.append(problem)
        for name in ("no-config.structure.json", "known-good.structure.json"):
            path = repo_dir / name
            if path.is_file():
                problem = check_json_fixture(path)
                if problem:
                    problems.append(problem)

    if not args.repo_only:
        if not raw_dir.is_dir():
            problems.append("raw evidence directory does not exist: %s" % raw_dir)
        else:
            raw_root = Path(args.raw_root)
            for directory in (raw_root, raw_dir):
                problem = check_private_permissions(directory)
                if problem:
                    problems.append(problem)
            problems.extend(check_raw_files(raw_dir, repo_dir / "manifest.yaml"))
            for name in RAW_FILES + (COMBINED_HAR,) + OPTIONAL_RAW_FILES:
                path = raw_dir / name
                if path.is_file():
                    problem = check_private_permissions(path)
                    if problem:
                        problems.append(problem)

    print("model: %s / %s / %s" % (args.vendor, args.model, args.firmware))
    print("repository path: %s" % repo_dir)
    if not args.repo_only:
        print("raw path: %s" % raw_dir)
    if problems:
        for problem in problems:
            print("MISSING or INVALID: %s" % problem)
        return 1

    print("bench evidence: OK")
    return 0


def check_all(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    manifests = sorted(repo_root.glob("*/*/*/manifest.yaml"))
    if not manifests:
        print("bench evidence: no committed manifests")
        return 0

    problems = []
    for manifest in manifests:
        directory = manifest.parent
        _, missing = file_status(directory, required_repo_files(directory))
        if missing:
            problems.append("%s missing: %s" % (directory, ", ".join(missing)))
        problem = check_manifest(manifest)
        if problem:
            problems.append("%s: %s" % (directory, problem))
        for name in ("no-config.structure.json", "known-good.structure.json"):
            path = directory / name
            if path.is_file():
                problem = check_json_fixture(path)
                if problem:
                    problems.append("%s: %s" % (directory, problem))

    print("committed manifests: %d" % len(manifests))
    if problems:
        for problem in problems:
            print("MISSING or INVALID: %s" % problem)
        return 1
    print("bench evidence: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
