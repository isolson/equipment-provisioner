#!/usr/bin/env python3
"""Validate config templates.

Two failure classes:
  1. Invalid JSON in any ``configs/templates/**/*.json`` — a malformed template
     silently breaks provisioning for that model.
  2. ``{{placeholder}}`` syntax in a DEEP-MERGE template. Normal provisioning
     merges templates into the device config *as-is* with no substitution, so a
     stray ``{{hostname}}`` would be written to the device literally.

IMPORTANT nuance (this bit non-obvious): the AP/PTP "configure as" flow DOES
have a substitution engine (``provisioner/mode_config.py:_render_string``), and
the mode-change templates (``ap.json`` / ``ptp-a.json`` / ``ptp-b.json``)
legitimately use ``{{...}}``. Those basenames are allowlisted here. Everything
else (e.g. ``tns-100.json``, any future ``default.json``) must be placeholder-free.

Usage:
    python scripts/check_templates.py [TEMPLATE_DIR]   # defaults to configs/templates
"""

import json
import os
import re
import sys
import tarfile
from pathlib import Path
from typing import List, Tuple

DEFAULT_DIR = os.path.join("configs", "templates")
PLACEHOLDER_RE = re.compile(r"\{\{\s*[^}]+\s*\}\}")

# Templates consumed by mode_config.py's render engine, where {{...}} is valid.
# Keyed by basename so it survives per-vendor directory layout.
PLACEHOLDER_ALLOWED_BASENAMES = {"ap.json", "ptp-a.json", "ptp-b.json"}
SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:password|passphrase|psk|secret|token|private_key)(?:$|_)",
    re.IGNORECASE,
)


def _iter_template_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            if name == ".gitkeep":
                continue
            files.append(os.path.join(dirpath, name))
    return sorted(files)


def _contains_secret_key(value) -> bool:
    """Detect actual secret-shaped scalar fields, not boolean feature flags."""
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_KEY_RE.search(str(key)) and isinstance(child, (str, bytes)) and child:
                return True
            if _contains_secret_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_key(child) for child in value)
    return False


def _is_ptp_asset(path: str) -> bool:
    return "ptp" in {part.lower() for part in Path(path).parts}


def _check_tar(path: str, structured: bool) -> List[str]:
    problems: List[str] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            config_members = [member for member in members if Path(member.name).name == "config.json"]
            if not config_members:
                return ["TAR has no config.json"]
            for member in members:
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    problems.append("TAR contains an unsafe path: %s" % member.name)
            config_file = archive.extractfile(config_members[0])
            if config_file is None:
                return problems + ["TAR config.json cannot be read"]
            try:
                parsed = json.load(config_file)
            except (ValueError, UnicodeDecodeError) as exc:
                problems.append("invalid config.json: %s" % exc)
            else:
                if structured and not _is_ptp_asset(path) and _contains_secret_key(parsed):
                    problems.append("secret-shaped field is not allowed in a non-PTP asset")
    except (tarfile.TarError, OSError) as exc:
        problems.append("invalid TAR: %s" % exc)
    return problems


def check_templates(root: str) -> List[Tuple[str, str]]:
    problems: List[Tuple[str, str]] = []
    for path in _iter_template_files(root):
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()

        if base.lower().endswith((".tar", ".tar.gz", ".tgz")):
            for problem in _check_tar(path, structured=True):
                problems.append((path, problem))
            continue

        try:
            with open(path, "r") as handle:
                text = handle.read()
        except (IOError, OSError) as exc:
            problems.append((path, "could not read: %s" % exc))
            continue

        # 1. JSON/TAR validity
        if ext == ".json":
            try:
                parsed = json.loads(text)
            except ValueError as exc:
                problems.append((path, "invalid JSON: %s" % exc))
                # still fall through to placeholder check on the raw text
            else:
                if not _is_ptp_asset(path) and _contains_secret_key(parsed):
                    problems.append((path, "secret-shaped field is not allowed in a non-PTP asset"))

        # 2. placeholder syntax, unless this is an allowlisted mode template
        if base not in PLACEHOLDER_ALLOWED_BASENAMES:
            match = PLACEHOLDER_RE.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                problems.append((
                    path,
                    "line %d: '%s' — {{placeholder}} not allowed in a deep-merge "
                    "template (no substitution engine on this path)" % (line, match.group(0)),
                ))

    return problems


def main(argv: List[str]) -> int:
    root = argv[1] if len(argv) > 1 else DEFAULT_DIR
    if not os.path.isdir(root):
        print("check_templates: no template dir at %s (nothing to check)" % root)
        return 0

    problems = check_templates(root)
    if not problems:
        print("check_templates: OK — all templates valid")
        return 0

    for path, problem in problems:
        print("%s  %s" % (path, problem))
    print("\ncheck_templates: FAILED — %d problem(s)" % len(problems), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
