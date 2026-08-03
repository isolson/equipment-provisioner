#!/usr/bin/env python3
"""Validate first-party documentation.

This gate checks the documentation facts that must stay synchronized with the
application. It is intentionally small and deterministic. A general STE
dictionary checker would produce false positives for vendor names, protocol
names, API paths, and shell commands.

Usage:
    python scripts/check_docs.py
"""

import os
import re
import sys
from typing import Iterable, List, Tuple
from urllib.parse import unquote


DOC_ROOTS = ("docs", "examples", "scripts")
DOC_SUFFIXES = (".md", ".html", ".txt")
LOCAL_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
INFORMAL_TERMS = (
    "etc.",
    "Just Works",
    "walk away",
    "happy path",
    "Gotcha",
    "gotcha",
)
SECRET_LITERALS = (
    "admin123",
    "admin/admin",
    "admin / admin",
    "admin / (blank)",
    "root / (blank)",
    "password=admin",
    "--password yourpassword",
)


def iter_docs() -> Iterable[str]:
    paths = ["AGENTS.md", "CHANGELOG.md", "CLAUDE.md", "README.md", "STANDARDS.md"]
    for root in DOC_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [name for name in dirs if name != ".git"]
            for name in names:
                if name.endswith(DOC_SUFFIXES):
                    paths.append(os.path.join(dirpath, name))
    return sorted(paths)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def check_local_links(path: str, text: str) -> List[Tuple[str, str]]:
    problems = []
    for raw_target in LOCAL_LINK_RE.findall(text):
        target = raw_target.strip().split()[0].strip("<>")
        target_path = unquote(target.split("#", 1)[0])
        if not target_path or target.startswith(("http://", "https://", "mailto:", "//")):
            continue
        candidate = os.path.normpath(os.path.join(os.path.dirname(path), target_path))
        if not os.path.exists(candidate):
            problems.append((path, "broken local link: %s" % target))
    return problems


def check_docs() -> List[Tuple[str, str]]:
    problems = []
    for path in iter_docs():
        if not os.path.exists(path):
            problems.append((path, "documentation file does not exist"))
            continue
        try:
            text = read_text(path)
        except (IOError, OSError, UnicodeError) as exc:
            problems.append((path, "could not read: %s" % exc))
            continue

        problems.extend(check_local_links(path, text))

        folded_text = text.casefold()
        for term in INFORMAL_TERMS:
            if term.casefold() in folded_text:
                problems.append((path, "informal or vague term: %r" % term))

        for literal in SECRET_LITERALS:
            if literal.casefold() in folded_text:
                problems.append((path, "credential literal or unsafe command example: %r" % literal))

    # These facts are defined by the current application and default switch
    # configuration. Keep the checks explicit so a stale operator document
    # fails before it reaches a production bench.
    facts = {
        "README.md": (
            ("/opt/provisioner/config/", "use /etc/provisioner and /var/lib/provisioner/repo"),
            ("/opt/provisioner/config/config.yaml", "runtime config is under /etc/provisioner"),
            ("BaseDeviceHandler", "the handler base class is BaseHandler"),
            ("1998", "the default deployment uses VLANs 1991-1996"),
        ),
        "docs/API.md": (
            ("/api/v1", "the mounted API prefix is /api"),
        ),
        "docs/label-pi.html": (
            ("1998", "the label must show VLANs 1991-1996"),
            ("port 1-8", "the default label has six provisioning ports"),
        ),
        "docs/label-switch.html": (
            ("port (1-8)", "the default switch has six provisioning ports"),
        ),
        "docs/BRANCHING.md": (
            ("serves `/ports`", "the health and port endpoints are /health and /api/ports"),
        ),
        "docs/TROUBLESHOOTING.md": (
            ("boot_wait_seconds", "the boot wait is controlled by the implementation"),
            ("systemctl status display-manager", "the kiosk uses the kiosk watchdog"),
            ("/etc/lightdm/", "the kiosk uses startx and Openbox"),
        ),
        "docs/plan-ap-config.md": (
            ("/apply-ap-config", "the mode endpoint is /apply-mode"),
        ),
        "docs/SCREENSHOTS.md": (
            ("Ports / Firmware / Files", "the screenshot guide must describe the current page headers"),
            ("Tarana device (purple badge)", "Tarana uses the orange vendor color"),
            ("Tachyon device (green badge)", "Tachyon uses the purple vendor color"),
        ),
        "scripts/README.md": (
            ("setup_switch.sh --rsc", "the switch script uses --config for a custom RouterOS file"),
        ),
    }
    for path, expected in facts.items():
        if not os.path.exists(path):
            continue
        text = read_text(path)
        for needle, explanation in expected:
            if needle in text:
                problems.append((path, "stale fact %r: %s" % (needle, explanation)))

    required_facts = {
        "docs/API.md": (
            ("device_type` — One of: `cambium`, `mikrotik`, `tachyon`, `tarana`, `ubiquiti`",
             "API device-type lists must include every supported vendor"),
        ),
        "scripts/README.md": (
            ("setup_switch.sh --config", "the switch instructions must use the current option name"),
        ),
    }
    for path, expected in required_facts.items():
        if not os.path.exists(path):
            continue
        text = read_text(path)
        for needle, explanation in expected:
            if needle not in text:
                problems.append((path, "missing current fact %r: %s" % (needle, explanation)))

    # The examples and implementation plan may document placeholders for the
    # mode-change flow, but both documents must state the rendering boundary.
    examples = read_text("examples/configs/README.md") if os.path.exists("examples/configs/README.md") else ""
    if "{{" in examples and ("mode_config.py" not in examples or "standard provisioning templates" not in examples):
        problems.append(("examples/configs/README.md", "mode-template placeholders lack a deep-merge boundary"))

    plan = read_text("docs/plan-ap-config.md") if os.path.exists("docs/plan-ap-config.md") else ""
    if "mode_config.py" not in plan or "deep merge" not in plan:
        problems.append(("docs/plan-ap-config.md", "must identify mode_config.py and the deep-merge boundary"))

    return problems


def main() -> int:
    problems = check_docs()
    if not problems:
        print("check_docs: OK — documentation links, safety examples, and project facts are consistent")
        return 0

    for path, problem in problems:
        print("%s  %s" % (path, problem))
    print("\ncheck_docs: FAILED — %d problem(s)" % len(problems), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
