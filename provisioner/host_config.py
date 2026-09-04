"""Edit credential values in the host ``config.yaml`` in place.

The file holds comments and hand formatting, so this module edits lines
inside the ``credentials.<vendor>`` block instead of dumping YAML. Values
are written as JSON strings (valid YAML scalars). Nothing here logs or
returns a value.
"""

import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

#: Credential keys the page may set. Everything else is refused.
EDITABLE_KEYS = ("username", "password", "backup_password", "wpa_key", "snmp_community")
_VENDOR_RE = re.compile(r"^(\s*)([a-z_]+):\s*(#.*)?$")
_KEY_RE = re.compile(r"^(\s*)([a-z_]+):")


def _vendor_blocks(lines: List[str]) -> Tuple[Optional[int], Dict[str, Tuple[int, int, int]]]:
    """Return ``(credentials indent, {vendor: (start, end, key_indent)})``.

    ``start`` is the index of the ``vendor:`` line, ``end`` the index after
    the block's last line, ``key_indent`` the indent of its keys.
    """
    cred_indent = None
    blocks = {}  # type: Dict[str, Tuple[int, int, int]]
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)credentials:\s*(#.*)?$", lines[i])
        if m and cred_indent is None:
            cred_indent = len(m.group(1))
            i += 1
            while i < len(lines):
                line = lines[i]
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    i += 1
                    continue
                vm = _VENDOR_RE.match(line)
                indent = len(line) - len(line.lstrip())
                if indent <= cred_indent:
                    break
                if vm and indent == cred_indent + 2:
                    vendor = vm.group(2)
                    start = i
                    i += 1
                    key_indent = cred_indent + 4
                    while i < len(lines):
                        kl = lines[i]
                        ks = kl.strip()
                        if ks and not ks.startswith("#"):
                            kind = len(kl) - len(kl.lstrip())
                            if kind <= cred_indent + 2:
                                break
                            key_indent = kind
                        i += 1
                    end = i
                    while end > start + 1 and not lines[end - 1].strip():
                        end -= 1
                    blocks[vendor] = (start, end, key_indent)
                    continue
                i += 1
            continue
        i += 1
    return cred_indent, blocks


def set_credential_values(path: Path, vendor: str, values: Mapping[str, str]) -> List[str]:
    """Set keys under ``credentials.<vendor>``; return the keys changed.

    Existing keys are replaced in place. Missing keys are appended to the
    vendor block. A missing vendor block is appended under ``credentials``.
    A backup ``config.yaml.bak-<utc>-credentials`` is written first and the
    file is left readable by root only.
    """
    if not re.match(r"^[a-z_]+$", vendor):
        raise ValueError("invalid vendor name")
    clean = {}  # type: Dict[str, str]
    for key, value in values.items():
        if key not in EDITABLE_KEYS:
            raise ValueError("credential key %s is not editable" % key)
        if value is None:
            continue
        clean[key] = str(value)
    if not clean:
        return []
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    cred_indent, blocks = _vendor_blocks(lines)
    if cred_indent is None:
        raise ValueError("config.yaml has no credentials block")
    changed = []  # type: List[str]
    if vendor in blocks:
        start, end, key_indent = blocks[vendor]
        block = lines[start + 1:end]
        seen = set()
        for offset, line in enumerate(block):
            km = _KEY_RE.match(line)
            if km and not line.strip().startswith("#") and km.group(2) in clean:
                key = km.group(2)
                block[offset] = "%s%s: %s" % (km.group(1), key, json.dumps(clean[key]))
                seen.add(key)
                changed.append(key)
        for key, value in clean.items():
            if key not in seen:
                block.append("%s%s: %s" % (" " * key_indent, key, json.dumps(value)))
                changed.append(key)
        lines[start + 1:end] = block
    else:
        insert_at = max([blk[1] for blk in blocks.values()] or [0])
        new_block = ["%s%s:" % (" " * (cred_indent + 2), vendor)]
        new_block += ["%s%s: %s" % (" " * (cred_indent + 4), key, json.dumps(value)) for key, value in clean.items()]
        lines[insert_at:insert_at] = new_block
        changed.extend(clean.keys())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(path.name + ".bak-%s-credentials" % stamp)
    shutil.copy2(str(path), str(backup))
    try:
        os.chmod(str(backup), 0o600)
    except OSError:
        pass
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass
    return changed
