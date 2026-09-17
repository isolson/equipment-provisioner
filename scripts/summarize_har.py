#!/usr/bin/env python3
"""Write a redacted request summary next to a bench HAR capture.

The summary lists the device operations the capture performed: method, path,
form field names, allowlisted control values (``type``, ``mask``, ``act``,
``debug``, ``opts``), status codes, multipart file field names, and any
firmware version strings the device reported. It never prints credentials,
tokens, keys, bodies, or file contents. Session tokens in URLs are masked.

Usage:
    python scripts/summarize_har.py <capture.har> [--out capture-summary.md] \
        [--title "ePMP 4518 5.10.4 -> 5.11.1, reset, config import"] \
        [--note "one sentence per line of interpretation"]...

Commit the summary in the repository evidence record next to the manifest
and copy it beside the raw HAR in the secure bench directory
(docs/BENCH_EVIDENCE.md). Read the summary before touching an endpoint.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ALLOWED_VALUES = ("type", "mask", "act", "debug", "opts", "applyStatusNeeded")
STATIC_RE = re.compile(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map)$", re.IGNORECASE)
TOKEN_RE = re.compile(r"(;stok=|[?&](?:token|session|sid|auth)=)[^/&?]+", re.IGNORECASE)
VERSION_KEY_RE = re.compile(r"version|uimage|fwver|firmware|build", re.IGNORECASE)
VERSION_VALUE_RE = re.compile(r"^v?\d+\.\d+[\w.\- ]*$")


def _path(url: str) -> str:
    url = TOKEN_RE.sub(r"\1***", url)
    url = url.split("?", 1)[0]
    parts = url.split("/", 3)
    return "/" + (parts[3] if len(parts) > 3 else "")


def _params(entry: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    post = entry["request"].get("postData") or {}
    fields = []  # type: List[str]
    files = []  # type: List[str]
    for param in post.get("params") or []:
        name = str(param.get("name", ""))
        if param.get("fileName"):
            files.append(name)
        elif name in ALLOWED_VALUES:
            fields.append("%s=%s" % (name, str(param.get("value", ""))[:24]))
        else:
            fields.append(name)
    if not post.get("params") and post.get("text"):
        # JSON or urlencoded body without parsed params: key names only.
        keys = re.findall(r'"([A-Za-z_][A-Za-z0-9_.-]*)"\s*:', post["text"][:4000])
        if keys:
            fields.append("json:" + ",".join(sorted(set(keys))[:12]))
        else:
            fields.extend(sorted({k for k in re.findall(r"(?:^|&)([A-Za-z_][A-Za-z0-9_.-]*)=", post["text"][:4000])})[:12])
    mime = str(post.get("mimeType") or "")
    if not mime:
        for header in entry["request"].get("headers") or []:
            if header.get("name", "").lower() == "content-type":
                mime = str(header.get("value", ""))
    if mime.startswith("multipart/form-data") and not files:
        files.append("(multipart)")
    return fields, files


def _versions(entry: Dict[str, Any]) -> Dict[str, str]:
    text = entry["response"].get("content", {}).get("text") or ""
    if not text.startswith("{") or len(text) > 2_000_000:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    found = {}  # type: Dict[str, str]

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and VERSION_KEY_RE.search(str(key)) and VERSION_VALUE_RE.match(value):
                    found[str(key)] = value[:24]
                else:
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:20]:
                walk(item, depth + 1)

    walk(data)
    return found


def _host(url: str) -> str:
    return url.split("//", 1)[-1].split("/", 1)[0].lower()


def summarize(har_path: Path, host: Optional[str] = None) -> Tuple[List[str], Dict[str, str]]:
    with har_path.open("r", encoding="utf-8", errors="replace") as handle:
        har = json.load(handle)
    entries = har["log"]["entries"]
    # Keep device traffic only. Browser extensions and telemetry talk to other
    # hosts; the device host is the most frequent one unless given.
    counts = {}  # type: Dict[str, int]
    for entry in entries:
        counts[_host(entry["request"]["url"])] = counts.get(_host(entry["request"]["url"]), 0) + 1
    device_host = host or (max(counts, key=counts.get) if counts else "")
    omitted = sum(n for h, n in counts.items() if h != device_host)
    rows = []  # type: List[str]
    versions = {}  # type: Dict[str, str]
    last_key = None  # type: Optional[Tuple[str, str]]
    repeat = 0
    for entry in entries:
        request = entry["request"]
        if _host(request["url"]) != device_host:
            continue
        path = _path(request["url"])
        if STATIC_RE.search(path) or path in ("/", "/favicon.ico"):
            continue
        method = request["method"]
        status = entry["response"]["status"]
        fields, files = _params(entry)
        for key, value in _versions(entry).items():
            if versions.get(key) != value:
                versions[key] = value
                rows.append("| %s | device reports | `%s` = `%s` | |" % (entry["startedDateTime"][11:19], key, value))
        key = (method, path)
        if key == last_key:
            repeat += 1
            continue
        if repeat:
            rows.append("| | repeated | `%s` x%d more | |" % (last_key[1], repeat))
            repeat = 0
        last_key = key
        detail = ", ".join(fields) if fields else ""
        if files:
            detail = (detail + " " if detail else "") + "file field: " + ", ".join(files)
        rows.append("| %s | %s | `%s` %s | %s |" % (entry["startedDateTime"][11:19], method, path, detail, status))
    if repeat and last_key:
        rows.append("| | repeated | `%s` x%d more | |" % (last_key[1], repeat))
    header = [
        "| Time | Method | Path and form field names | Status |",
        "| --- | --- | --- | --- |",
    ]
    meta = {
        "device_host": device_host,
        "omitted_other_hosts": str(omitted),
        "entries": str(len(entries)),
        "span": "%s to %s" % (entries[0]["startedDateTime"][:19], entries[-1]["startedDateTime"][:19]) if entries else "",
        "browser": str((har["log"].get("creator") or {}).get("name", "")),
    }
    return header + rows, meta


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("har")
    parser.add_argument("--out", help="summary path (default: capture-summary.md next to the HAR)")
    parser.add_argument("--title", default="")
    parser.add_argument("--note", action="append", default=[], help="interpretation line (repeatable)")
    parser.add_argument("--host", help="device host to keep (default: the most frequent host)")
    args = parser.parse_args(argv[1:])
    har_path = Path(args.har)
    rows, meta = summarize(har_path, host=args.host)
    out = Path(args.out) if args.out else har_path.with_name("capture-summary.md")
    lines = [
        "# Capture summary: %s" % (args.title or har_path.name),
        "",
        "Source capture: `%s` (%s entries, %s, %s). Raw file stays in the secure bench directory." % (
            har_path.name, meta["entries"], meta["span"], meta["browser"] or "unknown recorder"),
        "",
        "Device host: `%s`. Requests to other hosts (browser telemetry, extensions) omitted: %s." % (
            meta["device_host"], meta["omitted_other_hosts"]),
        "",
        "This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.",
        "",
    ]
    if args.note:
        lines += ["## What the capture did", ""] + ["- %s" % note for note in args.note] + [""]
    lines += ["## Request sequence", ""] + rows + [""]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print("wrote %s (%d rows)" % (out, len(rows) - 2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
