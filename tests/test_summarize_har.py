"""The HAR summarizer prints operations, never secrets."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import summarize_har  # noqa: E402


def _har(tmp_path):
    def entry(method, url, params=None, text=None, mime="", status=200, body="", t="2026-09-02T19:06:05.000Z"):
        post = {}
        if params is not None:
            post = {"mimeType": mime, "params": params}
        if text is not None:
            post = {"mimeType": mime, "text": text}
        return {
            "startedDateTime": t,
            "request": {"method": method, "url": url, "headers": [], "postData": post},
            "response": {"status": status, "content": {"text": body}},
        }
    entries = [
        entry("POST", "https://169.254.1.1/cgi-bin/luci", [{"name": "username", "value": "admin"}, {"name": "password", "value": "SECRET-pw-123"}], mime="application/x-www-form-urlencoded"),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/set_param", [{"name": "changed_elements", "value": '{"device_props":{"admin_password":"SECRET-pw-123","wirelessInterfaceEncryptionKey":"SECRET-key"}}'}, {"name": "debug", "value": "true"}]),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/local_upload_image", [{"name": "image", "value": "", "fileName": "ePMP-AX-v5.11.1.img"}], mime="multipart/form-data"),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/get_upload_status", [{"name": "debug", "value": "true"}]),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/get_upload_status", [{"name": "debug", "value": "true"}]),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/get_upload_status", [{"name": "debug", "value": "true"}]),
        entry("GET", "https://169.254.1.1/js/cambium_sku.js"),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/get_param", [{"name": "act", "value": "config_regular"}], body=json.dumps({"device_props": {"cambiumCurrentuImageVersion": "5.11.1", "wirelessInterfaceEncryptionKey": "SECRET-key", "admin_password": "SECRET-pw-123"}})),
        entry("POST", "https://169.254.1.1/cgi-bin/luci/;stok=abcdef0123456789/admin/reset_to_def", [{"name": "mask", "value": "1"}, {"name": "debug", "value": "true"}]),
        entry("POST", "https://169.254.1.1/cgi.lua/config?token=TOKENVALUE", text=json.dumps({"system": {"users": [{"name": "root", "password": "SECRET-pw-123"}]}}), mime="application/json"),
        entry("POST", "https://telemetry.example/HandleLogMetric", text=json.dumps({"log": "SECRET-telemetry"}), mime="application/json"),
    ]
    path = tmp_path / "capture.har"
    path.write_text(json.dumps({"log": {"creator": {"name": "TestRecorder"}, "entries": entries}}))
    return path


def test_summary_lists_operations_and_masks_everything_sensitive(tmp_path):
    har = _har(tmp_path)
    out = tmp_path / "capture-summary.md"
    assert summarize_har.main(["summarize_har.py", str(har), "--out", str(out), "--title", "unit test", "--note", "did a thing"]) == 0
    text = out.read_text()
    assert "SECRET" not in text
    assert "abcdef0123456789" not in text
    assert "TOKENVALUE" not in text
    assert "/cgi-bin/luci/;stok=***/admin/set_param" in text
    assert "changed_elements" in text and "debug=true" in text
    assert "file field: image" in text
    assert "`/cgi-bin/luci/;stok=***/admin/get_upload_status` x2 more" in text
    assert "`cambiumCurrentuImageVersion` = `5.11.1`" in text
    assert "mask=1" in text
    assert "json:name,password,system,users" in text  # key names only
    assert "cambium_sku.js" not in text
    assert "- did a thing" in text
    assert "# Capture summary: unit test" in text
    # Browser telemetry to other hosts is omitted, and counted.
    assert "HandleLogMetric" not in text
    assert "Device host: `169.254.1.1`" in text
    assert "omitted: 1." in text


def test_default_output_sits_next_to_the_har(tmp_path):
    har = _har(tmp_path)
    assert summarize_har.main(["summarize_har.py", str(har)]) == 0
    assert (tmp_path / "capture-summary.md").is_file()


def test_every_committed_har_record_has_a_summary():
    import yaml

    for manifest in Path("bench-evidence").glob("*/*/*/manifest.yaml"):
        data = yaml.safe_load(manifest.read_text())
        raw = data.get("raw_files") or {}
        has_har = any(str(k).endswith(".har") for k in raw) or "har" in str(data.get("notes", "")).lower() or "har" in str(data.get("operations", "")).lower()
        summaries = list(manifest.parent.glob("*summary.md"))
        if has_har or "upgrade" in (data.get("operations") or []):
            assert summaries, "%s has a HAR but no capture summary" % manifest.parent
        for summary in summaries:
            body = summary.read_text()
            assert "## Request sequence" in body
            assert "## What the capture did" in body, summary
