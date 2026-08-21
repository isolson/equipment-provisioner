"""Snapshot store unit tests (R3, issue #116).

Redaction assertions in this file are the security core of the story: they
assert against the R0 design-doc redaction map (§3.3) — secret-classified
values never appear in redacted output or in log records. All secrets in
fixtures are obviously fake.
"""

import json
import logging
import os
import stat
import threading
from pathlib import Path

import pytest

from provisioner.config import Config
from provisioner.snapshot_store import (
    SCHEMA_VERSION,
    SnapshotNotFound,
    SnapshotSchemaMismatch,
    SnapshotStore,
    SnapshotStoreError,
    SnapshotUnreadable,
    redact_snapshot,
)

# Obviously fake secret sentinels. If any of these strings shows up in a
# redacted payload or a log record, the test MUST fail.
FAKE_PSK = "FAKE-TEST-PSK-abc123456"
FAKE_RAW_SECRET = "FAKE-RAW-ADMIN-HASH-$6$deadbeef"
FAKE_UNCLASSIFIED_SECRET = "FAKE-RADIUS-SECRET-not-real"
FAKE_SECURITY_MODE = "wpa2-psk-fake-value"

ALL_SECRET_SENTINELS = (
    FAKE_PSK,
    FAKE_RAW_SECRET,
    FAKE_UNCLASSIFIED_SECRET,
    FAKE_SECURITY_MODE,
)


def make_snapshot(**overrides):
    """A full schema-v1 snapshot document with fake secrets in every
    secret-classified position of the R0 map."""
    doc = {
        "schema_version": 1,
        "vendor": "tachyon",
        "model": "TNA-303L-65",
        "serial_number": "SN0000000",
        "mac_address": "AA:BB:CC:00:11:22",
        "hostname": "tw05-north",
        "firmware_at_capture": "1.12.3",
        "captured_at": "2026-08-21T14:03:22Z",
        "source": "bench-capture",
        "identity": {
            "wireless": {
                "ssid": "NORTH",
                "psk": FAKE_PSK,
                # Present in the schema but NOT classified public in §3.3:
                # must be dropped by the default-secret rule.
                "security_mode": FAKE_SECURITY_MODE,
            },
            "mgmt_ip": {
                "mode": "static",
                "address": "10.20.30.40",
                "prefix": 24,
                "gateway": "10.20.30.1",
                "vlan": 12,
            },
            "routing": {"mode": "ospf", "area": "0.0.0.0"},
            "ptp_role": "a",
            "ptp_link_id": "tw05-tw12",
            # A field no schema revision has classified: default-secret.
            "radius_secret": FAKE_UNCLASSIFIED_SECRET,
        },
        "raw": {
            "format": "tachyon-export-json",
            "encoding": "json",
            "content": {"system": {"users": [{"password": FAKE_RAW_SECRET}]}},
        },
    }
    doc.update(overrides)
    return doc


@pytest.fixture
def store(tmp_path):
    return SnapshotStore(str(tmp_path / "snapshots"))


def assert_no_secret_values(payload):
    """Assert no fake secret value appears anywhere in a JSON-serializable
    payload (the story's core security property)."""
    blob = json.dumps(payload)
    for sentinel in ALL_SECRET_SENTINELS:
        assert sentinel not in blob, "secret value leaked: %s" % sentinel


# ---------------------------------------------------------------------------
# Round-trip + storage


def test_round_trip_preserves_full_document(store):
    saved = store.save(make_snapshot())
    loaded = store.load_full(saved["id"])
    assert loaded["identity"]["wireless"]["psk"] == FAKE_PSK
    assert loaded["raw"]["content"]["system"]["users"][0]["password"] == FAKE_RAW_SECRET
    assert loaded["schema_version"] == SCHEMA_VERSION
    assert loaded["vendor"] == "tachyon"
    assert loaded["captured_at"] == "2026-08-21T14:03:22Z"


def test_files_and_directory_are_private(store):
    saved = store.save(make_snapshot())
    dir_mode = stat.S_IMODE(os.stat(str(store.base_path)).st_mode)
    file_mode = stat.S_IMODE(
        os.stat(str(store.base_path / (saved["id"] + ".json"))).st_mode
    )
    assert dir_mode == 0o700
    assert file_mode == 0o600


def test_save_requires_vendor_model_source(store):
    for missing in ("vendor", "model", "source"):
        doc = make_snapshot()
        del doc[missing]
        with pytest.raises(SnapshotStoreError):
            store.save(doc)


def test_save_synthesizes_captured_at_and_schema_version(store):
    doc = make_snapshot()
    del doc["schema_version"]
    del doc["captured_at"]
    saved = store.save(doc)
    assert saved["schema_version"] == SCHEMA_VERSION
    assert saved["captured_at"].endswith("Z")


def test_read_paths_never_create_the_directory(tmp_path):
    config = Config(data={"local_path": str(tmp_path / "repo")})
    store = SnapshotStore.from_config(config)
    assert store.base_path == tmp_path / "snapshots"
    result = store.list_redacted()
    assert result["snapshots"] == []
    assert not store.base_path.exists()


def test_from_config_honors_explicit_path_and_retention(tmp_path):
    config = Config(
        snapshots={
            "path": str(tmp_path / "elsewhere"),
            "max_per_unit": 2,
            "max_total": 7,
        }
    )
    store = SnapshotStore.from_config(config)
    assert store.base_path == tmp_path / "elsewhere"
    assert store.max_per_unit == 2
    assert store.max_total == 7


# ---------------------------------------------------------------------------
# IDs and concurrent capture (issue #116: no Date.now()-style collisions)


def test_id_is_vendor_serial_timestamp(store):
    saved = store.save(make_snapshot())
    assert saved["id"] == "tachyon-SN0000000-20260821T140322Z"


def test_id_falls_back_to_mac_without_separators(store):
    doc = make_snapshot(serial_number=None)
    saved = store.save(doc)
    assert saved["id"] == "tachyon-AABBCC001122-20260821T140322Z"


def test_same_unit_same_second_gets_unique_ids(store):
    first = store.save(make_snapshot())
    second = store.save(make_snapshot())
    assert first["id"] != second["id"]
    assert second["id"].startswith(first["id"])  # collision suffix


def test_six_port_concurrent_capture_unique_files(store):
    """Six ports capturing at the same second — all six must persist."""
    errors = []

    def capture(port):
        try:
            store.save(make_snapshot(serial_number="SN-PORT-%d" % port))
        except Exception as e:  # pragma: no cover - failure diagnostics
            errors.append(e)

    threads = [threading.Thread(target=capture, args=(port,)) for port in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(list(store.base_path.glob("*.json"))) == 6


def test_same_unit_concurrent_capture_no_collision(tmp_path):
    """Same unit, same second, six threads — collision suffixes keep every
    file distinct (no Date.now()-style overwrites)."""
    store = SnapshotStore(str(tmp_path / "snapshots"), max_per_unit=10)
    errors = []

    def capture():
        try:
            store.save(make_snapshot())
        except Exception as e:  # pragma: no cover - failure diagnostics
            errors.append(e)

    threads = [threading.Thread(target=capture) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(list(store.base_path.glob("*.json"))) == 6


def test_hostile_snapshot_id_is_rejected(store):
    store.save(make_snapshot())
    bad_ids = (
        "../../../etc/passwd", "..", ".hidden", "a/b", "",
        # Trailing newline: `$` would match before it (PR #129 review F2) —
        # fullmatch + \Z must reject it (filename + log-forging vector).
        "advnl\n", "abc\ndef", "abc\r",
    )
    for bad_id in bad_ids:
        with pytest.raises(SnapshotNotFound):
            store.get_redacted(bad_id)
        with pytest.raises(SnapshotNotFound):
            store.delete(bad_id)
    for bad_id in ("../escape", "advnl\n"):
        with pytest.raises(SnapshotStoreError):
            store.save(make_snapshot(id=bad_id))
    # No newline-named file may have been created.
    assert all("\n" not in p.name for p in store.base_path.iterdir())


# ---------------------------------------------------------------------------
# Redaction (R0 §3.3 map)


def test_redaction_public_metadata_passes_through():
    redacted = redact_snapshot(make_snapshot(id="tachyon-SN0000000-x"))
    for field in (
        "schema_version", "id", "vendor", "model", "serial_number",
        "mac_address", "hostname", "firmware_at_capture", "captured_at",
        "source",
    ):
        assert field in redacted
    assert redacted["serial_number"] == "SN0000000"


def test_redaction_psk_replaced_by_presence_and_length():
    redacted = redact_snapshot(make_snapshot())
    wireless = redacted["identity"]["wireless"]
    assert "psk" not in wireless
    assert wireless["psk_present"] is True
    assert wireless["psk_length"] == len(FAKE_PSK)
    assert_no_secret_values(redacted)


def test_redaction_psk_absent_reports_not_present():
    doc = make_snapshot()
    del doc["identity"]["wireless"]["psk"]
    wireless = redact_snapshot(doc)["identity"]["wireless"]
    assert wireless["psk_present"] is False
    assert "psk_length" not in wireless


def test_redaction_public_identity_fields_survive():
    redacted = redact_snapshot(make_snapshot())
    identity = redacted["identity"]
    assert identity["wireless"]["ssid"] == "NORTH"
    assert identity["mgmt_ip"] == {
        "mode": "static",
        "address": "10.20.30.40",
        "prefix": 24,
        "gateway": "10.20.30.1",
        "vlan": 12,
    }
    assert identity["routing"] == {"mode": "ospf", "area": "0.0.0.0"}
    assert identity["ptp_role"] == "a"
    assert identity["ptp_link_id"] == "tw05-tw12"


def test_redaction_default_secret_for_unclassified_identity_fields():
    """§3.3: any identity.* field not explicitly classified public is
    omitted — including schema-known-but-unclassified security_mode and a
    brand-new field no revision has seen."""
    redacted = redact_snapshot(make_snapshot())
    assert "security_mode" not in redacted["identity"]["wireless"]
    assert "radius_secret" not in redacted["identity"]
    assert "identity.wireless.security_mode" in redacted["redacted_fields"]
    assert "identity.radius_secret" in redacted["redacted_fields"]
    assert_no_secret_values(redacted)


def test_redaction_dotted_key_spoof_is_default_secret():
    """PR #129 review F1 regression — the reviewer's exact spoof corpus.

    Literal identity keys containing dots must never forge a public path:
    classification is structural (tuple components), so each of these is an
    unclassified single-component field and falls to default-secret."""
    doc = make_snapshot()
    doc["identity"] = {
        "mgmt_ip.password": "FAKE-LEAK-A",
        "routing.secret": "FAKE-LEAK-B",
        "wireless.ssid": "FAKE-LEAK-C",
    }
    redacted = redact_snapshot(doc)
    blob = json.dumps(redacted)
    for leaked in ("FAKE-LEAK-A", "FAKE-LEAK-B", "FAKE-LEAK-C"):
        assert leaked not in blob, "dotted-key spoof leaked: %s" % leaked
    assert redacted["identity"] == {}
    for name in (
        "identity.mgmt_ip.password",
        "identity.routing.secret",
        "identity.wireless.ssid",
    ):
        assert name in redacted["redacted_fields"]


def test_redaction_dotted_key_spoof_nested_variants():
    """Dotted-key spoofs nested inside real containers, plus the literal
    'wireless.psk' key — dropped with no misplaced presence marker."""
    doc = make_snapshot()
    doc["identity"]["wireless"]["ssid.spoof"] = "FAKE-LEAK-D"
    doc["identity"]["mgmt_ip"]["address.spoof"] = "FAKE-LEAK-E"
    doc["identity"]["wireless.psk"] = "FAKE-LEAK-F"
    doc["identity"]["wireless.ssid"] = {"nested": "FAKE-LEAK-G"}
    redacted = redact_snapshot(doc)
    blob = json.dumps(redacted)
    for leaked in ("FAKE-LEAK-D", "FAKE-LEAK-E", "FAKE-LEAK-F", "FAKE-LEAK-G"):
        assert leaked not in blob, "nested dotted-key spoof leaked: %s" % leaked
    # Real fields still classified correctly.
    assert redacted["identity"]["wireless"]["ssid"] == "NORTH"
    assert redacted["identity"]["mgmt_ip"]["address"] == "10.20.30.40"
    # No psk marker forged at the identity top level by the literal key.
    assert "psk_present" not in redacted["identity"]
    assert redacted["identity"]["wireless"]["psk_present"] is True
    for name in (
        "identity.wireless.ssid.spoof",
        "identity.mgmt_ip.address.spoof",
        "identity.wireless.psk",
        "identity.wireless.ssid",
    ):
        assert name in redacted["redacted_fields"]


def test_redaction_unknown_keys_inside_public_containers_default_secret():
    """Review F3: mgmt_ip/routing are enumerated key sets, not wildcard
    subtrees — an unknown key inside them is default-secret."""
    doc = make_snapshot()
    doc["identity"]["mgmt_ip"]["snmp_community"] = FAKE_UNCLASSIFIED_SECRET
    doc["identity"]["routing"]["auth_key"] = FAKE_UNCLASSIFIED_SECRET
    redacted = redact_snapshot(doc)
    assert "snmp_community" not in redacted["identity"]["mgmt_ip"]
    assert "auth_key" not in redacted["identity"]["routing"]
    assert "identity.mgmt_ip.snmp_community" in redacted["redacted_fields"]
    assert "identity.routing.auth_key" in redacted["redacted_fields"]
    # The schema-enumerated keys are unaffected.
    assert redacted["identity"]["mgmt_ip"]["vlan"] == 12
    assert redacted["identity"]["routing"]["area"] == "0.0.0.0"
    assert_no_secret_values(redacted)


def test_redaction_unknown_identity_container_dropped_wholesale():
    doc = make_snapshot()
    doc["identity"]["mystery_block"] = {"nested": {"secret": FAKE_UNCLASSIFIED_SECRET}}
    redacted = redact_snapshot(doc)
    assert "mystery_block" not in redacted["identity"]
    assert "identity.mystery_block" in redacted["redacted_fields"]
    assert_no_secret_values(redacted)


def test_redaction_raw_blob_never_present():
    redacted = redact_snapshot(make_snapshot())
    assert redacted["raw"] == {
        "content_present": True,
        "format": "tachyon-export-json",
        "encoding": "json",
    }
    assert "raw.content" in redacted["redacted_fields"]
    assert_no_secret_values(redacted)


def test_redaction_unknown_top_level_field_omitted():
    doc = make_snapshot()
    doc["future_field"] = FAKE_UNCLASSIFIED_SECRET
    redacted = redact_snapshot(doc)
    assert "future_field" not in redacted
    assert "future_field" in redacted["redacted_fields"]


def test_list_and_get_redacted_carry_no_secret_values(store):
    saved = store.save(make_snapshot())
    assert_no_secret_values(store.list_redacted())
    assert_no_secret_values(store.get_redacted(saved["id"]))


# ---------------------------------------------------------------------------
# Logs never carry secret values


def test_logs_never_contain_secret_values(store, caplog):
    with caplog.at_level(logging.DEBUG):
        saved = store.save(make_snapshot())
        # Force retention evictions (logged) and every read path.
        store.max_per_unit = 1
        store.save(make_snapshot())
        store.list_redacted()
        remaining = store.list_redacted()["snapshots"][0]["id"]
        store.get_redacted(remaining)
        store.delete(remaining)
        assert saved  # at least one save logged
    assert any("Retention eviction" in r.getMessage() for r in caplog.records)
    for record in caplog.records:
        message = record.getMessage()
        for sentinel in ALL_SECRET_SENTINELS:
            assert sentinel not in message, "secret value leaked into logs"


# ---------------------------------------------------------------------------
# Corrupt-file tolerance (never crash at boot)


def test_corrupt_files_are_skipped_with_warning_not_crash(store, caplog):
    good = store.save(make_snapshot())
    (store.base_path / "corrupt-garbage-1.json").write_text("{not json at all")
    (store.base_path / "corrupt-partial-2.json").write_text(
        '{"schema_version": 1, "vendor": "tach'
    )
    (store.base_path / "corrupt-notdict-3.json").write_text('["a", "list"]')

    with caplog.at_level(logging.WARNING):
        result = store.list_redacted()

    assert result["total"] == 1
    assert result["snapshots"][0]["id"] == good["id"]
    assert result["skipped_unreadable"] == 3
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("Skipping snapshot file" in m for m in warnings)


def test_get_corrupt_snapshot_raises_unreadable_but_delete_works(store):
    store.base_path.mkdir(parents=True, exist_ok=True)
    (store.base_path / "corrupt-file-1.json").write_text("{broken")
    with pytest.raises(SnapshotUnreadable):
        store.get_redacted("corrupt-file-1")
    store.delete("corrupt-file-1")
    with pytest.raises(SnapshotNotFound):
        store.delete("corrupt-file-1")


def test_boot_style_construction_with_bad_dir_contents_does_not_raise(tmp_path):
    base = tmp_path / "snapshots"
    base.mkdir()
    (base / "junk.json").write_text("\x00\x01 not json")
    store = SnapshotStore(str(base))
    assert store.list_redacted()["total"] == 0


# ---------------------------------------------------------------------------
# Schema-version policy


def test_save_refuses_newer_schema_version(store):
    with pytest.raises(SnapshotSchemaMismatch):
        store.save(make_snapshot(schema_version=SCHEMA_VERSION + 1))


def test_get_newer_schema_version_readable_error(store):
    saved = store.save(make_snapshot())
    path = store.base_path / (saved["id"] + ".json")
    doc = json.loads(path.read_text())
    doc["schema_version"] = SCHEMA_VERSION + 1
    path.write_text(json.dumps(doc))
    with pytest.raises(SnapshotSchemaMismatch) as excinfo:
        store.get_redacted(saved["id"])
    assert "newer than supported" in str(excinfo.value)
    # List skips it (with a warning) rather than failing.
    assert store.list_redacted()["total"] == 0
    # Manual delete still works regardless.
    store.delete(saved["id"])


def test_reader_ignores_unknown_fields_forward_compat(store):
    saved = store.save(make_snapshot())
    path = store.base_path / (saved["id"] + ".json")
    doc = json.loads(path.read_text())
    doc["added_by_future_minor_revision"] = "ok"
    path.write_text(json.dumps(doc))
    redacted = store.get_redacted(saved["id"])
    assert redacted["id"] == saved["id"]
    assert "added_by_future_minor_revision" not in redacted


# ---------------------------------------------------------------------------
# Retention


def test_per_unit_retention_keeps_newest(tmp_path, caplog):
    store = SnapshotStore(str(tmp_path / "snapshots"), max_per_unit=2)
    with caplog.at_level(logging.INFO):
        for hour in (10, 11, 12, 13):
            store.save(
                make_snapshot(captured_at="2026-08-21T%02d:00:00Z" % hour)
            )
    result = store.list_redacted()
    assert result["total"] == 2
    kept = [s["captured_at"] for s in result["snapshots"]]
    assert kept == ["2026-08-21T13:00:00Z", "2026-08-21T12:00:00Z"]
    evictions = [
        r.getMessage() for r in caplog.records
        if "Retention eviction" in r.getMessage()
    ]
    assert len(evictions) == 2
    assert any("per-unit cap" in m for m in evictions)


def test_per_unit_retention_does_not_touch_other_units(tmp_path):
    store = SnapshotStore(str(tmp_path / "snapshots"), max_per_unit=1)
    store.save(make_snapshot(serial_number="SN-AAA"))
    store.save(make_snapshot(serial_number="SN-BBB"))
    store.save(make_snapshot(serial_number="SN-AAA",
                             captured_at="2026-08-21T15:00:00Z"))
    result = store.list_redacted()
    serials = sorted(s["serial_number"] for s in result["snapshots"])
    assert serials == ["SN-AAA", "SN-BBB"]


def test_total_cap_evicts_oldest_across_units(tmp_path, caplog):
    store = SnapshotStore(str(tmp_path / "snapshots"), max_per_unit=10, max_total=3)
    with caplog.at_level(logging.INFO):
        for i, hour in enumerate((9, 10, 11, 12)):
            store.save(make_snapshot(
                serial_number="SN-%d" % i,
                captured_at="2026-08-21T%02d:00:00Z" % hour,
            ))
    result = store.list_redacted()
    assert result["total"] == 3
    assert all(
        s["captured_at"] != "2026-08-21T09:00:00Z" for s in result["snapshots"]
    )
    assert any("total cap" in r.getMessage() for r in caplog.records)


def test_manual_delete_regardless_of_retention(store):
    saved = store.save(make_snapshot())
    store.delete(saved["id"])
    with pytest.raises(SnapshotNotFound):
        store.get_redacted(saved["id"])


# ---------------------------------------------------------------------------
# Pagination and filters


def test_list_pagination_newest_first(tmp_path):
    store = SnapshotStore(str(tmp_path / "snapshots"), max_per_unit=100)
    for hour in range(5):
        store.save(make_snapshot(captured_at="2026-08-21T%02d:00:00Z" % hour))
    page1 = store.list_redacted(limit=2, offset=0)
    page2 = store.list_redacted(limit=2, offset=2)
    assert page1["total"] == 5
    assert [s["captured_at"] for s in page1["snapshots"]] == [
        "2026-08-21T04:00:00Z", "2026-08-21T03:00:00Z",
    ]
    assert [s["captured_at"] for s in page2["snapshots"]] == [
        "2026-08-21T02:00:00Z", "2026-08-21T01:00:00Z",
    ]


def test_list_filters(store):
    store.save(make_snapshot())
    store.save(make_snapshot(vendor="cambium", serial_number="SN-CAM",
                             mac_address="11:22:33:44:55:66"))
    assert store.list_redacted(vendor="cambium")["total"] == 1
    assert store.list_redacted(serial_number="sn0000000")["total"] == 1
    assert store.list_redacted(mac_address="aa-bb-cc-00-11-22")["total"] == 1
    assert store.list_redacted(vendor="ubiquiti")["total"] == 0
