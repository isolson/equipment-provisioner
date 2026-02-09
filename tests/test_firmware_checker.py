"""Tests for firmware checker source initialization behavior."""

import tempfile
from pathlib import Path

from provisioner.firmware import FirmwareManager
from provisioner.firmware_checker import FirmwareChecker


def test_checker_merges_missing_default_sources():
    """Older configs should pick up newly added default sources."""
    with tempfile.TemporaryDirectory() as temp_dir:
        manager = FirmwareManager(temp_dir)
        checker = FirmwareChecker(
            config={
                "enabled": True,
                "sources": {
                    "tachyon": {
                        "enabled": True,
                        "channel": "release",
                    },
                },
            },
            firmware_manager=manager,
            firmware_path=Path(temp_dir),
        )

    # Tachyon from explicit config + MikroTik from defaults.
    assert "tachyon" in checker._sources
    assert "mikrotik" in checker._sources
