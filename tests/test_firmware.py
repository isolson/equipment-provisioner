"""Tests for firmware management module."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from provisioner.firmware import FirmwareManager, FirmwareInfo


class TestVersionExtraction:
    """Tests for version extraction from filenames."""

    def setup_method(self):
        """Create a temporary directory for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = FirmwareManager(self.temp_dir)

    def test_extract_standard_version(self):
        """Test extraction of standard semantic versions."""
        assert self.manager._extract_version_from_filename("firmware-v1.2.3.bin") == "1.2.3"
        assert self.manager._extract_version_from_filename("device_1.2.3.img") == "1.2.3"
        assert self.manager._extract_version_from_filename("routeros-7.13-arm.npk") == "7.13"
        assert self.manager._extract_version_from_filename("firmware-2.0.bin") == "2.0"

    def test_extract_tarana_version(self):
        """Test extraction of Tarana firmware versions.

        Tarana firmware files are named like: SYS.A3.R10.XXX.3.622.005.00.tbn
        The full dotted string (minus .tbn) IS the version for comparison.
        """
        filename = "SYS.A3.R10.XXX.3.622.005.00.tbn"
        expected = "SYS.A3.R10.XXX.3.622.005.00"
        assert self.manager._extract_version_from_filename(filename) == expected

        # Test another Tarana version
        filename2 = "SYS.A3.R10.XXX.3.611.002.00.tbn"
        expected2 = "SYS.A3.R10.XXX.3.611.002.00"
        assert self.manager._extract_version_from_filename(filename2) == expected2

    def test_extract_tachyon_version(self):
        """Test extraction of Tachyon firmware versions.

        Tachyon files are named like: tna-30x-1.12.3-r54970-xxx.bin
        Version should combine base version and revision: 1.12.3.54970
        """
        filename = "tna-30x-1.12.3-r54970-default.bin"
        expected = "1.12.3.54970"
        assert self.manager._extract_version_from_filename(filename) == expected

        # TNA-303L variant
        filename2 = "tna-303l-1.11.0-r52000-squashfs.bin"
        expected2 = "1.11.0.52000"
        assert self.manager._extract_version_from_filename(filename2) == expected2

        # TNS-100 subscriber
        filename3 = "tns-100-1.12.3-r54970-default.bin"
        expected3 = "1.12.3.54970"
        assert self.manager._extract_version_from_filename(filename3) == expected3

    def test_extract_unknown_format(self):
        """Test handling of unrecognized filename formats."""
        assert self.manager._extract_version_from_filename("random_file.bin") == "unknown"
        assert self.manager._extract_version_from_filename("no-version-here") == "unknown"


class TestVersionComparison:
    """Tests for firmware version comparison logic."""

    def setup_method(self):
        """Create a temporary directory for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = FirmwareManager(self.temp_dir)

    def test_compare_simple_versions(self):
        """Test comparison of simple semantic versions."""
        # Greater than
        assert self.manager._compare_versions("2.0.0", "1.0.0") == 1
        assert self.manager._compare_versions("1.1.0", "1.0.0") == 1
        assert self.manager._compare_versions("1.0.1", "1.0.0") == 1

        # Less than
        assert self.manager._compare_versions("1.0.0", "2.0.0") == -1
        assert self.manager._compare_versions("1.0.0", "1.1.0") == -1
        assert self.manager._compare_versions("1.0.0", "1.0.1") == -1

        # Equal
        assert self.manager._compare_versions("1.0.0", "1.0.0") == 0

    def test_compare_versions_with_prefix(self):
        """Test version comparison ignoring 'v' prefix."""
        assert self.manager._compare_versions("v1.0.0", "1.0.0") == 0
        assert self.manager._compare_versions("V2.0.0", "v1.0.0") == 1
        assert self.manager._compare_versions("1.0.0", "v2.0.0") == -1

    def test_compare_versions_different_lengths(self):
        """Test comparison of versions with different segment counts."""
        assert self.manager._compare_versions("1.0", "1.0.0") == 0
        assert self.manager._compare_versions("1.0.1", "1.0") == 1
        assert self.manager._compare_versions("1.0", "1.0.1") == -1

    def test_compare_tachyon_versions(self):
        """Test comparison of Tachyon versions with revision numbers."""
        # Higher revision should be newer
        assert self.manager._compare_versions("1.12.3.54970", "1.12.3.52000") == 1
        assert self.manager._compare_versions("1.12.3.52000", "1.12.3.54970") == -1

        # Higher base version wins regardless of revision
        assert self.manager._compare_versions("1.13.0.50000", "1.12.3.99999") == 1

    def test_compare_complex_versions(self):
        """Test comparison of complex version strings."""
        # Versions with underscores/dashes
        assert self.manager._compare_versions("1_0_0", "1.0.0") == 0
        assert self.manager._compare_versions("1-1-0", "1.0.0") == 1


class TestModelFirmwarePatterns:
    """Tests for model-to-firmware pattern matching."""

    def setup_method(self):
        """Create a temporary directory with firmware files."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = FirmwareManager(self.temp_dir)

    def test_cambium_epmp_ax_patterns(self):
        """Test Cambium ePMP AX series uses correct firmware patterns."""
        patterns = FirmwareManager.MODEL_FIRMWARE_PATTERNS

        # ePMP 4000 series should use epmp-ax firmware
        assert "epmp-ax" in patterns.get("epmp 4518", [])
        assert "epmp-ax" in patterns.get("epmp 4525", [])
        assert "epmp-ax" in patterns.get("epmp 4600", [])
        assert "epmp-ax" in patterns.get("epmp 4625", [])

    def test_cambium_force_300_patterns(self):
        """Test Cambium Force 300 series uses AC firmware patterns."""
        patterns = FirmwareManager.MODEL_FIRMWARE_PATTERNS

        assert "epmp-ac" in patterns.get("force 300-25", [])
        assert "epmp-ac" in patterns.get("force 300-19", [])
        assert "force300" in patterns.get("force 300-25", [])

    def test_tachyon_patterns(self):
        """Test Tachyon model patterns."""
        patterns = FirmwareManager.MODEL_FIRMWARE_PATTERNS

        # TNA-30x series
        assert "tna-30x" in patterns.get("tna-303x", [])
        assert "tna-30x" in patterns.get("tna-301", [])
        assert "tna-30x" in patterns.get("tna-302", [])

        # TNA-303L (long range) has separate firmware
        assert "tna-303l" in patterns.get("tna-303l", [])
        assert "tna-303l" in patterns.get("tna-303l-65", [])

        # TNS-100 subscriber
        assert "tns-100" in patterns.get("tns-100", [])

    def test_ubiquiti_wave_patterns(self):
        """Test Ubiquiti Wave model patterns.

        Wave devices split between two firmware types:
        - GMC (75ba): Wave-AP, Wave-Pro, Wave-AP-Micro, Wave-Pico
        - MGMP (02da): Wave-Nano, Wave-Micro, Wave-LR
        """
        patterns = FirmwareManager.MODEL_FIRMWARE_PATTERNS

        # GMC firmware devices
        assert "75ba-wave" in patterns.get("wave-pro", [])
        assert "75ba-wave" in patterns.get("wave-ap", [])
        assert "gmc" in patterns.get("wave-pico", [])

        # MGMP firmware devices
        assert "02da-wave" in patterns.get("wave-nano", [])
        assert "02da-wave" in patterns.get("wave-micro", [])
        assert "mgmp" in patterns.get("wave-lr", [])


class TestFirmwareFinding:
    """Tests for firmware file discovery."""

    def setup_method(self):
        """Create a temporary directory with firmware files."""
        self.temp_dir = tempfile.mkdtemp()
        self.firmware_path = Path(self.temp_dir)

    def test_find_firmware_by_convention_tachyon(self):
        """Test finding Tachyon firmware by naming convention."""
        # Create tachyon firmware directory
        tachyon_dir = self.firmware_path / "tachyon"
        tachyon_dir.mkdir(parents=True)

        # Create test firmware files
        (tachyon_dir / "tna-30x-1.11.0-r52000-default.bin").touch()
        (tachyon_dir / "tna-30x-1.12.3-r54970-default.bin").touch()

        manager = FirmwareManager(self.temp_dir)
        result = manager.get_firmware_file("tachyon", "tna-303x")

        assert result is not None
        assert "1.12.3" in result.version  # Should find the higher version

    def test_find_firmware_by_convention_wave(self):
        """Test finding Wave firmware by naming convention."""
        # Create ubiquiti firmware directory
        ubiquiti_dir = self.firmware_path / "ubiquiti"
        ubiquiti_dir.mkdir(parents=True)

        # Create test firmware files for different Wave variants
        (ubiquiti_dir / "75ba-wave-2.0.0.bin").touch()
        (ubiquiti_dir / "02da-wave-2.0.0.bin").touch()

        manager = FirmwareManager(self.temp_dir)

        # Wave-Nano should find 02da firmware
        result = manager.get_firmware_file("ubiquiti", "wave-nano")
        assert result is not None
        assert "02da" in result.filename.lower()

        # Wave-Pro should find 75ba firmware
        result = manager.get_firmware_file("ubiquiti", "wave-pro")
        assert result is not None
        assert "75ba" in result.filename.lower()

    def test_get_all_firmware_files(self):
        """Test getting all matching firmware files for retry logic."""
        # Create cambium firmware directory
        cambium_dir = self.firmware_path / "cambium"
        cambium_dir.mkdir(parents=True)

        # Create multiple versions
        (cambium_dir / "epmp-ax-4.8.0.bin").touch()
        (cambium_dir / "epmp-ax-4.8.1.bin").touch()
        (cambium_dir / "epmp-ax-4.7.0.bin").touch()

        manager = FirmwareManager(self.temp_dir)
        results = manager.get_all_firmware_files("cambium", "epmp 4525")

        assert len(results) == 3
        # Should be sorted by version, highest first
        assert "4.8.1" in results[0].version
        assert "4.8.0" in results[1].version
        assert "4.7.0" in results[2].version

    def test_firmware_not_found(self):
        """Test handling when no firmware is found."""
        manager = FirmwareManager(self.temp_dir)
        result = manager.get_firmware_file("nonexistent", None)
        assert result is None


class TestNeedsUpdate:
    """Tests for firmware update checking."""

    def setup_method(self):
        """Create a temporary directory with firmware files."""
        self.temp_dir = tempfile.mkdtemp()
        self.firmware_path = Path(self.temp_dir)

        # Create tachyon firmware directory with a file
        tachyon_dir = self.firmware_path / "tachyon"
        tachyon_dir.mkdir(parents=True)
        (tachyon_dir / "tna-30x-1.12.3-r54970-default.bin").touch()

        self.manager = FirmwareManager(self.temp_dir)

    def test_needs_update_when_older(self):
        """Test that update is needed when current version is older."""
        assert self.manager.needs_update("tachyon", "1.11.0.50000", "tna-303x") is True

    def test_no_update_when_current(self):
        """Test that no update is needed when versions match."""
        assert self.manager.needs_update("tachyon", "1.12.3.54970", "tna-303x") is False

    def test_no_update_when_newer(self):
        """Test that no update is needed when current is newer."""
        assert self.manager.needs_update("tachyon", "1.13.0.60000", "tna-303x") is False

    def test_no_update_when_no_firmware_available(self):
        """Test that no update is needed when firmware not found."""
        assert self.manager.needs_update("nonexistent", "1.0.0", None) is False


class TestChecksumVerification:
    """Tests for firmware checksum verification."""

    def setup_method(self):
        """Create a temporary directory for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = FirmwareManager(self.temp_dir)

    def test_verify_checksum_no_checksum_specified(self):
        """Test that verification passes when no checksum specified."""
        info = FirmwareInfo(
            device_type="test",
            model=None,
            version="1.0.0",
            filename="test.bin",
            path=Path("/nonexistent"),
            checksum=None,
        )
        assert self.manager.verify_checksum(info) is True

    def test_verify_checksum_file_not_found(self):
        """Test that verification fails when file doesn't exist."""
        info = FirmwareInfo(
            device_type="test",
            model=None,
            version="1.0.0",
            filename="test.bin",
            path=Path("/nonexistent/file.bin"),
            checksum="abc123",
        )
        assert self.manager.verify_checksum(info) is False

    def test_verify_checksum_correct(self):
        """Test verification with correct checksum."""
        # Create a test file
        test_file = Path(self.temp_dir) / "test.bin"
        test_file.write_bytes(b"test content")

        # Calculate expected checksum
        import hashlib
        expected = hashlib.sha256(b"test content").hexdigest()

        info = FirmwareInfo(
            device_type="test",
            model=None,
            version="1.0.0",
            filename="test.bin",
            path=test_file,
            checksum=expected,
        )
        assert self.manager.verify_checksum(info) is True

    def test_verify_checksum_incorrect(self):
        """Test verification with incorrect checksum."""
        # Create a test file
        test_file = Path(self.temp_dir) / "test.bin"
        test_file.write_bytes(b"test content")

        info = FirmwareInfo(
            device_type="test",
            model=None,
            version="1.0.0",
            filename="test.bin",
            path=test_file,
            checksum="wrong_checksum",
        )
        assert self.manager.verify_checksum(info) is False
