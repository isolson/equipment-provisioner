"""Firmware management and update utilities."""

import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

import yaml

logger = logging.getLogger(__name__)


@dataclass
class FirmwareInfo:
    """Information about a firmware file."""
    device_type: str
    model: Optional[str]
    version: str
    filename: str
    path: Path
    checksum: Optional[str] = None
    release_notes: Optional[str] = None


class FirmwareManager:
    """Manages firmware files and version checking."""

    def __init__(self, firmware_path: str, manifest_path: Optional[str] = None):
        """Initialize firmware manager.

        Args:
            firmware_path: Base path to firmware directory.
            manifest_path: Optional path to manifest.yaml with firmware info.
        """
        self.firmware_path = Path(firmware_path)
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self._manifest: Dict[str, Any] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        """Load firmware manifest if available."""
        # Try to find manifest
        manifest_candidates = [
            self.manifest_path,
            self.firmware_path / "manifest.yaml",
            self.firmware_path.parent / "manifest.yaml",
        ]

        for path in manifest_candidates:
            if path and path.exists():
                with open(path, "r") as f:
                    self._manifest = yaml.safe_load(f) or {}
                logger.info(f"Loaded firmware manifest from {path}")
                return

        logger.warning("No firmware manifest found")

    def get_latest_version(self, device_type: str, model: Optional[str] = None) -> Optional[str]:
        """Get the latest firmware version for a device type.

        First checks manifest.yaml, then auto-detects from files in the firmware directory.

        Args:
            device_type: Device type (e.g., "mikrotik", "cambium").
            model: Optional specific model.

        Returns:
            Version string or None if not found.
        """
        # Try manifest first
        firmware_info = self._manifest.get("firmware", {}).get(device_type, {})
        logger.debug(f"get_latest_version: manifest firmware_info for {device_type} = {firmware_info}")

        if model and model in firmware_info:
            version = firmware_info[model].get("version")
            logger.info(f"get_latest_version: Found model {model} in manifest: {version}")
            return version
        elif "default" in firmware_info:
            version = firmware_info["default"].get("version")
            logger.info(f"get_latest_version: Found default in manifest: {version}")
            return version
        elif "version" in firmware_info:
            version = firmware_info["version"]
            logger.info(f"get_latest_version: Found version in manifest: {version}")
            return version

        # No manifest entry - auto-detect from files
        logger.info(f"get_latest_version: No manifest entry, auto-detecting from files")
        fw_info = self._find_firmware_by_convention(device_type, model)
        if fw_info:
            logger.info(f"get_latest_version: Auto-detected firmware {fw_info.filename} version {fw_info.version}")
            return fw_info.version

        logger.info(f"get_latest_version: No firmware found for {device_type}/{model}")
        return None

    def get_firmware_file(self, device_type: str, model: Optional[str] = None) -> Optional[FirmwareInfo]:
        """Get firmware file info for a device type.

        Args:
            device_type: Device type.
            model: Optional specific model.

        Returns:
            FirmwareInfo or None if not found.
        """
        logger.info(f"get_firmware_file: Looking for {device_type}/{model} in {self.firmware_path}")
        firmware_info = self._manifest.get("firmware", {}).get(device_type, {})

        # Determine which config to use
        if model and model in firmware_info:
            info = firmware_info[model]
        elif "default" in firmware_info:
            info = firmware_info["default"]
        elif "file" in firmware_info:
            info = firmware_info
        else:
            # Try to find firmware file by convention
            return self._find_firmware_by_convention(device_type, model)

        filename = info.get("file")
        if not filename:
            return self._find_firmware_by_convention(device_type, model)

        path = self.firmware_path / device_type / filename
        if not path.exists():
            logger.warning(f"Firmware file not found: {path}")
            return None

        return FirmwareInfo(
            device_type=device_type,
            model=model,
            version=info.get("version", "unknown"),
            filename=filename,
            path=path,
            checksum=info.get("checksum") or info.get("sha256"),
            release_notes=info.get("release_notes"),
        )

    # Model to firmware filename pattern mapping
    # Maps device models to the firmware filename patterns they accept
    MODEL_FIRMWARE_PATTERNS: Dict[str, list] = {
        # Cambium ePMP AX series (WiFi 6) - uses ePMP-ax firmware
        "epmp 4518": ["epmp-ax", "epmp_ax"],
        "epmp 4525": ["epmp-ax", "epmp_ax"],
        "epmp 4600": ["epmp-ax", "epmp_ax"],
        # Cambium Force 300 series - uses AC firmware
        "force 300-25": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-16": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-13": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300 csm": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        # Cambium ePMP 3000 series - uses ePMP-NonGPS or ePMP-GPS firmware
        "epmp 3000": ["epmp-nongps", "epmp-gps", "epmp3000"],
        "epmp 3000l": ["epmp-nongps", "epmp-gps", "epmp3000"],
        # Cambium ePMP 2000/1000 series
        "epmp 2000": ["epmp-nongps", "epmp2000"],
        "epmp 1000": ["epmp1000", "epmp-nongps"],
        # Tachyon TNA-30x series (standard) - uses tna-30x firmware
        "tna-303x": ["tna-30x", "tna30x"],
        "tna-301": ["tna-30x", "tna30x"],
        "tna-302": ["tna-30x", "tna30x"],
        # Tachyon TNA-303L series (long range) - uses tna-303l firmware
        "tna-303l": ["tna-303l", "tna303l"],
        "tna-303l-65": ["tna-303l", "tna303l"],
        # Tachyon TNS-100 series (subscriber) - uses tns-100 firmware
        "tns-100": ["tns-100", "tns100"],
    }

    def _find_firmware_by_convention(
        self,
        device_type: str,
        model: Optional[str] = None
    ) -> Optional[FirmwareInfo]:
        """Find firmware file by naming convention.

        Scans the device firmware directory and returns the file with the highest version.

        Args:
            device_type: Device type.
            model: Optional model.

        Returns:
            FirmwareInfo or None.
        """
        device_dir = self.firmware_path / device_type
        logger.info(f"Looking for firmware in {device_dir} for model={model}")
        if not device_dir.exists():
            logger.warning(f"Firmware directory does not exist: {device_dir}")
            return None

        # Common firmware file extensions
        firmware_extensions = {'.bin', '.npk', '.img', '.fw', '.tar', '.gz'}

        # Get firmware patterns for this model
        model_patterns = None
        if model:
            model_key = model.lower().replace("cambium ", "").strip()
            model_patterns = self.MODEL_FIRMWARE_PATTERNS.get(model_key)
            logger.info(f"Model key: '{model_key}', patterns: {model_patterns}")

        # Find all firmware files
        candidates = []
        files_in_dir = list(device_dir.iterdir())
        logger.info(f"Files in {device_dir}: {[f.name for f in files_in_dir]}")
        for f in files_in_dir:
            if f.is_file() and f.suffix.lower() in firmware_extensions:
                filename_lower = f.name.lower()
                # If model specified, check if it matches
                if model:
                    if model_patterns:
                        # Use pattern matching for known models
                        matches = [p for p in model_patterns if p in filename_lower]
                        if not matches:
                            logger.debug(f"Skipping {f.name}: no pattern match for {model_patterns}")
                            continue
                        logger.debug(f"File {f.name} matches patterns: {matches}")
                    elif model.lower() not in filename_lower:
                        # Fall back to direct model name matching
                        logger.debug(f"Skipping {f.name}: model {model.lower()} not in filename")
                        continue
                version = self._extract_version_from_filename(f.name)
                candidates.append((f, version))
                logger.debug(f"Candidate: {f.name} version={version}")

        if not candidates:
            return None

        # Sort by version (highest first), then by modification time
        def sort_key(item):
            path, version = item
            # Parse version for sorting
            version_parts = []
            for part in version.replace("-", ".").replace("_", ".").split("."):
                try:
                    version_parts.append(int(part))
                except ValueError:
                    version_parts.append(0)
            # Pad to ensure consistent comparison
            while len(version_parts) < 5:
                version_parts.append(0)
            return (version_parts, path.stat().st_mtime)

        candidates.sort(key=sort_key, reverse=True)
        best_path, best_version = candidates[0]

        return FirmwareInfo(
            device_type=device_type,
            model=model,
            version=best_version,
            filename=best_path.name,
            path=best_path,
        )

    def _extract_version_from_filename(self, filename: str) -> str:
        """Try to extract version from firmware filename.

        Args:
            filename: Firmware filename.

        Returns:
            Version string or "unknown".
        """
        import re

        # Tachyon firmware patterns:
        #   tna-30x-1.12.3-r54970-... (standard TNA-30x series)
        #   tna-303l-1.12.3-r54970-... (TNA-303L long range)
        #   tns-100-1.12.3-r54970-... (TNS-100 subscriber)
        # Extract version (1.12.3) and revision (54970) -> "1.12.3.54970"
        tachyon_pattern = r'tn[as]-\d+[a-z]?-(\d+\.\d+\.\d+)-r(\d+)'
        tachyon_match = re.search(tachyon_pattern, filename.lower())
        if tachyon_match:
            version = tachyon_match.group(1)
            revision = tachyon_match.group(2)
            result = f"{version}.{revision}"
            logger.debug(f"Extracted Tachyon version from {filename}: {result}")
            return result

        # Common patterns: firmware-v1.2.3.bin, device_1.2.3.img
        patterns = [
            r'[vV]?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
            r'[-_](\d+\.\d+(?:\.\d+)?)',
        ]

        for pattern in patterns:
            match = re.search(pattern, filename)
            if match:
                return match.group(1)

        return "unknown"

    def needs_update(
        self,
        device_type: str,
        current_version: str,
        model: Optional[str] = None
    ) -> bool:
        """Check if device needs firmware update.

        Args:
            device_type: Device type.
            current_version: Current firmware version.
            model: Optional model.

        Returns:
            True if update is available and newer.
        """
        latest = self.get_latest_version(device_type, model)
        logger.info(f"needs_update: device_type={device_type}, model={model}, current={current_version}, latest={latest}")
        if not latest:
            logger.info(f"needs_update: No latest version found for {device_type}/{model}")
            return False

        comparison = self._compare_versions(latest, current_version)
        logger.info(f"needs_update: Version comparison {latest} vs {current_version} = {comparison}")
        return comparison > 0

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings.

        Args:
            v1: First version.
            v2: Second version.

        Returns:
            1 if v1 > v2, -1 if v1 < v2, 0 if equal.
        """
        def normalize(v: str) -> list:
            # Remove common prefixes
            v = v.lower().lstrip("v").strip()
            # Split and convert to integers where possible
            parts = []
            for part in v.replace("-", ".").replace("_", ".").split("."):
                try:
                    parts.append(int(part))
                except ValueError:
                    parts.append(part)
            return parts

        v1_parts = normalize(v1)
        v2_parts = normalize(v2)

        # Pad shorter version
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))

        for p1, p2 in zip(v1_parts, v2_parts):
            if isinstance(p1, int) and isinstance(p2, int):
                if p1 > p2:
                    return 1
                elif p1 < p2:
                    return -1
            else:
                # String comparison
                s1, s2 = str(p1), str(p2)
                if s1 > s2:
                    return 1
                elif s1 < s2:
                    return -1

        return 0

    def verify_checksum(self, firmware_info: FirmwareInfo) -> bool:
        """Verify firmware file checksum.

        Args:
            firmware_info: Firmware info with expected checksum.

        Returns:
            True if checksum matches or no checksum specified.
        """
        if not firmware_info.checksum:
            return True

        if not firmware_info.path.exists():
            return False

        # Calculate SHA256
        sha256 = hashlib.sha256()
        with open(firmware_info.path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        calculated = sha256.hexdigest().lower()
        expected = firmware_info.checksum.lower()

        if calculated != expected:
            logger.error(f"Checksum mismatch for {firmware_info.filename}: "
                        f"expected {expected}, got {calculated}")
            return False

        return True
