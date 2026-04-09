"""Helpers for first-run readiness checks and setup-bundle import."""

from __future__ import annotations

import json
import shutil
import socket
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, Callable, Dict, Iterable, List, Optional


STATUS_PRIORITY = {
    "ready": 0,
    "warning": 1,
    "missing": 2,
    "error": 3,
}

SUPPORTED_DEVICE_TYPES = ("cambium", "mikrotik", "tachyon", "tarana", "ubiquiti")
ROOT_BUNDLE_NAMES = {
    "configs",
    "firmware",
    "credentials.json",
    "manifest.yaml",
    "config.yaml",
    "provisioner.env",
    "settings",
}
IGNORED_BUNDLE_PREFIXES = ("__MACOSX",)


def _is_placeholder_secret(value: Optional[str]) -> bool:
    if value is None:
        return True
    stripped = value.strip()
    if not stripped:
        return True
    return stripped.startswith("your_") or stripped.startswith("${")


def _split_ros_list(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    text = str(value).strip()
    if not text:
        return set()
    return {item.strip() for item in text.split(",") if item.strip()}


def _status_from_checks(checks: List[Dict[str, Any]]) -> str:
    if not checks:
        return "ready"
    return max(checks, key=lambda item: STATUS_PRIORITY.get(item["status"], 0))["status"]


def _management_interface_name(config: Any) -> Optional[str]:
    management = getattr(getattr(config, "network", None), "management", None)
    if not management or not getattr(management, "enabled", False):
        return None
    interface = getattr(getattr(config, "network", None), "interface", "eth0")
    vlan = getattr(management, "vlan", None)
    if vlan is None:
        return None
    return f"{interface}.{vlan}"


def _interface_exists(interface_name: str) -> bool:
    return Path("/sys/class/net") .joinpath(interface_name).exists()


def _read_primary_credentials(config: Any) -> List[Dict[str, Any]]:
    defaults = {
        "cambium": "admin/admin",
        "mikrotik": "admin/(empty until switch password is set)",
        "tachyon": "root/admin",
        "tarana": "admin/(set your fleet password)",
        "ubiquiti": "ubnt/ubnt",
    }

    result = []
    for device_type in SUPPORTED_DEVICE_TYPES:
        creds = getattr(getattr(config, "credentials", None), device_type, None)
        password = getattr(creds, "password", "")
        status = "ready"
        summary = "Configured"

        if _is_placeholder_secret(password):
            status = "warning"
            summary = "Missing or placeholder"
        elif device_type in {"cambium", "tachyon", "ubiquiti"} and password in {"admin", "ubnt"}:
            status = "warning"
            summary = "Still using factory default"

        result.append(
            {
                "device_type": device_type,
                "username": getattr(creds, "username", "admin"),
                "has_password": bool(password),
                "status": status,
                "summary": summary,
                "recommended": defaults[device_type],
            }
        )

    return result


def _template_requirements(config: Any) -> Dict[str, Dict[str, Any]]:
    requirements = {
        "cambium": {"required": True, "modes": ["default", "ap", "ptp-a", "ptp-b"]},
        "tachyon": {"required": True, "modes": ["default", "ap", "ptp-a", "ptp-b"]},
        "tarana": {
            "required": bool(getattr(getattr(config, "features", None), "apply_config_tarana", False)),
            "modes": ["default"],
        },
        "ubiquiti": {
            "required": bool(getattr(getattr(config, "features", None), "apply_config_ubiquiti", False)),
            "modes": ["default"],
        },
    }
    return requirements


def _existing_template_modes(device_dir: Path) -> Dict[str, List[str]]:
    matches: Dict[str, List[str]] = {}
    if not device_dir.exists():
        return matches

    for file_path in sorted(p for p in device_dir.iterdir() if p.is_file()):
        stem = file_path.name
        for prefix in ("default", "ap", "ptp-a", "ptp-b"):
            if stem.startswith(prefix):
                matches.setdefault(prefix, []).append(file_path.name)
    return matches


def _build_template_check(config: Any, data_path: Path) -> Dict[str, Any]:
    templates_root = data_path / "configs" / "templates"
    requirements = _template_requirements(config)
    device_checks = []
    missing_required = []

    for device_type, info in requirements.items():
        existing = _existing_template_modes(templates_root / device_type)
        missing_modes = [mode for mode in info["modes"] if mode not in existing]
        required_default_missing = info["required"] and "default" not in existing

        status = "ready"
        summary = "Templates present"
        if required_default_missing:
            status = "missing"
            summary = "Missing required default template"
            missing_required.append(device_type)
        elif not existing:
            status = "warning"
            summary = "No templates uploaded yet"
        elif missing_modes:
            status = "warning"
            summary = f"Missing mode templates: {', '.join(missing_modes)}"

        device_checks.append(
            {
                "device_type": device_type,
                "required": info["required"],
                "status": status,
                "summary": summary,
                "existing": existing,
                "missing_modes": missing_modes,
            }
        )

    status = "ready"
    summary = "Default provisioning templates are in place."
    if missing_required:
        status = "missing"
        summary = "Upload a default template for each required device type."
    elif any(item["status"] == "warning" for item in device_checks):
        status = "warning"
        summary = "Optional AP/PTP templates are still missing for some device types."

    return {
        "id": "config_templates",
        "title": "Config templates",
        "status": status,
        "summary": summary,
        "details": device_checks,
    }


def _build_firmware_check(data_path: Path) -> Dict[str, Any]:
    firmware_root = data_path / "firmware"
    per_vendor = []
    missing_required = []

    for device_type in SUPPORTED_DEVICE_TYPES:
        device_dir = firmware_root / device_type
        files = sorted(p.name for p in device_dir.iterdir() if p.is_file()) if device_dir.exists() else []
        status = "ready" if files else "warning"
        summary = f"{len(files)} file(s)"

        if device_type == "mikrotik" and not files:
            status = "missing"
            summary = "Required for Netinstall and recovery"
            missing_required.append(device_type)

        per_vendor.append(
            {
                "device_type": device_type,
                "status": status,
                "summary": summary,
                "files": files[:10],
                "count": len(files),
            }
        )

    status = "ready"
    summary = "Local firmware inventory is ready."
    if missing_required:
        status = "missing"
        summary = "Add at least one RouterOS package for MikroTik Netinstall."
    elif any(item["count"] == 0 for item in per_vendor):
        status = "warning"
        summary = "Some vendors still rely on WAN-time firmware downloads."

    return {
        "id": "firmware_inventory",
        "title": "Firmware inventory",
        "status": status,
        "summary": summary,
        "details": per_vendor,
    }


def _build_credentials_check(config: Any, data_path: Path) -> Dict[str, Any]:
    primary = _read_primary_credentials(config)
    custom_path = data_path / "credentials.json"
    custom_credentials: Dict[str, Any] = {}
    if custom_path.exists():
        try:
            import json

            with open(custom_path) as handle:
                custom_credentials = json.load(handle) or {}
        except Exception:
            custom_credentials = {}

    custom_counts = {
        device_type: len(custom_credentials.get(device_type, []))
        for device_type in SUPPORTED_DEVICE_TYPES
    }

    status = "ready"
    summary = "Primary fleet passwords are configured."
    if any(item["status"] != "ready" for item in primary):
        status = "warning"
        summary = "One or more device types still use placeholders or factory defaults."

    return {
        "id": "credentials",
        "title": "Credentials",
        "status": status,
        "summary": summary,
        "details": primary,
        "custom_counts": custom_counts,
    }


def _tcp_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_mikrotik_switch(config: Any) -> Dict[str, Any]:
    """Inspect the provisioning switch, preferring RouterOS API when available."""
    management = getattr(getattr(config, "network", None), "management", None)
    switch_ip = getattr(management, "switch_ip", None) or "192.168.88.1"
    configured_password = getattr(getattr(config.credentials, "mikrotik", None), "password", "")
    password_candidates = []
    for password in (configured_password, ""):
        if password not in password_candidates:
            password_candidates.append(password)

    result: Dict[str, Any] = {
        "reachable": False,
        "mode": "absent",
        "host": switch_ip,
        "identity": None,
        "board_name": None,
        "version": None,
        "api_reachable": _tcp_connect(switch_ip, 8728) or _tcp_connect(switch_ip, 8729),
        "ssh_reachable": _tcp_connect(switch_ip, 22),
        "status": "missing",
        "summary": "No MikroTik switch detected at the configured management IP.",
        "actions": [
            "Plug a factory-default MikroTik switch directly into the host NIC.",
            "Use the first eight ports as: ether1-ether6 provisioning, ether7 WAN, ether8 trunk to the host.",
            "Run the switch setup flow or import a setup bundle that already contains the host settings.",
        ],
        "checks": [],
    }

    if not result["api_reachable"] and not result["ssh_reachable"]:
        return result

    result["reachable"] = True

    try:
        import librouteros  # type: ignore
    except ImportError:
        result["status"] = "warning"
        result["mode"] = "reachable"
        result["summary"] = "Switch responds on the network, but RouterOS API probing is unavailable."
        return result

    last_error = None
    for password in password_candidates:
        try:
            api = librouteros.connect(
                host=switch_ip,
                username="admin",
                password=password,
                timeout=3.0,
            )
            try:
                identity_rows = list(api.path("/system/identity").select())
                resource_rows = list(api.path("/system/resource").select())
                bridge_vlans = list(api.path("/interface/bridge/vlan").select())
                bridge_ports = list(api.path("/interface/bridge/port").select())
                ip_addresses = list(api.path("/ip/address").select())
                scripts = list(api.path("/system/script").select())
                schedulers = list(api.path("/system/scheduler").select())
            finally:
                api.close()

            identity = identity_rows[0].get("name") if identity_rows else None
            board_name = resource_rows[0].get("board-name") if resource_rows else None
            version = resource_rows[0].get("version") if resource_rows else None

            result.update(
                {
                    "identity": identity,
                    "board_name": board_name,
                    "version": version,
                    "auth_mode": "configured-password" if password else "factory-default",
                }
            )

            bridge_port_map = {
                str(row.get("interface")): str(row.get("pvid", ""))
                for row in bridge_ports
                if row.get("interface")
            }
            vlan_map = {
                str(row.get("vlan-ids")): {
                    "tagged": _split_ros_list(row.get("tagged")),
                    "untagged": _split_ros_list(row.get("untagged")),
                }
                for row in bridge_vlans
                if row.get("vlan-ids") is not None
            }
            addresses = {str(row.get("address")) for row in ip_addresses if row.get("address")}
            script_names = {str(row.get("name")) for row in scripts if row.get("name")}
            scheduler_names = {str(row.get("name")) for row in schedulers if row.get("name")}

            expected_pvids = {
                "ether1": "1991",
                "ether2": "1992",
                "ether3": "1993",
                "ether4": "1994",
                "ether5": "1995",
                "ether6": "1996",
                "ether7": "1",
                "ether8": "1",
            }

            checks = []
            for interface, pvid in expected_pvids.items():
                checks.append(
                    {
                        "name": f"{interface} PVID",
                        "status": "ready" if bridge_port_map.get(interface) == pvid else "missing",
                        "expected": pvid,
                        "actual": bridge_port_map.get(interface),
                    }
                )

            vlan_expectations = {
                "1990": {"tagged": {"bridge1", "ether8"}},
                "1991": {"tagged": {"ether8"}, "untagged": {"ether1"}},
                "1992": {"tagged": {"ether8"}, "untagged": {"ether2"}},
                "1993": {"tagged": {"ether8"}, "untagged": {"ether3"}},
                "1994": {"tagged": {"ether8"}, "untagged": {"ether4"}},
                "1995": {"tagged": {"ether8"}, "untagged": {"ether5"}},
                "1996": {"tagged": {"ether8"}, "untagged": {"ether6"}},
            }
            for vlan_id, expectation in vlan_expectations.items():
                entry = vlan_map.get(vlan_id, {})
                tagged = entry.get("tagged", set())
                untagged = entry.get("untagged", set())
                ok = expectation["tagged"].issubset(tagged) and expectation.get("untagged", set()).issubset(untagged)
                checks.append(
                    {
                        "name": f"VLAN {vlan_id}",
                        "status": "ready" if ok else "missing",
                    }
                )

            checks.extend(
                [
                    {
                        "name": "Management IP",
                        "status": "ready" if "192.168.88.1/24" in addresses else "missing",
                    },
                    {
                        "name": "Identity",
                        "status": "ready" if identity == "provisioner-switch" else "warning",
                    },
                    {
                        "name": "Webhook script",
                        "status": "ready" if "port-monitor" in script_names else "missing",
                    },
                    {
                        "name": "Webhook scheduler",
                        "status": "ready" if "port-monitor-scheduler" in scheduler_names else "missing",
                    },
                ]
            )

            result["checks"] = checks
            if identity == "provisioner-switch" and all(item["status"] == "ready" for item in checks):
                result["mode"] = "configured"
                result["status"] = "ready"
                result["summary"] = "Provisioning switch is configured for the first eight ports."
            elif password == "" and identity != "provisioner-switch":
                result["mode"] = "factory-default"
                result["status"] = "warning"
                result["summary"] = "Factory-default MikroTik switch detected. Apply the provisioning switch layout before using the bench."
            else:
                result["mode"] = "partial"
                result["status"] = "warning"
                result["summary"] = "MikroTik switch is reachable, but the provisioning layout is incomplete."

            return result
        except Exception as exc:  # pragma: no cover - network-dependent
            last_error = str(exc)

    result["mode"] = "reachable"
    result["status"] = "warning"
    result["summary"] = "Switch responds on the network, but the readiness probe could not authenticate."
    if last_error:
        result["error"] = last_error
    return result


def build_readiness_report(
    config: Any,
    data_path: Path,
    *,
    config_path: Optional[Path] = None,
    env_path: Optional[Path] = None,
    switch_probe: Optional[Callable[[Any], Dict[str, Any]]] = None,
    interface_exists_func: Optional[Callable[[str], bool]] = None,
) -> Dict[str, Any]:
    """Build a readiness report for the first-run setup flow."""

    interface_exists_func = interface_exists_func or _interface_exists
    switch_probe = switch_probe or probe_mikrotik_switch

    system_files = {
        "config": str(config_path) if config_path else None,
        "env": str(env_path) if env_path else None,
        "config_exists": bool(config_path and config_path.exists()),
        "env_exists": bool(env_path and env_path.exists()),
    }

    management_iface = _management_interface_name(config)
    management_check = {
        "id": "management_network",
        "title": "Management VLAN interface",
        "status": "ready",
        "summary": "Management interface is configured.",
        "details": {
            "interface": management_iface,
            "exists": bool(management_iface and interface_exists_func(management_iface)),
            "switch_ip": getattr(getattr(config.network, "management", None), "switch_ip", None),
            "host_ip": getattr(getattr(config.network, "management", None), "ip", None),
        },
    }
    if not management_iface:
        management_check["status"] = "warning"
        management_check["summary"] = "Management VLAN is disabled in config."
    elif not management_check["details"]["exists"]:
        management_check["status"] = "missing"
        management_check["summary"] = "Expected management VLAN interface is not present yet."

    checks = [
        {
            "id": "host_files",
            "title": "Host setup files",
            "status": "ready" if system_files["config_exists"] and system_files["env_exists"] else "missing",
            "summary": "Host config and environment files are present."
            if system_files["config_exists"] and system_files["env_exists"]
            else "Host config or environment file is still missing.",
            "details": system_files,
        },
        management_check,
        {
            "id": "mikrotik_switch",
            "title": "MikroTik provisioning switch",
            **switch_probe(config),
        },
        _build_credentials_check(config, data_path),
        _build_template_check(config, data_path),
        _build_firmware_check(data_path),
    ]

    counts = {status: 0 for status in STATUS_PRIORITY}
    for check in checks:
        counts[check["status"]] += 1

    bundle_layout = [
        "configs/templates/<device_type>/...",
        "configs/overrides/<device_type>/...",
        "firmware/<device_type>/...",
        "credentials.json",
        "manifest.yaml",
        "settings/config.yaml (optional)",
        "settings/provisioner.env (optional)",
    ]

    return {
        "status": _status_from_checks(checks),
        "summary": counts,
        "checks": checks,
        "switch_port_map": [
            "ether1-ether6: provisioning ports for VLANs 1991-1996",
            "ether7: WAN or internet uplink",
            "ether8: trunk to the host",
        ],
        "bundle_layout": bundle_layout,
    }


def _normalize_member_path(member_name: str, strip_prefix: Optional[str]) -> Optional[PurePosixPath]:
    if not member_name or member_name.endswith("/"):
        return None
    path = PurePosixPath(member_name)
    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts:
        return None
    if any(part == ".." for part in parts):
        raise ValueError(f"Unsafe path in archive: {member_name}")
    if parts[0] in IGNORED_BUNDLE_PREFIXES:
        return None
    if strip_prefix and parts and parts[0] == strip_prefix:
        parts = parts[1:]
    if not parts or parts[0] in IGNORED_BUNDLE_PREFIXES:
        return None
    return PurePosixPath(*parts)


def _bundle_strip_prefix(members: Iterable[str]) -> Optional[str]:
    candidate_parts = []
    for member_name in members:
        path = PurePosixPath(member_name)
        parts = [part for part in path.parts if part not in ("", ".")]
        if not parts or parts[0] in IGNORED_BUNDLE_PREFIXES:
            continue
        candidate_parts.append(parts)

    if not candidate_parts:
        return None

    first_components = {parts[0] for parts in candidate_parts}
    if len(first_components) != 1:
        return None

    only_prefix = next(iter(first_components))
    if only_prefix in ROOT_BUNDLE_NAMES:
        return None
    if any(len(parts) < 2 for parts in candidate_parts):
        return None
    return only_prefix


def _copy_file(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def import_setup_bundle(
    archive_path: Path,
    filename: str,
    *,
    data_path: Path,
    config_path: Optional[Path] = None,
    env_path: Optional[Path] = None,
    apply_system_files: bool = False,
) -> Dict[str, Any]:
    """Import a setup bundle archive into the provisioner filesystem layout."""

    lower_name = filename.lower()
    if lower_name.endswith(".zip"):
        archive_type = "zip"
    elif lower_name.endswith((".tar", ".tar.gz", ".tgz")):
        archive_type = "tar"
    else:
        raise ValueError("Unsupported bundle format. Use .zip, .tar, .tar.gz, or .tgz.")

    summary = {
        "configs": 0,
        "firmware": 0,
        "credentials": 0,
        "manifest": 0,
        "system_files": 0,
    }
    imported_files: List[str] = []
    skipped_files: List[str] = []

    with TemporaryDirectory(prefix="provisioner-bundle-") as temp_dir:
        extract_root = Path(temp_dir)
        if archive_type == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                strip_prefix = _bundle_strip_prefix(archive.namelist())
                for member_name in archive.namelist():
                    normalized = _normalize_member_path(member_name, strip_prefix)
                    if normalized is None:
                        continue
                    destination = extract_root / Path(*normalized.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member_name) as src, open(destination, "wb") as dest:
                        shutil.copyfileobj(src, dest)
        else:
            with tarfile.open(archive_path) as archive:
                strip_prefix = _bundle_strip_prefix(member.name for member in archive.getmembers())
                for member in archive.getmembers():
                    normalized = _normalize_member_path(member.name, strip_prefix)
                    if normalized is None or not member.isfile():
                        continue
                    destination = extract_root / Path(*normalized.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    with extracted, open(destination, "wb") as dest:
                        shutil.copyfileobj(extracted, dest)

        for extracted in sorted(path for path in extract_root.rglob("*") if path.is_file()):
            relative = extracted.relative_to(extract_root)
            root_name = relative.parts[0]

            if root_name == "configs":
                destination = data_path / relative
                _copy_file(extracted, destination)
                summary["configs"] += 1
                imported_files.append(str(relative))
            elif root_name == "firmware":
                destination = data_path / relative
                _copy_file(extracted, destination)
                summary["firmware"] += 1
                imported_files.append(str(relative))
            elif str(relative) == "credentials.json":
                destination = data_path / "credentials.json"
                _copy_file(extracted, destination)
                summary["credentials"] += 1
                imported_files.append(str(relative))
            elif str(relative) == "manifest.yaml":
                destination = data_path / "manifest.yaml"
                _copy_file(extracted, destination)
                summary["manifest"] += 1
                imported_files.append(str(relative))
            elif root_name == "settings":
                if not apply_system_files:
                    skipped_files.append(str(relative))
                    continue
                target_name = relative.name
                if target_name == "config.yaml" and config_path:
                    _copy_file(extracted, config_path)
                    summary["system_files"] += 1
                    imported_files.append(str(relative))
                elif target_name == "provisioner.env" and env_path:
                    _copy_file(extracted, env_path)
                    summary["system_files"] += 1
                    imported_files.append(str(relative))
                else:
                    skipped_files.append(str(relative))
            elif str(relative) == "config.yaml":
                if apply_system_files and config_path:
                    _copy_file(extracted, config_path)
                    summary["system_files"] += 1
                    imported_files.append(str(relative))
                else:
                    skipped_files.append(str(relative))
            elif str(relative) == "provisioner.env":
                if apply_system_files and env_path:
                    _copy_file(extracted, env_path)
                    summary["system_files"] += 1
                    imported_files.append(str(relative))
                else:
                    skipped_files.append(str(relative))
            else:
                skipped_files.append(str(relative))

    return {
        "success": True,
        "message": f"Imported setup bundle '{filename}'",
        "summary": summary,
        "imported_files": imported_files,
        "skipped_files": skipped_files,
        "restart_required": summary["system_files"] > 0,
    }


def write_setup_bundle(
    bundle_path: Path,
    *,
    data_path: Path,
    config_path: Optional[Path] = None,
    env_path: Optional[Path] = None,
    include_system_files: bool = False,
) -> Dict[str, Any]:
    """Write a portable setup bundle zip archive."""

    summary = {
        "configs": 0,
        "firmware": 0,
        "credentials": 0,
        "manifest": 0,
        "system_files": 0,
    }

    def add_tree(archive: zipfile.ZipFile, source: Path, prefix: str, key: str) -> None:
        if not source.exists():
            return
        for file_path in sorted(path for path in source.rglob("*") if path.is_file()):
            archive.write(file_path, arcname=str(PurePosixPath(prefix) / file_path.relative_to(source)))
            summary[key] += 1

    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        add_tree(archive, data_path / "configs", "configs", "configs")
        add_tree(archive, data_path / "firmware", "firmware", "firmware")

        credentials_path = data_path / "credentials.json"
        if credentials_path.exists():
            archive.write(credentials_path, arcname="credentials.json")
            summary["credentials"] += 1

        manifest_path = data_path / "manifest.yaml"
        if manifest_path.exists():
            archive.write(manifest_path, arcname="manifest.yaml")
            summary["manifest"] += 1

        if include_system_files:
            if config_path and config_path.exists():
                archive.write(config_path, arcname="settings/config.yaml")
                summary["system_files"] += 1
            if env_path and env_path.exists():
                archive.write(env_path, arcname="settings/provisioner.env")
                summary["system_files"] += 1

        metadata = {
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "summary": summary,
        }
        archive.writestr("bundle-metadata.json", json.dumps(metadata, indent=2))

    return {
        "success": True,
        "summary": summary,
        "filename": bundle_path.name,
        "path": str(bundle_path),
    }


def seed_bundled_templates(
    repo_root: Path,
    *,
    data_path: Path,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Copy bundled repo templates into the live data store."""

    source_root = repo_root / "configs" / "templates"
    target_root = data_path / "configs" / "templates"
    copied_files: List[str] = []
    skipped_files: List[str] = []

    if not source_root.exists():
        raise FileNotFoundError(f"Bundled template directory not found: {source_root}")

    for source_file in sorted(path for path in source_root.rglob("*") if path.is_file()):
        if source_file.name.startswith("."):
            continue

        relative = source_file.relative_to(source_root)
        target = target_root / relative
        if target.exists() and not overwrite:
            skipped_files.append(str(relative))
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target)
        copied_files.append(str(relative))

    return {
        "success": True,
        "message": "Seeded bundled templates into the live config store",
        "copied": len(copied_files),
        "skipped": len(skipped_files),
        "copied_files": copied_files,
        "skipped_files": skipped_files,
    }
