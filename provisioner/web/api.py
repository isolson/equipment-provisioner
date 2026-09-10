"""REST API endpoints for Network Provisioner web interface."""

import asyncio
import io
import json
import logging
import os
import re
import subprocess
import tarfile
import uuid
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from ..config_assets import (
    ConfigAsset,
    ConfigAssetCatalog,
    MODE_TO_PTP_SIDE,
)
from ..fingerprint import is_mikrotik_oui
from ..handler_manager import HandlerManager, provisionable_device_types
from ..setup_tools import (
    build_readiness_report,
    import_setup_bundle,
    seed_bundled_templates,
    write_setup_bundle,
)
from ..vendor_registry import (
    builtin_ui_credentials,
    config_family_metadata,
    nonprovisionable_device_types,
    ptp_families_compatible,
    spec_for,
    ui_styles,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["api"])
_SECRET_KEY_RE = re.compile(
    r"(?:password|passphrase|psk|secret|token|community|private[_-]?key|encryption[_-]?key)",
    re.IGNORECASE,
)


def _normalized_firmware_version(value: Any) -> str:
    """Return a firmware version in the form used by asset directories."""
    normalized = str(value or "").strip().lower()
    return re.sub(r"^v", "", normalized)


# ============================================================================
# Request/Response Models
# ============================================================================

class PortStatus(BaseModel):
    """Status of a single provisioning port."""
    port_number: int
    vlan_id: int
    link_up: bool
    device_detected: bool
    device_type: Optional[str] = None
    device_ip: Optional[str] = None
    device_mac: Optional[str] = None
    device_serial: Optional[str] = None
    device_model: Optional[str] = None
    provisioning: bool = False
    waiting_for_boot: bool = False
    boot_wait_remaining: Optional[int] = None
    last_activity: Optional[str] = None
    link_speed: Optional[str] = None
    last_result: Optional[str] = None
    last_error: Optional[str] = None
    needs_credentials: bool = False
    checklist: Dict[str, Any] = Field(default_factory=dict)
    step_plan: List[Dict[str, str]] = Field(default_factory=list)
    step_status: Dict[str, Any] = Field(default_factory=dict)
    step_details: Dict[str, str] = Field(default_factory=dict)
    device_mode: Optional[str] = None
    mode_config: Optional[Dict[str, Any]] = None
    ptp_link_id: Optional[str] = None
    workflow: Dict[str, Any] = Field(default_factory=dict)
    # Server-owned presentation state, event cursor, and mode-change job.
    presentation: Dict[str, Any] = Field(default_factory=dict)
    event_seq: int = 0
    run_id: Optional[str] = None
    mode_job: Optional[Dict[str, Any]] = None
    firmware_version: Optional[str] = None
    reprovision_wait: int = 0


class ProvisionRequest(BaseModel):
    """Request to manually provision a device."""
    port_number: int
    custom_password: Optional[str] = None
    custom_username: Optional[str] = None
    skip_firmware: bool = False
    skip_config: bool = False
    config_override: Optional[Dict[str, Any]] = None
    operator_id: Optional[int] = None
    # Site-role config overlay for this job (opaque string, e.g. "tower").
    # None falls back to config.yaml provisioning.default_role. Absent in
    # old clients, so requests are wire-compatible. UI exposure is R2.
    role: Optional[str] = None


class ProvisionResponse(BaseModel):
    """Response from a provision request."""
    success: bool
    job_id: Optional[int] = None
    message: str


class NetinstallRequest(BaseModel):
    """Request to run Netinstall on a port (MikroTik BOOTP mode)."""
    port_number: int


class ApplyModeRequest(BaseModel):
    """Request to apply a device mode after provisioning."""
    mode: str  # "sm", "ap", or "ptp"
    # AP fields
    tower: Optional[int] = None
    direction: Optional[str] = None
    # PTP fields
    my_tower: Optional[int] = None
    remote_tower: Optional[int] = None
    # Optional post-provision override for connectorized Cambium radios.
    # Omitted means the handler uses its safe connectorized default.
    antenna_gain_db: Optional[int] = None


class CredentialOverride(BaseModel):
    """Temporary credential override for a port."""
    port_number: int
    username: str
    password: str
    device_type: Optional[str] = None  # If known


class JobStatus(BaseModel):
    """Status of a provisioning job."""
    job_id: int
    status: str
    port_number: Optional[int] = None  # Port where device was provisioned
    device_type: Optional[str] = None
    device_model: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    ip_address: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    old_firmware: Optional[str] = None
    new_firmware: Optional[str] = None
    config_applied: Optional[str] = None


class SystemStatus(BaseModel):
    """Overall system status."""
    running: bool
    mode: str  # "vlan" or "simple"
    uptime_seconds: Optional[float] = None
    total_ports: int
    active_ports: int
    devices_detected: int
    provisioning_in_progress: int


# ============================================================================
# Port Management Endpoints
# ============================================================================

@router.get("/ports", response_model=List[PortStatus])
async def get_all_ports(request: Request):
    """Get status of all provisioning ports."""
    provisioner = request.app.state.provisioner
    
    if not provisioner or not provisioner.port_manager:
        # Return mock data if provisioner not available
        return _get_mock_ports()
    
    port_status = provisioner.port_manager.get_port_status()
    
    return [
        PortStatus(port_number=port_num, **status)
        for port_num, status in port_status.items()
    ]


@router.get("/ports/{port_number}", response_model=PortStatus)
async def get_port(port_number: int, request: Request):
    """Get status of a specific port."""
    provisioner = request.app.state.provisioner
    
    if not provisioner or not provisioner.port_manager:
        mock_ports = _get_mock_ports()
        for port in mock_ports:
            if port.port_number == port_number:
                return port
        raise HTTPException(status_code=404, detail="Port not found")
    
    port_status = provisioner.port_manager.get_port_status()
    
    if port_number not in port_status:
        raise HTTPException(status_code=404, detail="Port not found")
    
    status = port_status[port_number]
    return PortStatus(port_number=port_number, **status)


@router.get("/ports/{port_number}/events")
async def get_port_events(
    port_number: int,
    request: Request,
    since: int = 0,
    limit: int = 200,
):
    """Return the server-owned timeline for one port (oldest first).

    Entries carry step names, results, and mismatch field names. They never
    carry a credential or a device secret.
    """
    provisioner = request.app.state.provisioner
    if not provisioner or not provisioner.port_manager:
        raise HTTPException(status_code=503, detail="Port manager not available")
    port_manager = provisioner.port_manager
    if port_number not in port_manager.get_port_status():
        raise HTTPException(status_code=404, detail="Port not found")
    return port_manager.get_events(port_number, since=max(0, since), limit=max(1, min(limit, 500)))


# ============================================================================
# Provisioning Endpoints
# ============================================================================

# Store temporary credential overrides (in-memory, cleared on restart)
_credential_overrides: Dict[int, CredentialOverride] = {}


@router.get("/device-settings")
async def get_device_settings(request: Request):
    """Get device-type-specific provisioning settings (defaults for UI)."""
    provisioner = request.app.state.provisioner
    if not provisioner:
        return {}
    config = provisioner.config
    return {
        "tarana": {
            "operator_id": getattr(config.device_settings.tarana, 'operator_id', None),
        },
    }


@router.put("/device-settings")
async def update_device_settings(settings: Dict[str, Any], request: Request):
    """Update device-type-specific provisioning settings.

    Updates the in-memory config AND persists the change to
    ``/var/lib/provisioner/device-settings.json`` so it survives a
    ``systemctl restart provisioner-web``. The file is loaded on startup by
    ``load_config`` and overlaid on top of ``config.yaml``.

    Only fields explicitly edited via this endpoint are written to the
    overrides file — we deliberately do NOT snapshot the full in-memory
    ``device_settings`` to avoid shadowing values that legitimately come
    from ``config.yaml`` (e.g. mikrotik.ztp_api_key).
    """
    provisioner = request.app.state.provisioner
    if not provisioner:
        raise HTTPException(status_code=503, detail="Provisioner not available")

    from ..config import load_device_settings_overrides, save_device_settings_overrides_dict

    persisted_changes: Dict[str, Any] = {}

    if "tarana" in settings:
        tarana = settings["tarana"]
        if "operator_id" in tarana:
            provisioner.config.device_settings.tarana.operator_id = tarana["operator_id"]
            persisted_changes.setdefault("tarana", {})["operator_id"] = tarana["operator_id"]

    if persisted_changes:
        # Merge the change into whatever is already on disk so other
        # previously-persisted overrides (future fields) are not lost.
        try:
            existing = load_device_settings_overrides()
            merged = _merge_settings_dict(existing, persisted_changes)
            save_device_settings_overrides_dict(merged)
        except OSError as e:
            logger.error("Failed to persist device settings: %s", e)
            raise HTTPException(
                status_code=500,
                detail=f"Settings updated in memory but could not be saved to disk: {e}",
            )

    return {"success": True}


def _merge_settings_dict(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow-recursive merge for device-settings overrides dict."""
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_settings_dict(result[key], value)
        else:
            result[key] = value
    return result


@router.post("/provision", response_model=ProvisionResponse)
async def provision_device(
    req: ProvisionRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Manually trigger provisioning for a port."""
    provisioner = request.app.state.provisioner
    
    if not provisioner:
        raise HTTPException(status_code=503, detail="Provisioner not available")
    
    port_manager = provisioner.port_manager
    if not port_manager:
        raise HTTPException(status_code=503, detail="Port manager not available")
    
    # Check if port exists and has a device
    port_status = port_manager.get_port_status()
    if req.port_number not in port_status:
        raise HTTPException(status_code=404, detail="Port not found")
    
    status = port_status[req.port_number]
    if not status["device_detected"]:
        raise HTTPException(status_code=400, detail="No device detected on port")
    
    if status["provisioning"]:
        raise HTTPException(status_code=409, detail="Port already provisioning")
    
    # Store custom credentials if provided
    if req.custom_password:
        _credential_overrides[req.port_number] = CredentialOverride(
            port_number=req.port_number,
            username=req.custom_username or "admin",
            password=req.custom_password,
            device_type=status["device_type"],
        )
    
    # Trigger provisioning in background
    background_tasks.add_task(
        _run_provisioning,
        provisioner,
        req.port_number,
        status["device_type"],
        status["device_ip"],
        req,
    )
    
    return ProvisionResponse(
        success=True,
        message=f"Provisioning started for port {req.port_number}",
    )


_NPK_NAME_RE = re.compile(
    r"^(?P<package>routeros|wifi-qcom|wifi-qcom-ac|wifi-mediatek|wireless)-"
    r"(?:(?P<arch_first>[a-z0-9_]+)-(?P<version_after_arch>\d+(?:\.\d+)+)|"
    r"(?P<version_first>\d+(?:\.\d+)+)-(?P<arch_after_version>[a-z0-9_]+))"
    r"\.npk$",
    re.IGNORECASE,
)
_NPK_PACKAGE_ORDER = {
    "routeros": 0,
    "wifi-qcom": 10,
    "wifi-qcom-ac": 11,
    "wifi-mediatek": 12,
    "wireless": 13,
}


def _select_latest_npk_per_arch(mikrotik_fw_dir: Path) -> List[str]:
    """Return one .npk path per package/arch, picking the newest version.

    MikroTik has used both `routeros-<arch>-<version>.npk` and
    `routeros-<version>-<arch>.npk`; extra packages such as `wifi-qcom` use
    `<package>-<version>-<arch>.npk`. Netinstall ships the full selected set,
    including WiFi driver packages required by the wifi contract. Files that
    don't match are passed through unchanged so unconventional names still
    reach netinstall-cli.
    """
    selected_by_package_arch: Dict[tuple[str, str], tuple] = {}
    unmatched: List[Path] = []
    for path in mikrotik_fw_dir.glob("*.npk"):
        match = _NPK_NAME_RE.match(path.name)
        if not match:
            unmatched.append(path)
            continue
        package = match.group("package").lower()
        version_str = match.group("version_after_arch") or match.group("version_first")
        arch = (match.group("arch_first") or match.group("arch_after_version")).lower()
        try:
            version_tuple = tuple(int(part) for part in version_str.split("."))
        except ValueError:
            unmatched.append(path)
            continue
        key = (package, arch)
        existing = selected_by_package_arch.get(key)
        if existing is None or version_tuple > existing[0]:
            selected_by_package_arch[key] = (version_tuple, path)

    ordered = sorted(
        selected_by_package_arch.items(),
        key=lambda item: (
            _NPK_PACKAGE_ORDER.get(item[0][0], 99),
            item[0][1],
            item[1][1].name,
        ),
    )
    selected = [str(entry[1][1]) for entry in ordered]
    selected.extend(str(p) for p in sorted(unmatched))
    return selected


@router.post("/netinstall", response_model=ProvisionResponse)
async def netinstall_device(
    req: NetinstallRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Run Netinstall on a port (MikroTik in BOOTP mode).

    Flashes RouterOS firmware with the contract Netinstall Mode + Configure
    scripts. The device must be in Netinstall/BOOTP mode (reset button held
    during power-on).
    """
    provisioner = request.app.state.provisioner
    if not provisioner:
        raise HTTPException(status_code=503, detail="Provisioner not available")

    port_manager = provisioner.port_manager
    if not port_manager:
        raise HTTPException(status_code=503, detail="Port manager not available")

    port_status = port_manager.get_port_status()
    if req.port_number not in port_status:
        raise HTTPException(status_code=404, detail="Port not found")

    status = port_status[req.port_number]
    if status.get("provisioning"):
        raise HTTPException(status_code=409, detail="Port already provisioning")

    capabilities = HandlerManager.operator_capabilities_for(
        status.get("device_type")
    )
    if not capabilities["manual_netinstall"]:
        raise HTTPException(
            status_code=400,
            detail="Netinstall is not supported for the detected device",
        )

    # Manual recovery is destructive. Match the automatic BOOTP path's OUI
    # safety boundary instead of trusting a possibly stale device-type tag.
    device_mac = status.get("device_mac")
    if not device_mac or not is_mikrotik_oui(device_mac):
        raise HTTPException(
            status_code=400,
            detail="Netinstall requires a detected MikroTik MAC address",
        )

    background_tasks.add_task(
        _run_netinstall,
        provisioner,
        req.port_number,
    )

    return ProvisionResponse(
        success=True,
        message=f"Netinstall started for port {req.port_number}",
    )


def _ship_ready_issues(readback: Dict[str, Any]) -> List[str]:
    """Contract rule 5: the register readback must show a unit with no past
    life before it ships. (`business-router` hardware classes are excepted
    by the contract; nothing in the current fleet falls in that class, so
    role is enforced strictly here.)
    """
    issues = []
    if readback.get("role", "unknown") != "unknown":
        issues.append(f"role={readback.get('role')}")
    if readback.get("customer_id") is not None:
        issues.append(f"customer_id={readback.get('customer_id')}")
    if readback.get("has_checkin_secret", False):
        issues.append("has_checkin_secret=true")
    return issues


def _mikrotik_netinstall_label_payload(config, info) -> Optional[Dict[str, Any]]:
    """Build the optional client-side print payload for a ship-ready unit."""
    printer = getattr(config, "label_printer", None)
    if not printer:
        return None
    if not getattr(printer, "enabled", False):
        return None
    if getattr(printer, "provider", "") != "brady_web_bluetooth":
        return None
    if not getattr(printer, "auto_print_mikrotik_netinstall", True):
        return None

    serial = getattr(info, "serial_number", None)
    mac = getattr(info, "mac_address", None)
    if not serial or not mac:
        logger.warning(
            "MikroTik label print skipped: missing serial or MAC "
            "(serial=%r mac=%r)",
            serial,
            mac,
        )
        return None

    return {
        "type": "mikrotik_netinstall",
        "serial": serial,
        "mac": mac,
        "model": getattr(info, "model", None) or "",
        "copies": getattr(printer, "copies", 1),
    }


async def _run_netinstall(provisioner, port_number: int):
    """Run Netinstall + served Configure-script pipeline in background."""
    from provisioner.handlers.mikrotik import MikrotikHandler
    from provisioner.web.websocket import (
        notify_port_change,
        notify_provisioning_completed,
    )

    port_manager = provisioner.port_manager
    port_manager.mark_port_provisioning(port_number, True)
    port_manager.reset_checklist(port_number)

    netinstall_step_plan = [
        {"key": "script_fetch", "label": "Fetch served scripts"},
        {"key": "netinstall", "label": "Netinstall"},
        {"key": "reboot", "label": "First boot"},
        {"key": "login", "label": "Login"},
        {"key": "model_confirmed", "label": "Device identity"},
        {"key": "base_flash", "label": "Base flash marker"},
        {"key": "ztp_ready", "label": "ZTP readiness"},
        {"key": "phone_home_url", "label": "Phone-home endpoint"},
        {"key": "register", "label": "Equipment registration"},
        {"key": "ship_ready", "label": "Ship-ready state"},
    ]
    port_manager.set_step_plan(port_number, netinstall_step_plan)

    state = port_manager.port_states.get(port_number)
    if state:
        state.last_result = None
        state.last_error = None

    interface = port_manager.get_interface_for_port(port_number)
    config = provisioner.config

    # Progress callback for UI
    async def on_progress(step, success, detail=None):
        status = "loading" if success == "running" else success
        # device_info carries MAC/serial for internal state transfer. Do not
        # copy those identifiers into the generic validation-detail map.
        if step != "device_info":
            port_manager.update_checklist(port_number, step, status, detail)
        port_status = port_manager._get_single_port_status(port_number)
        await notify_port_change(port_number, port_status)

    async def finish(
        success: bool,
        error: Optional[str] = None,
        detail: Optional[str] = None,
        label: Optional[Dict[str, Any]] = None,
    ):
        # Single exit chokepoint — never leak the watchdog-suppression flag.
        # mark_port_provisioning() does not reset expecting_reboot, so clear it
        # here explicitly (harmless no-op if it was never set).
        port_manager.set_expecting_reboot(port_number, False)
        port_manager.mark_port_provisioning(
            port_number,
            False,
            success=success,
            error=error,
        )
        port_status = port_manager._get_single_port_status(port_number)
        await notify_port_change(port_number, port_status)
        payload = {"message": detail or ("Complete" if success else error or "Failed")}
        if error:
            payload["error"] = error
        if label:
            payload["label"] = label
        await notify_provisioning_completed(port_number, 0, success, payload)

    # Device is in BOOTP mode — model unknown. Pass every latest package we
    # have so netinstall-cli can match the arch from the BOOTP request itself.
    # This includes WiFi driver packages; sixtyops/wifi PR #253 treats the
    # served Netinstall Configure script as the durable post-reset contract,
    # and the driver package is part of that initial flash set.
    mikrotik_fw_dir = provisioner.firmware_manager.firmware_path / "mikrotik"
    npks = _select_latest_npk_per_arch(mikrotik_fw_dir)
    if not npks:
        logger.error(f"No MikroTik firmware found for Netinstall on port {port_number} (looked in {mikrotik_fw_dir})")
        await finish(False, "No MikroTik firmware available")
        return

    ztp_api_url = getattr(config.device_settings.mikrotik, 'ztp_api_url', None)
    if not ztp_api_url:
        await finish(False, "device_settings.mikrotik.ztp_api_url not configured")
        return

    ztp_api_key = getattr(config.device_settings.mikrotik, 'ztp_api_key', None)
    if not ztp_api_key:
        await finish(False, "device_settings.mikrotik.ztp_api_key not configured")
        return

    # The served Configure script embeds the backend's *stored* fleet-bootstrap
    # password, so the post-flash SSH login must use that value. Fetch it from
    # the contract credentials endpoint (same API key); fall back to the local
    # MIKROTIK_BOOTSTRAP_PASS when the endpoint is unavailable.
    local_bootstrap_pass = config.credentials["mikrotik"].bootstrap_password
    canonical_bootstrap_pass = None
    try:
        creds = await MikrotikHandler.fetch_provisioning_credentials(
            ztp_api_url, ztp_api_key
        )
        canonical_bootstrap_pass = (creds or {}).get("bootstrap_password") or None
    except Exception as exc:
        logger.warning(
            f"provisioning-credentials fetch failed ({exc}); "
            f"falling back to local MIKROTIK_BOOTSTRAP_PASS"
        )
    if (
        canonical_bootstrap_pass
        and local_bootstrap_pass
        and canonical_bootstrap_pass != local_bootstrap_pass
    ):
        logger.warning(
            "Local MIKROTIK_BOOTSTRAP_PASS differs from the wifi-api's stored "
            "bootstrap_password; using the canonical value for post-flash login"
        )
    bootstrap_pass = canonical_bootstrap_pass or local_bootstrap_pass
    if not bootstrap_pass:
        logger.error(
            "No bootstrap password — provisioning-credentials fetch failed and "
            "MIKROTIK_BOOTSTRAP_PASS is unset; cannot run Netinstall"
        )
        await finish(False, "No bootstrap password (fetch failed, MIKROTIK_BOOTSTRAP_PASS unset)")
        return

    await on_progress("script_fetch", "running", "Fetching served Netinstall scripts...")
    try:
        configure_script_body = await MikrotikHandler.fetch_netinstall_bootstrap(
            ztp_api_url,
            ztp_api_key,
        )
    except Exception as exc:
        await on_progress("script_fetch", False, f"Fetch failed: {str(exc)[:100]}")
        await finish(False, f"netinstall-bootstrap fetch failed: {exc}")
        return

    # The Mode script is also backend-owned (served ungated — a single static
    # device-mode command, no secrets). Stage 1 of the wifi runbook requires
    # both served scripts; the provisioner must not author its own.
    try:
        mode_script_body = await MikrotikHandler.fetch_netinstall_mode(ztp_api_url)
    except Exception as exc:
        await on_progress("script_fetch", False, f"Mode-script fetch failed: {str(exc)[:100]}")
        await finish(False, f"netinstall-mode fetch failed: {exc}")
        return
    await on_progress("script_fetch", True, "Fetched Configure and Mode scripts")

    try:
        # Step 1: Netinstall with the served Mode script plus the served
        # Configure script from the target wifi backend.
        handler = MikrotikHandler(
            ip="192.168.88.1",
            credentials={"username": MikrotikHandler.BOOTSTRAP_USER, "password": bootstrap_pass},
            interface=interface,
        )

        await on_progress("netinstall", "running", "Waiting for device in BOOTP mode...")

        success = await handler.netinstall(
            firmware_paths=npks,
            interface=interface,
            configure_script_body=configure_script_body,
            mode_script_body=mode_script_body,
            on_progress=on_progress,
        )

        if not success:
            await finish(False, "Netinstall failed")
            return

        # Suppress the port link-loss watchdog for the rest of the pipeline: the
        # first boot and follow-up verification windows can still flap the port,
        # and the watchdog would otherwise read that as an unplug. Internal
        # wait_for_* timeouts still bound the run, so a real unplug fails cleanly.
        port_manager.set_expecting_reboot(port_number, True)

        # Step 2: Wait for device to boot after Netinstall.
        # First boot is slow (RouterBOOT + RouterOS init + SSH server start);
        # 240s observed needed in practice on hAP ax2. The boot also flaps the
        # port when the `-s` userscript adds `bridge-bootstrap` across all ether
        # ports (down longer than LINK_DOWN_GRACE_SECONDS) — but that is already
        # covered by the blanket expecting_reboot=True set above, which stays in
        # effect through the base-flash + ZTP register steps and is cleared once
        # in finish(). Do NOT clear it here: doing so re-arms the watchdog during
        # those follow-up steps and cancels the pipeline mid-flow.
        await on_progress("reboot", "running", "Waiting for device to boot...")
        await asyncio.sleep(10)

        booted = await handler.wait_for_reboot(timeout=240)
        if not booted:
            await finish(False, "Device did not boot after Netinstall")
            return
        await on_progress("reboot", True, "Device booted")

        # Step 3: Connect and get device info
        await on_progress("login", "running")
        if not await handler.connect():
            await on_progress("login", False, "Failed to connect after Netinstall")
            await finish(False, "Failed to connect after Netinstall")
            return
        await on_progress("login", True)

        info = await handler.get_info()
        await on_progress("device_info", True, f"mac:{info.mac_address or ''}|serial:{info.serial_number or ''}")
        await on_progress("model_confirmed", True, info.model)

        if info.mac_address or info.serial_number:
            port_manager.update_port_device_info(
                port_number,
                mac=info.mac_address,
                serial=info.serial_number,
                model=info.model,
            )

        # Contract registration requires a real serial; refuse to continue
        # rather than POST `UNKNOWN` to the wifi-api and pollute the registry.
        serial = info.serial_number
        if not serial or serial.upper() == "UNKNOWN":
            await on_progress("model_confirmed", False, "No serial — cannot register")
            await finish(False, "Could not read RouterBOARD serial; refusing to register")
            return

        # Step 4: Verify the served Configure script wrote its note marker.
        verified = await handler.wait_for_base_flash_applied()
        if not verified:
            logger.error(
                "Netinstall pipeline failed on port %s: base_flash_version marker missing",
                port_number,
            )
            await on_progress("base_flash", False, "base_flash_version marker missing")
            await finish(
                False,
                f"/system/note missing base_flash_version "
                f">= {MikrotikHandler.BASE_FLASH_VERSION}",
            )
            return
        detected_bf = handler.base_flash_version_detected or MikrotikHandler.BASE_FLASH_VERSION
        logger.info(
            "MikroTik Configure-script marker verified on port %s (%s)",
            port_number,
            detected_bf,
        )
        await on_progress("base_flash", True, f"Configure script verified ({detected_bf})")

        # Step 5: Verify the served Configure script left the device ZTP-ready.
        ztp_ready, ztp_detail = await handler.verify_ztp_ready(serial)
        if not ztp_ready:
            logger.error(
                "Netinstall pipeline failed on port %s: ZTP readiness check failed: %s",
                port_number,
                ztp_detail,
            )
            await on_progress("ztp_ready", False, ztp_detail)
            await finish(False, f"ZTP readiness check failed: {ztp_detail}")
            return
        logger.info("MikroTik ZTP readiness verified on port %s: %s", port_number, ztp_detail)
        await on_progress("ztp_ready", True, ztp_detail)

        # Step 5b: wifi-capable models must leave the flash with bound radios.
        # The known hAP ax failure mode is a clean install with an empty
        # /interface/wifi (runbook step 1 pass criterion) — registering such a
        # unit would ship a wifi-dead router.
        device_arch = (getattr(info, "hardware_version", "") or "").lower()
        if MikrotikHandler.wifi_driver_for_model(info.model, device_arch):
            wifi_step = {"key": "wifi_bind", "label": "WiFi radio binding"}
            phone_home_index = next(
                index
                for index, item in enumerate(netinstall_step_plan)
                if item["key"] == "phone_home_url"
            )
            netinstall_step_plan.insert(phone_home_index, wifi_step)
            port_manager.set_step_plan(port_number, netinstall_step_plan)
            if not await handler.verify_wifi_radios_bound():
                logger.error(
                    "Netinstall pipeline failed on port %s: /interface/wifi is "
                    "empty after flash (model=%s)",
                    port_number,
                    info.model,
                )
                await on_progress("wifi_bind", False, "/interface/wifi is empty")
                await finish(
                    False,
                    "WiFi radios not bound after Netinstall (/interface/wifi empty)",
                )
                return
            await on_progress("wifi_bind", True, "wifi radios bound")

        # Step 5c: verify the baked phone-home URL from the bench host
        # (contract rule 4). The bench never gives the device an internet
        # path — first checkin is install-time by design — so the bench host
        # checks the URL this flash actually baked on the device's behalf.
        phone_home_url = await handler.get_phone_home_url()
        expected_host = urlparse(ztp_api_url).hostname
        baked_host = urlparse(phone_home_url).hostname if phone_home_url else None
        if not phone_home_url or baked_host != expected_host:
            logger.error(
                "Netinstall pipeline failed on port %s: baked phone-home URL %r "
                "does not point at backend host %r",
                port_number,
                phone_home_url,
                expected_host,
            )
            await on_progress("phone_home_url", False, f"baked={phone_home_url or 'none'}")
            await finish(
                False,
                f"baked phone-home URL mismatch: {phone_home_url or 'none'} "
                f"(expected host {expected_host})",
            )
            return
        try:
            # GET the ungated Mode script on the *baked* host: proves the host
            # the device will actually phone home to is alive and serving ZTP,
            # without re-trusting the configured URL.
            await MikrotikHandler.fetch_netinstall_mode(
                f"{urlparse(phone_home_url).scheme}://{urlparse(phone_home_url).netloc}"
            )
        except Exception as exc:
            await on_progress("phone_home_url", False, f"unreachable: {str(exc)[:80]}")
            await finish(False, f"baked phone-home host unreachable from bench: {exc}")
            return
        await on_progress("phone_home_url", True, f"baked URL OK ({baked_host})")

        await handler.disconnect()

        # Step 6: Register with the wifi-api, then assert the ship-ready
        # readback (contract rule 5): a recycled unit still carrying a locked
        # role, a customer assignment, or a server-side TOFU secret would be
        # served its old life — or rejected outright — at the new install.
        from provisioner.equipment_registry import (
            clear_checkin_secret,
            clear_role_lock,
            register_mikrotik,
        )
        register_kwargs = dict(
            ztp_api_url=ztp_api_url,
            api_key=ztp_api_key,
            serial=serial,
            mac=info.mac_address or "",
            model=info.model or "",
            firmware_version=info.firmware_version or "",
            base_flash_version=(
                handler.base_flash_version_detected
                or MikrotikHandler.BASE_FLASH_VERSION
            ),
        )
        try:
            await on_progress("register", "running", "Registering equipment")
            readback = await register_mikrotik(**register_kwargs)
            await on_progress("register", True, "Equipment registered")

            if not any(
                key in readback for key in ("role", "customer_id", "has_checkin_secret")
            ):
                # Pre-#255 backend: no readback to assert on. Don't block the
                # bench, but say so loudly — ship-ready is unverified.
                logger.warning(
                    "wifi-api register response has no ship-ready readback "
                    "(backend without wifi PR #255) — skipping ship-ready assertions"
                )
                await on_progress("ship_ready", True, "SKIPPED (backend lacks readback)")
            else:
                issues = _ship_ready_issues(readback)
                if issues:
                    # The unit is on the bench by deliberate operator action —
                    # that is the operator confirmation for clearing its old
                    # life. Both clears are logged loudly server-side.
                    logger.warning(
                        "MikroTik %s not ship-ready (%s) — remediating per contract",
                        serial,
                        ", ".join(issues),
                    )
                    await on_progress(
                        "ship_ready", "running", f"stale: {', '.join(issues)} — clearing"
                    )
                    if (
                        readback.get("role", "unknown") != "unknown"
                        or readback.get("customer_id") is not None
                    ):
                        await clear_role_lock(ztp_api_url, ztp_api_key, serial)
                    if readback.get("has_checkin_secret"):
                        await clear_checkin_secret(ztp_api_url, ztp_api_key, serial)
                    readback = await register_mikrotik(**register_kwargs)
                    issues = _ship_ready_issues(readback)
                if issues:
                    await on_progress("ship_ready", False, ", ".join(issues))
                    await finish(
                        False,
                        f"unit not ship-ready after remediation: {', '.join(issues)}",
                    )
                    return
                await on_progress(
                    "ship_ready", True, "role=unknown, no customer, no stale secret"
                )
        except Exception as exc:
            await on_progress("register", False, str(exc)[:100])
            await finish(False, f"wifi-api register failed: {exc}")
            return

        label_payload = _mikrotik_netinstall_label_payload(config, info)
        await on_progress("complete", True, "Netinstall Configure script + register complete")
        await finish(
            True,
            detail="Netinstall Configure script + register complete",
            label=label_payload,
        )
        logger.info(f"Netinstall + Configure script + register complete on port {port_number}: {serial}")

    except Exception as exc:
        logger.error(f"Netinstall pipeline failed on port {port_number}: {exc}", exc_info=True)
        await finish(False, str(exc)[:200])


@router.post("/credentials", response_model=Dict[str, str])
async def set_credentials(creds: CredentialOverride):
    """Set temporary credential override for a port."""
    _credential_overrides[creds.port_number] = creds
    return {"message": f"Credentials set for port {creds.port_number}"}


@router.delete("/credentials/{port_number}")
async def clear_credentials(port_number: int):
    """Clear credential override for a port."""
    if port_number in _credential_overrides:
        del _credential_overrides[port_number]
    return {"message": f"Credentials cleared for port {port_number}"}


@router.get("/credentials")
async def get_credential_overrides():
    """Get list of ports with credential overrides (passwords hidden)."""
    return {
        port: {
            "username": creds.username,
            "device_type": creds.device_type,
            "has_password": True,
        }
        for port, creds in _credential_overrides.items()
    }


def get_credential_override(port_number: int) -> Optional[CredentialOverride]:
    """Get credential override for a port (used by provisioner)."""
    return _credential_overrides.get(port_number)


async def _run_provisioning(
    provisioner,
    port_number: int,
    device_type: str,
    device_ip: str,
    req: ProvisionRequest,
):
    """Run provisioning in background task.

    Wraps _provision_port_device with proper port state management,
    matching what _run_port_provisioning does for auto-provisioning.
    """
    import asyncio

    # Mark port as actively provisioning (clears old failed state in UI)
    provisioner.port_manager.mark_port_provisioning(port_number, True)

    # Clear old result/error so UI doesn't flash the previous failure
    if port_number in provisioner.port_manager.port_states:
        state = provisioner.port_manager.port_states[port_number]
        state.last_result = None
        state.last_error = None
        state.provisioning_task = asyncio.current_task()

    success = False
    cancelled = False
    try:
        # Get custom credentials if set
        creds = _credential_overrides.get(port_number)
        custom_credentials = None
        if creds:
            custom_credentials = {"username": creds.username, "password": creds.password}

        success = await provisioner._provision_port_device(
            port_number,
            device_type,
            device_ip,
            custom_credentials=custom_credentials,
            provision_request=req,
        )

        # Clear credentials after use
        if port_number in _credential_overrides:
            del _credential_overrides[port_number]

    except asyncio.CancelledError:
        logger.warning(f"Retry provisioning cancelled for port {port_number} (device unplugged)")
        cancelled = True
        success = False
    except Exception as e:
        logger.exception(f"Background provisioning failed for port {port_number}")
        success = False
    finally:
        if port_number in provisioner.port_manager.port_states:
            state = provisioner.port_manager.port_states[port_number]
            state.provisioning_task = None
            state.expecting_reboot = False
        if not cancelled:
            provisioner.port_manager.mark_port_provisioning(port_number, False, success=success)


# ============================================================================
# History/Jobs Endpoints
# ============================================================================

@router.get("/jobs", response_model=List[JobStatus])
async def get_jobs(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
):
    """Get provisioning job history."""
    limit = min(max(limit, 1), 200)
    try:
        from ..db import get_db
        db = await get_db()
        jobs = await db.get_recent_jobs(limit=limit)
        
        return [
            JobStatus(
                job_id=job.id,
                status=job.status.value if hasattr(job.status, 'value') else job.status,
                port_number=job.port_number,
                device_type=job.device_type,
                device_model=job.device_model,
                mac_address=job.mac_address,
                serial_number=job.serial_number,
                ip_address=job.ip_address,
                started_at=job.started_at.isoformat() if job.started_at else None,
                completed_at=job.completed_at.isoformat() if job.completed_at else None,
                error_message=job.error_message,
                old_firmware=job.old_firmware,
                new_firmware=job.new_firmware,
                config_applied=job.config_applied,
            )
            for job in jobs
        ]
    except Exception as e:
        logger.warning(f"Could not fetch jobs: {e}")
        return []


@router.get("/jobs/{job_id}", response_model=JobStatus)
async def get_job(job_id: int, request: Request):
    """Get a specific provisioning job."""
    try:
        from ..db import get_db
        db = await get_db()
        job = await db.get_job(job_id)
        
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return JobStatus(
            job_id=job.id,
            status=job.status.value if hasattr(job.status, 'value') else job.status,
            port_number=job.port_number,
            device_type=job.device_type,
            device_model=job.device_model,
            mac_address=job.mac_address,
            serial_number=job.serial_number,
            ip_address=job.ip_address,
            started_at=job.started_at.isoformat() if job.started_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
            error_message=job.error_message,
            old_firmware=job.old_firmware,
            new_firmware=job.new_firmware,
            config_applied=job.config_applied,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Could not fetch job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# System Status Endpoints
# ============================================================================

@router.get("/status", response_model=SystemStatus)
async def get_system_status(request: Request):
    """Get overall system status."""
    provisioner = request.app.state.provisioner
    
    if not provisioner:
        return SystemStatus(
            running=False,
            mode="unknown",
            total_ports=0,
            active_ports=0,
            devices_detected=0,
            provisioning_in_progress=0,
        )
    
    port_status = {}
    if provisioner.port_manager:
        port_status = provisioner.port_manager.get_port_status()
    
    devices_detected = sum(1 for s in port_status.values() if s.get("device_detected"))
    provisioning = sum(1 for s in port_status.values() if s.get("provisioning"))
    active = sum(1 for s in port_status.values() if s.get("link_up"))
    
    return SystemStatus(
        running=provisioner._running,
        mode="vlan" if provisioner._use_vlan_mode else "simple",
        total_ports=len(port_status),
        active_ports=active,
        devices_detected=devices_detected,
        provisioning_in_progress=provisioning,
    )


# ============================================================================
# Feature Flags
# ============================================================================

@router.get("/features")
async def get_features():
    """Get current feature flag state."""
    from ..config import get_config
    return get_config().features.model_dump()


# ============================================================================
# Device Detection/Identification
# ============================================================================

@router.post("/ports/{port_number}/identify")
async def identify_device(port_number: int, request: Request):
    """Re-identify the device on a port."""
    provisioner = request.app.state.provisioner
    
    if not provisioner or not provisioner.port_manager:
        raise HTTPException(status_code=503, detail="Provisioner not available")
    
    port_status = provisioner.port_manager.get_port_status()
    if port_number not in port_status:
        raise HTTPException(status_code=404, detail="Port not found")
    
    status = port_status[port_number]
    if not status["link_up"]:
        raise HTTPException(status_code=400, detail="No link on port")
    
    # Trigger detection
    await provisioner.port_manager._detect_device_on_port(port_number)
    
    # Return updated status
    updated_status = provisioner.port_manager.get_port_status()[port_number]
    return {
        "device_detected": updated_status["device_detected"],
        "device_type": updated_status["device_type"],
        "device_ip": updated_status["device_ip"],
    }


# ============================================================================
# Mock Data (for development/testing)
# ============================================================================

def _get_mock_ports() -> List[PortStatus]:
    """Return mock port data for development."""
    return [
        PortStatus(
            port_number=1,
            vlan_id=1991,
            link_up=True,
            device_detected=True,
            device_type="cambium",
            device_ip="169.254.1.1",
            device_model="ePMP 3000",
            provisioning=False,
        ),
        PortStatus(
            port_number=2,
            vlan_id=1992,
            link_up=True,
            device_detected=True,
            device_type="mikrotik",
            device_ip="192.168.88.1",
            device_model="hAP ac²",
            provisioning=True,
        ),
        PortStatus(
            port_number=3,
            vlan_id=1993,
            link_up=False,
            device_detected=False,
            provisioning=False,
        ),
        PortStatus(
            port_number=4,
            vlan_id=1994,
            link_up=True,
            device_detected=True,
            device_type="tachyon",
            device_ip="169.254.1.1",
            device_model="TN-301",
            provisioning=False,
        ),
        PortStatus(
            port_number=5,
            vlan_id=1995,
            link_up=False,
            device_detected=False,
            provisioning=False,
        ),
        PortStatus(
            port_number=6,
            vlan_id=1996,
            link_up=True,
            device_detected=True,
            device_type="ubiquiti",
            device_ip="192.168.1.20",
            device_model="Rocket 5AC",
            provisioning=False,
        ),
    ]


# ============================================================================
# Firmware & Config Management Models
# ============================================================================

class FirmwareInfo(BaseModel):
    """Information about a firmware file."""
    device_type: str
    filename: str
    version: str
    size: int
    modified: str
    path: str


class ConfigInfo(BaseModel):
    """Information about a config file."""
    device_type: str
    filename: str
    config_type: str  # "template" or "override"
    size: int
    modified: str
    path: str


class ConfigAssetInfo(BaseModel):
    """Structured metadata for a family/mode-aware config asset."""
    path: str
    device_type: str
    config_type: str
    filename: str
    size: int
    modified: str
    family: Optional[str] = None
    firmware: Optional[str] = None
    role: Optional[str] = None
    mode: Optional[str] = None
    profile: Optional[str] = None
    link_profile: Optional[str] = None
    scope: Optional[str] = None
    asset_kind: str = "standard"
    secret_present: bool = False
    property_count: int = 0
    dynamic_fields: List[str] = Field(default_factory=list)
    content_type: str
    protected: bool
    editable: bool


class ConfigAssetUpdate(BaseModel):
    """Content update for one non-protected text asset."""
    path: str
    content: str


class FirmwareUrlRequest(BaseModel):
    """Request to download firmware from URL."""
    url: str
    device_type: str
    filename: Optional[str] = None  # Auto-detect from URL if not provided


class SetupSwitchRequest(BaseModel):
    """Request to configure a MikroTik provisioning switch."""
    ip: str = "192.168.88.1"
    username: str = "admin"
    password: str = ""
    skip_password_change: bool = False


class SeedTemplatesRequest(BaseModel):
    """Request to seed bundled templates into the live store."""
    overwrite: bool = False


# ============================================================================
# Firmware Management Endpoints
# ============================================================================

def _get_data_path(request: Request) -> Path:
    """Get the data path for firmware/configs."""
    provisioner = request.app.state.provisioner
    if provisioner and hasattr(provisioner, 'config'):
        return Path(provisioner.config.data.local_path)
    # Fallback to default
    return Path("/var/lib/provisioner/repo")


def _get_system_config_path() -> Path:
    """Get the system config.yaml path."""
    return Path("/etc/provisioner/config.yaml")


def _get_system_env_path() -> Path:
    """Get the system provisioner.env path."""
    return Path("/etc/provisioner/provisioner.env")


def _get_repo_root() -> Path:
    """Get the repository root."""
    return Path(__file__).resolve().parents[2]


# Valid device types derive from HANDLER_MAP — see
# provisioner.handler_manager.provisionable_device_types() (Story 2 / #72).


def _validate_device_type(device_type: str) -> str:
    """Validate device_type is a known type. Raises HTTPException if not."""
    sanitized = os.path.basename(device_type).lower().strip()
    if sanitized not in provisionable_device_types():
        raise HTTPException(status_code=400, detail=f"Invalid device type: {device_type}")
    return sanitized


def _sanitize_path_component(name: str) -> str:
    """Sanitize a single path component (filename or directory name).

    Strips directory traversal and null bytes.
    """
    name = os.path.basename(name)
    name = name.replace("\x00", "")
    if not name or name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid path component")
    return name


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing spaces, parentheses, and other problematic chars."""
    # Get just the filename without path
    name = os.path.basename(filename)
    # Remove null bytes
    name = name.replace("\x00", "")
    # Remove parentheses and their contents like "(1)"
    name = re.sub(r'\s*\([^)]*\)', '', name)
    # Replace spaces with nothing
    name = name.replace(' ', '')
    return name


def _extract_version_from_filename(filename: str) -> str:
    """Extract version number from firmware filename."""
    patterns = [
        r'[vV]?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
        r'[-_](\d+\.\d+(?:\.\d+)?)',
    ]
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            return match.group(1)
    return "unknown"


# Filename keywords that identify a vendor beyond its own device-type
# string. Hand-keyed per-vendor extras (like _template_requirements in
# setup_tools.py) — a vendor absent here simply matches on its
# device-type string alone, so use .get(), never direct indexing.
_DEVICE_TYPE_FILENAME_HINTS = {
    "cambium": ("epmp",),
    "mikrotik": ("routeros",),
    "ubiquiti": ("airos", "ubnt"),
}


def _get_device_type_from_filename(filename: str) -> Optional[str]:
    """Try to detect device type from filename."""
    filename_lower = filename.lower()
    for device_type in provisionable_device_types():
        hints = (device_type,) + _DEVICE_TYPE_FILENAME_HINTS.get(device_type, ())
        if any(hint in filename_lower for hint in hints):
            return device_type
    return None


# ============================================================================
# First-Run Setup Endpoints
# ============================================================================


@router.get("/setup/readiness")
async def setup_readiness(request: Request):
    """Return a first-run readiness checklist for the current bench."""
    provisioner = request.app.state.provisioner
    if not provisioner or not hasattr(provisioner, "config"):
        raise HTTPException(status_code=503, detail="Provisioner config not available")

    return build_readiness_report(
        provisioner.config,
        _get_data_path(request),
        config_path=_get_system_config_path(),
        env_path=_get_system_env_path(),
    )


@router.post("/setup/bundle/import")
async def setup_bundle_import(
    request: Request,
    file: UploadFile = File(...),
    apply_system_files: bool = Form(False),
):
    """Import a setup bundle archive into the local provisioner layout."""
    data_path = _get_data_path(request)
    suffix = Path(file.filename or "").suffix or ".bundle"
    tmp_path: Optional[Path] = None

    try:
        with NamedTemporaryFile(prefix="provisioner-setup-", suffix=suffix, delete=False) as handle:
            tmp_path = Path(handle.name)
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)

        return import_setup_bundle(
            tmp_path,
            file.filename or tmp_path.name,
            data_path=data_path,
            config_path=_get_system_config_path(),
            env_path=_get_system_env_path(),
            apply_system_files=apply_system_files,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Setup bundle import failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await file.close()
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


@router.get("/setup/bundle/export")
async def setup_bundle_export(request: Request, include_system_files: bool = False):
    """Export the current bench state as a portable setup bundle zip."""
    data_path = _get_data_path(request)
    download_name = f"provisioner-setup-{datetime.now().date().isoformat()}.zip"
    with NamedTemporaryFile(prefix="provisioner-export-", suffix=".zip", delete=False) as handle:
        bundle_path = Path(handle.name)

    try:
        result = write_setup_bundle(
            bundle_path,
            data_path=data_path,
            config_path=_get_system_config_path(),
            env_path=_get_system_env_path(),
            include_system_files=include_system_files,
        )
    except Exception as exc:
        bundle_path.unlink(missing_ok=True)
        logger.error(f"Setup bundle export failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return FileResponse(
        path=bundle_path,
        filename=download_name,
        media_type="application/zip",
        background=BackgroundTask(lambda path: Path(path).unlink(missing_ok=True), str(bundle_path)),
    )


@router.post("/setup/switch/configure")
async def setup_switch_configure(body: SetupSwitchRequest):
    """Configure a MikroTik switch for the provisioning bench."""
    script_path = _get_repo_root() / "scripts" / "setup_switch.sh"
    if not script_path.exists():
        raise HTTPException(status_code=500, detail="setup_switch.sh not found")

    cmd = [
        "/bin/bash",
        str(script_path),
        "--ip",
        body.ip,
        "--username",
        body.username,
        "--yes",
    ]
    if body.skip_password_change:
        cmd.append("--skip-password-change")

    try:
        child_env = os.environ.copy()
        child_env["PROVISIONER_SWITCH_PASSWORD"] = body.password
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(_get_repo_root()),
            env=child_env,
        )
        stdout, _ = await proc.communicate()
    except Exception as exc:
        logger.error(f"Failed to launch switch setup: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    output = (stdout or b"").decode(errors="replace")
    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Switch setup failed",
                "returncode": proc.returncode,
                "output": output[-4000:],
            },
        )

    return {
        "success": True,
        "message": "MikroTik switch configured for six ports, a WAN uplink, and a host trunk",
        "output": output[-4000:],
        "port_map": [
            "ether1-ether6: provisioning VLANs 1991-1996",
            "ether7: WAN uplink",
            "ether8: trunk to host",
        ],
    }


@router.post("/setup/templates/seed")
async def setup_seed_templates(request: Request, body: SeedTemplatesRequest):
    """Seed bundled repo templates into the live config store."""
    try:
        return seed_bundled_templates(
            _get_repo_root(),
            data_path=_get_data_path(request),
            overwrite=body.overwrite,
        )
    except Exception as exc:
        logger.error(f"Template seeding failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/setup/restart-service")
async def setup_restart_service():
    """Restart the provisioner-web systemd service after a short delay."""
    if not Path("/bin/sh").exists():
        raise HTTPException(status_code=500, detail="Shell not available for restart")

    try:
        subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                "sleep 1; systemctl restart provisioner-web",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:
        logger.error(f"Failed to schedule service restart: {exc}")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "success": True,
        "message": "Provisioner web service restart scheduled",
    }


@router.get("/firmware", response_model=List[FirmwareInfo])
async def list_firmware(request: Request):
    """List all available firmware files."""
    data_path = _get_data_path(request)
    firmware_path = data_path / "firmware"

    if not firmware_path.exists():
        return []

    firmware_list = []
    for device_dir in firmware_path.iterdir():
        if device_dir.is_dir() and not device_dir.name.startswith('.'):
            device_type = device_dir.name
            for fw_file in device_dir.iterdir():
                if fw_file.is_file() and not fw_file.name.startswith('.'):
                    stat = fw_file.stat()
                    firmware_list.append(FirmwareInfo(
                        device_type=device_type,
                        filename=fw_file.name,
                        version=_extract_version_from_filename(fw_file.name),
                        size=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        path=str(fw_file.relative_to(data_path)),
                    ))

    return sorted(firmware_list, key=lambda x: (x.device_type, x.filename))


@router.post("/firmware/upload")
async def upload_firmware(
    request: Request,
    file: UploadFile = File(...),
    device_type: str = Form(...),
):
    """Upload a firmware file."""
    device_type = _validate_device_type(device_type)
    data_path = _get_data_path(request)
    firmware_path = data_path / "firmware" / device_type
    firmware_path.mkdir(parents=True, exist_ok=True)

    # Sanitize filename - remove spaces, parentheses, etc.
    safe_filename = _sanitize_filename(file.filename)
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    dest_path = firmware_path / safe_filename
    tmp_path = dest_path.with_suffix(dest_path.suffix + ".part")

    try:
        # Stream to a .part file in chunks so memory stays bounded and a partial
        # upload never leaves a truncated file in place under the real name.
        bytes_written = 0
        with open(tmp_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                bytes_written += len(chunk)
        os.replace(tmp_path, dest_path)

        stat = dest_path.stat()
        return {
            "success": True,
            "message": f"Firmware uploaded: {safe_filename}",
            "firmware": {
                "device_type": device_type,
                "filename": safe_filename,
                "version": _extract_version_from_filename(safe_filename),
                "size": stat.st_size,
                "path": str(dest_path.relative_to(data_path)),
            }
        }
    except Exception as e:
        logger.error(f"Failed to upload firmware: {e}")
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/firmware/url")
async def download_firmware_from_url(
    request: Request,
    body: FirmwareUrlRequest,
):
    """Download firmware from a URL."""
    device_type = _validate_device_type(body.device_type)
    data_path = _get_data_path(request)

    # Determine filename from URL if not provided
    filename = body.filename
    if not filename:
        filename = body.url.split('/')[-1].split('?')[0]
        if not filename:
            raise HTTPException(status_code=400, detail="Could not determine filename from URL")

    # Sanitize
    safe_filename = _sanitize_filename(filename)
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    firmware_path = data_path / "firmware" / device_type
    firmware_path.mkdir(parents=True, exist_ok=True)
    dest_path = firmware_path / safe_filename

    tmp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(body.url, timeout=aiohttp.ClientTimeout(total=600)) as response:
                if response.status != 200:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to download: HTTP {response.status}"
                    )

                with open(tmp_path, "wb") as f:
                    async for chunk in response.content.iter_chunked(8192):
                        if chunk:
                            f.write(chunk)

        tmp_path.rename(dest_path)
        stat = dest_path.stat()
        return {
            "success": True,
            "message": f"Firmware downloaded: {safe_filename}",
            "firmware": {
                "device_type": device_type,
                "filename": safe_filename,
                "version": _extract_version_from_filename(safe_filename),
                "size": stat.st_size,
                "path": str(dest_path.relative_to(data_path)),
            }
        }
    except HTTPException:
        tmp_path.unlink(missing_ok=True)
        raise
    except aiohttp.ClientError as e:
        logger.error(f"Failed to download firmware: {e}")
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Download failed: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to save firmware: {e}")
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/firmware/{device_type}/{filename}")
async def delete_firmware(
    request: Request,
    device_type: str,
    filename: str,
):
    """Delete a firmware file."""
    device_type = _validate_device_type(device_type)
    filename = _sanitize_path_component(filename)
    data_path = _get_data_path(request)
    firmware_path = data_path / "firmware" / device_type / filename

    if not firmware_path.exists():
        raise HTTPException(status_code=404, detail="Firmware file not found")

    try:
        firmware_path.unlink()
        return {"success": True, "message": f"Deleted {filename}"}
    except Exception as e:
        logger.error(f"Failed to delete firmware: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class FirmwareMoveRequest(BaseModel):
    new_device_type: str


@router.post("/firmware/{device_type}/{filename}/move")
async def move_firmware(
    request: Request,
    device_type: str,
    filename: str,
    body: FirmwareMoveRequest,
):
    """Move a firmware file to a different device-type directory."""
    src_type = _validate_device_type(device_type)
    dst_type = _validate_device_type(body.new_device_type)
    filename = _sanitize_path_component(filename)
    data_path = _get_data_path(request)

    src_path = data_path / "firmware" / src_type / filename
    if not src_path.exists():
        raise HTTPException(status_code=404, detail="Firmware file not found")

    if src_type == dst_type:
        return {"success": True, "message": "No change", "device_type": dst_type}

    dst_dir = data_path / "firmware" / dst_type
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst_path = dst_dir / filename

    if dst_path.exists():
        raise HTTPException(
            status_code=409,
            detail=f"{filename} already exists under {dst_type}",
        )

    try:
        os.replace(src_path, dst_path)
        return {
            "success": True,
            "message": f"Moved {filename} to {dst_type}",
            "device_type": dst_type,
        }
    except Exception as e:
        logger.error(f"Failed to move firmware: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Firmware Checker Endpoints (auto-update checking)
# ============================================================================


class FirmwareDownloadRequest(BaseModel):
    """Request to download a specific discovered firmware."""
    vendor: str
    model: str
    version: str


@router.get("/firmware/checker-status")
async def firmware_checker_status(request: Request):
    """Get firmware auto-checker status."""
    from ..firmware_checker import get_firmware_checker

    checker = get_firmware_checker()
    if not checker:
        return {"enabled": False, "running": False, "sources": {}, "available_updates": []}

    return checker.get_status()


@router.post("/firmware/check-now")
async def firmware_check_now(request: Request, vendor: Optional[str] = None):
    """Manually trigger firmware check for new versions.

    Optionally filter by vendor (e.g., ?vendor=tachyon).
    """
    from ..firmware_checker import get_firmware_checker

    checker = get_firmware_checker()
    if not checker:
        raise HTTPException(status_code=503, detail="Firmware checker not initialized. Restart the provisioner.")

    if not checker._sources:
        raise HTTPException(
            status_code=503,
            detail="No firmware sources loaded. Restart the provisioner to reload sources.",
        )

    results = await checker.check_now(vendor)
    return {
        "updates_found": len(results),
        "updates": [
            {
                "vendor": fw.vendor,
                "model": fw.model,
                "version": fw.version,
                "filename": fw.filename,
                "download_url": fw.download_url,
                "channel": fw.channel,
            }
            for fw in results
        ],
    }


@router.post("/firmware/download-update")
async def firmware_download_update(
    request: Request,
    body: FirmwareDownloadRequest,
):
    """Download a specific firmware that was found during check."""
    from ..firmware_checker import get_firmware_checker

    checker = get_firmware_checker()
    if not checker:
        raise HTTPException(status_code=503, detail="Firmware checker not enabled")

    success = await checker.download_specific(body.vendor, body.model, body.version)
    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Firmware not found in available updates: {body.vendor}/{body.model}/{body.version}",
        )

    return {"success": True, "message": f"Downloaded {body.vendor} {body.model} {body.version}"}


class ChannelUpdateRequest(BaseModel):
    """Request to update firmware channel for a vendor source."""
    vendor: str
    channel: str


@router.post("/firmware/set-channel")
async def firmware_set_channel(request: Request, body: ChannelUpdateRequest):
    """Set the firmware channel for a vendor source at runtime.

    Channel options are vendor-specific (for example, MikroTik:
    "long-term", "stable", "testing").
    """
    from ..firmware_checker import get_firmware_checker

    checker = get_firmware_checker()
    if not checker:
        raise HTTPException(status_code=503, detail="Firmware checker not enabled")

    source = checker._sources.get(body.vendor)
    if not source:
        raise HTTPException(status_code=404, detail=f"No source configured for vendor: {body.vendor}")

    normalized_channel = checker.normalize_channel(body.vendor, body.channel)
    supported_channels = checker.get_supported_channels(body.vendor)
    if not normalized_channel:
        raise HTTPException(status_code=400, detail=f"Invalid channel '{body.channel}'")
    if normalized_channel not in supported_channels:
        raise HTTPException(
            status_code=400,
            detail=f"Channel must be one of: {', '.join(supported_channels)}",
        )

    # Update the source config in-memory
    if isinstance(source.config, dict):
        source.config["channel"] = normalized_channel
        source.config.pop("include_beta", None)
    else:
        # Pydantic model — replace with updated dict
        config_dict = source.config.model_dump()
        config_dict["channel"] = normalized_channel
        config_dict.pop("include_beta", None)
        source.config = config_dict

    return {
        "success": True,
        "vendor": body.vendor,
        "channel": normalized_channel,
        "message": f"Channel set to '{normalized_channel}' for {body.vendor}",
    }


@router.post("/firmware/checker-toggle")
async def firmware_checker_toggle(request: Request, enabled: bool = True):
    """Enable or disable the firmware checker at runtime."""
    from ..firmware_checker import get_firmware_checker

    checker = get_firmware_checker()
    if not checker:
        raise HTTPException(status_code=503, detail="Firmware checker not initialized")

    await checker.set_enabled(enabled)
    return {"success": True, "enabled": enabled}


# ============================================================================
# Config Management Endpoints
# ============================================================================


def _config_asset_catalog(request: Request) -> ConfigAssetCatalog:
    return ConfigAssetCatalog(_get_data_path(request))


def _config_asset_response(asset: ConfigAsset) -> ConfigAssetInfo:
    return ConfigAssetInfo(**asset.as_dict())


def _validate_family_directory(device_type: str, family: Optional[str]) -> None:
    """Reject a family name that is not declared by the vendor registry."""
    if not family:
        return
    spec = spec_for(device_type)
    if spec is None or family not in {entry.directory for entry in spec.config_families}:
        raise HTTPException(status_code=400, detail="Unknown config family")


def _validate_family_role(
    device_type: str,
    family: Optional[str],
    role: Optional[str],
    mode: Optional[str],
    profile: Optional[str],
) -> None:
    """Validate structured hierarchy fields against the registry contract."""
    if not family:
        if any(value for value in (role, mode, profile)):
            raise HTTPException(status_code=400, detail="Family is required for structured fields")
        return

    spec = spec_for(device_type)
    family_spec = next(
        (entry for entry in (spec.config_families if spec else ()) if entry.directory == family),
        None,
    )
    if family_spec is None:
        raise HTTPException(status_code=400, detail="Unknown config family")
    if role and role.upper() not in family_spec.roles:
        raise HTTPException(status_code=400, detail="Role is not supported by this config family")
    if mode and mode not in ("ap", "sm"):
        raise HTTPException(status_code=400, detail="Structured uploads support AP or SM mode only")
    if mode == "ap" and role and role.upper() != "AP":
        raise HTTPException(status_code=400, detail="AP mode requires AP role")
    if mode == "sm" and role and role.upper() != "SM":
        raise HTTPException(status_code=400, detail="SM mode requires SM role")
    if profile and role and role.upper() != "AP":
        raise HTTPException(status_code=400, detail="Profiles are supported only for AP assets")
    if profile and profile.lower() not in {"default", "north", "east", "south", "west"}:
        raise HTTPException(status_code=400, detail="Unknown AP profile")


def _contains_secret_key(value: Any) -> bool:
    """Detect credential-like keys without inspecting or logging their values."""
    if isinstance(value, dict):
        for key, child in value.items():
            key_lower = str(key).lower()
            if _SECRET_KEY_RE.search(key_lower) and child not in (None, "", [], {}):
                return True
            if _contains_secret_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_key(child) for child in value)
    return False


def _asset_config_for_ownership(filename: str, content: bytes) -> Optional[Dict[str, Any]]:
    """Return the JSON object inside a JSON or TAR asset, for the ownership gate."""
    lower_name = filename.lower()
    try:
        if lower_name.endswith(".json"):
            parsed = json.loads(content.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else None
        if lower_name.endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
                member = next(
                    (m for m in archive.getmembers() if Path(m.name).name == "config.json"),
                    None,
                )
                if member is None:
                    return None
                handle = archive.extractfile(member)
                parsed = json.load(handle) if handle is not None else None
                return parsed if isinstance(parsed, dict) else None
    except (ValueError, UnicodeDecodeError, tarfile.TarError, OSError):
        return None
    return None


def _asset_role_for_ownership(role: Optional[str], mode: Optional[str], filename: str) -> Optional[str]:
    """Infer the role a written asset declares. A flat baseline is SM."""
    if role:
        return role.upper()
    if mode in ("ap", "sm"):
        return mode.upper()
    if mode in ("ptp-a", "ptp-b"):
        return "PTP"
    base = Path(filename).name.lower()
    if base.startswith("ptp"):
        return "PTP"
    if base.startswith("ap"):
        return "AP"
    return "SM"


def _ownership_violations(
    device_type: str,
    config: Optional[Dict[str, Any]],
    role: Optional[str],
    family: Optional[str],
) -> List[str]:
    """Return field names (never values) that break the vendor's contract.

    Uploads that reach the active template tree must satisfy the field
    ownership contract (docs/PROVISIONING_NORTH_STAR.md), so a secret, a
    device default, or a site identity field can never enter a baseline.
    """
    if not isinstance(config, dict) or not role:
        return []
    from ..field_ownership import template_violations
    from ..vendor_registry import spec_for

    spec = spec_for(device_type)
    handler_cls = spec.handler_cls if spec else None
    contract = getattr(handler_cls, "FIELD_OWNERSHIP", None)
    if contract is None:
        return []
    return [
        "%s (%s)" % (violation.path, violation.reason)
        for violation in template_violations(contract, config, role, family, strict=True)
    ]


def _validate_uploaded_asset(
    filename: str,
    content: bytes,
    structured: bool,
    allow_field_export: bool = False,
) -> Optional[Dict[str, Any]]:
    """Validate JSON/TAR shape and return JSON when one is uploaded.

    Standard assets reject credential-like fields.  Native field exports are
    the explicit exception: they keep their secrets in protected runtime
    storage and are never returned by the content API.
    """
    lower_name = filename.lower()
    if lower_name.endswith(".json"):
        try:
            parsed = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON: %s" % exc)
        if not allow_field_export and _contains_secret_key(parsed):
            raise HTTPException(
                status_code=400,
                detail="Only field deployment exports may contain credential or secret fields",
            )
        return parsed if isinstance(parsed, dict) else None
    if allow_field_export:
        raise HTTPException(
            status_code=400,
            detail="Field deployment exports must be native Cambium JSON",
        )
    if lower_name.endswith((".tar", ".tar.gz", ".tgz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
                members = archive.getmembers()
                if not any(Path(member.name).name == "config.json" for member in members):
                    raise HTTPException(status_code=400, detail="TAR asset has no config.json")
                for member in members:
                    member_path = Path(member.name)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        raise HTTPException(status_code=400, detail="TAR contains an unsafe path")
                if structured:
                    config_member = next(
                        member for member in members if Path(member.name).name == "config.json"
                    )
                    config_file = archive.extractfile(config_member)
                    if config_file is not None:
                        parsed = json.load(config_file)
                        if _contains_secret_key(parsed):
                            raise HTTPException(
                                status_code=400,
                                detail="Family assets cannot contain credential or secret fields",
                            )
        except HTTPException:
            raise
        except (tarfile.TarError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Invalid TAR asset: %s" % exc)
    return None


def _protected_config_upload_path(data_root: Path, source_id: str, filename: str) -> Path:
    """Return the private path for one original field export."""
    return data_root / "config-uploads" / "cambium" / source_id / filename


def _store_protected_config_upload(
    data_root: Path,
    source_id: str,
    filename: str,
    content: bytes,
) -> Path:
    """Store exact upload bytes outside the catalog with private permissions."""
    destination = _protected_config_upload_path(data_root, source_id, filename)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    protected_root = data_root / "config-uploads"
    protected_vendor_root = protected_root / "cambium"
    for directory in (protected_root, protected_vendor_root, destination.parent):
        try:
            os.chmod(str(directory), 0o700)
        except OSError:
            pass
    temporary = destination.with_name(destination.name + ".part")
    temporary.write_bytes(content)
    os.chmod(str(temporary), 0o600)
    os.replace(str(temporary), str(destination))
    return destination


@router.get("/config-assets", response_model=List[ConfigAssetInfo])
async def list_config_assets(
    request: Request,
    device_type: Optional[str] = None,
    family: Optional[str] = None,
    firmware: Optional[str] = None,
    role: Optional[str] = None,
    mode: Optional[str] = None,
    scope: Optional[str] = None,
    config_type: Optional[str] = None,
):
    """List the recursive family/mode configuration catalog."""
    if device_type:
        device_type = _validate_device_type(device_type)
    try:
        assets = _config_asset_catalog(request).list_assets(
            device_type=device_type,
            family=family,
            firmware=firmware,
            role=role,
            mode=mode,
            scope=scope,
            config_type=config_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [_config_asset_response(asset) for asset in assets]


@router.get("/config-assets/metadata")
async def config_asset_metadata():
    """Return registry-derived family metadata and stable mode labels."""
    return {
        "families": config_family_metadata(),
        "modes": {
            "ap": "AP",
            "sm": "SM",
            "ptp-a": "PTP Main",
            "ptp-b": "PTP SM",
        },
        "scopes": {
            "family": "Family profile",
            "shared": "Shared baseline",
        },
        "asset_kinds": {
            "standard": "Standard template",
            "field_export": "Field deployment export",
        },
    }


@router.get("/config-assets/content")
async def get_config_asset_content(request: Request, path: str):
    """Return editable text content; protected assets never leave the host."""
    try:
        asset_path, asset = _config_asset_catalog(request).resolve(path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config asset not found")
    if asset.protected:
        raise HTTPException(status_code=403, detail="Protected runtime asset content is host-only")
    if not asset.editable:
        raise HTTPException(status_code=415, detail="This asset is not editable text")
    try:
        content = asset_path.read_text()
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not read config asset") from exc
    response = {"path": asset.path, "filename": asset.filename, "content": content}
    if asset.content_type == "json":
        try:
            response["parsed"] = json.loads(content)
        except json.JSONDecodeError:
            pass
    return response


@router.post("/config-assets/upload")
async def upload_config_asset(
    request: Request,
    file: UploadFile = File(...),
    config_type: str = Form("template"),
    device_type: str = Form(...),
    family: Optional[str] = Form(None),
    firmware: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    mode: Optional[str] = Form(None),
    profile: Optional[str] = Form(None),
    link_profile: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    asset_kind: str = Form("auto"),
    model: Optional[str] = Form(None),
    ptp_side: Optional[str] = Form(None),
):
    """Upload a deployment profile (AP or PTP) or a Cambium field export.

    The page sends family, role, and a direction (AP) or link plus side
    (PTP). The kind of file and the firmware of a field export are inferred.
    """
    device_type = _validate_device_type(device_type)
    if config_type not in ("template", "override"):
        raise HTTPException(status_code=400, detail="Invalid config type")
    if asset_kind not in ("standard", "field_export", "auto"):
        raise HTTPException(status_code=400, detail="Invalid asset kind")
    if ptp_side:
        if ptp_side.lower() not in ("a", "b"):
            raise HTTPException(status_code=400, detail="PTP side must be a or b")
        mode = "ptp-%s" % ptp_side.lower()
        role = role or "PTP"
    if role and role.upper() == "AP" and not mode:
        mode = "ap"
    if role and role.upper() == "SM" and not mode:
        mode = "sm"

    catalog = _config_asset_catalog(request)
    if asset_kind == "auto":
        peek = await file.read()
        await file.seek(0)
        inferred = "standard"
        if device_type == "cambium" and (file.filename or "").lower().endswith(".json"):
            try:
                from ..handlers.cambium import CambiumHandler

                if CambiumHandler.is_full_config_export(json.loads(peek.decode("utf-8"))):
                    inferred = "field_export"
            except (ValueError, UnicodeDecodeError):
                inferred = "standard"
        asset_kind = inferred
    is_field_export = asset_kind == "field_export"
    if is_field_export:
        if model:
            raise HTTPException(
                status_code=400,
                detail="Model inference is not supported for field exports",
            )
        if device_type != "cambium":
            raise HTTPException(status_code=400, detail="Field exports are supported for Cambium only")
        if config_type != "template":
            raise HTTPException(status_code=400, detail="Field exports must be templates")
        if not role or role.upper() not in {"AP", "SM", "PTP"}:
            raise HTTPException(status_code=400, detail="Field exports require an explicit AP, SM, or PTP role")
        if mode and mode not in ("ap", "sm", "ptp-a", "ptp-b"):
            raise HTTPException(status_code=400, detail="Invalid field export mode")
        if role.upper() == "SM" and mode and mode != "sm":
            raise HTTPException(status_code=400, detail="SM field exports require SM mode")
        if True:
            # Every field export lands in a model family. The runtime-only
            # shared profile is retired: it could not be linted in git.
            if scope not in (None, "family"):
                raise HTTPException(
                    status_code=400,
                    detail="The shared scope is retired; upload the export to a model family",
                )
            if not family:
                raise HTTPException(status_code=400, detail="Field exports require a model family")
            if not firmware:
                # Take the firmware from the export itself.
                try:
                    peek = await file.read()
                    await file.seek(0)
                    from ..handlers.cambium import CambiumHandler

                    firmware = CambiumHandler.field_export_metadata(json.loads(peek.decode("utf-8"))).get("firmware_version")
                except (ValueError, UnicodeDecodeError):
                    firmware = None
            if not firmware:
                raise HTTPException(status_code=400, detail="Field exports require a firmware version (not found in the export)")
            _validate_family_directory(device_type, family)
            spec = spec_for(device_type)
            family_spec = next(
                (entry for entry in (spec.config_families if spec else ()) if entry.directory == family),
                None,
            )
            if family_spec is None or role.upper() not in family_spec.roles:
                raise HTTPException(status_code=400, detail="Role is not supported by this config family")
            if role.upper() == "AP" and mode and mode != "ap":
                raise HTTPException(status_code=400, detail="AP field exports require AP mode")
            if role.upper() == "PTP":
                if mode and mode not in ("ptp-a", "ptp-b"):
                    raise HTTPException(status_code=400, detail="PTP field exports require PTP mode")
                if mode and not profile:
                    # The page sends the side (a/b); the side directory follows.
                    profile = MODE_TO_PTP_SIDE.get(mode)
                if not link_profile or not profile:
                    raise HTTPException(status_code=400, detail="PTP exports require link and side profiles")
                expected_profile = MODE_TO_PTP_SIDE.get(mode) if mode else None
                if expected_profile is None and profile.lower() not in {
                    value.lower() for value in MODE_TO_PTP_SIDE.values()
                }:
                    raise HTTPException(
                        status_code=400,
                        detail="PTP exports require a Main or SM side profile",
                    )
                if expected_profile and profile.lower() != expected_profile.lower():
                    raise HTTPException(
                        status_code=400,
                        detail=f"{mode} exports require the {expected_profile} side profile",
                    )
            elif profile and profile.lower() not in {"default", "north", "east", "south", "west"}:
                raise HTTPException(status_code=400, detail="Unknown AP profile")
        if scope is None:
            scope = "family"
    else:
        if model and scope == "shared":
            raise HTTPException(
                status_code=400,
                detail="Model-specific uploads cannot use the shared scope",
            )
        if model:
            try:
                family, role = catalog.infer_structured_fields_for_model(
                    device_type, model, family=family, role=role, mode=mode
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if family is None:
                raise HTTPException(
                    status_code=400,
                    detail="No config family is registered for this model",
                )
        if scope == "shared":
            raise HTTPException(
                status_code=400,
                detail="The shared scope is retired; upload the asset to a model family",
            )
        else:
            _validate_family_directory(device_type, family)
            _validate_family_role(device_type, family, role, mode, profile)
            if mode == "ptp-a" or mode == "ptp-b" or (role and role.lower() == "ptp"):
                raise HTTPException(status_code=403, detail="PTP assets use the host-only installation workflow")
            if mode == "ap" and role and role.lower() != "ap":
                raise HTTPException(status_code=400, detail="AP mode requires AP role")
            if mode == "sm" and role and role.lower() != "sm":
                raise HTTPException(status_code=400, detail="SM mode requires SM role")

    safe_filename = _sanitize_filename(file.filename or "")
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    try:
        content = await file.read()
        original_content = content
        parsed = _validate_uploaded_asset(
            safe_filename,
            content,
            structured=bool(family or scope == "shared") or is_field_export,
            allow_field_export=is_field_export,
        )
        upload_metadata = None
        source_id = None
        if is_field_export:
            from ..handlers.cambium import CambiumHandler

            if not CambiumHandler.is_full_config_export(parsed):
                raise HTTPException(
                    status_code=400,
                    detail="Field export must contain device_props and template_props",
                )
            upload_metadata = CambiumHandler.field_export_metadata(parsed)
            exported_firmware = upload_metadata.get("firmware_version")
            if not exported_firmware:
                raise HTTPException(
                    status_code=400,
                    detail="Field export must include a firmware version",
                )
            if _normalized_firmware_version(firmware) != _normalized_firmware_version(
                exported_firmware
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Selected firmware must match the native export firmware version",
                )
            role = role.upper()
            parsed = CambiumHandler.normalize_field_export(parsed, role)
            content = json.dumps(parsed, indent=2).encode("utf-8") + b"\n"
            source_id = uuid.uuid4().hex
            _store_protected_config_upload(
                _get_data_path(request), source_id, safe_filename, original_content,
            )

        gate_config = parsed if isinstance(parsed, dict) else _asset_config_for_ownership(safe_filename, content)
        violations = _ownership_violations(
            device_type,
            gate_config,
            _asset_role_for_ownership(role, mode, safe_filename),
            family,
        )
        if violations:
            raise HTTPException(
                status_code=400,
                detail="Template violates the field ownership contract: "
                + ", ".join(violations[:12]),
            )

        active_filename = "default.json" if is_field_export else safe_filename
        if model:
            destination = catalog.destination_for_model(
                config_type,
                device_type,
                model,
                family,
                firmware,
                role,
                mode,
                profile,
                link_profile,
                active_filename,
            )
        else:
            destination = catalog.destination(
                config_type,
                device_type,
                family,
                firmware,
                role,
                mode,
                profile,
                link_profile,
                active_filename,
                scope=scope,
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if is_field_export:
            try:
                os.chmod(str(destination.parent), 0o700)
            except OSError:
                pass
        temporary = destination.with_name(destination.name + ".part." + uuid.uuid4().hex)
        temporary.write_bytes(content)
        if is_field_export:
            os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(destination))
        data_root = _get_data_path(request).resolve()
        asset = _config_asset_catalog(request).resolve(
            str(destination.relative_to(data_root))
        )[1]
        response = {"success": True, "asset": _config_asset_response(asset)}
        if upload_metadata is not None:
            response["metadata"] = upload_metadata
            response["metadata"]["source_id"] = source_id
        return response
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        logger.error("Failed to upload config asset: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to store config asset") from exc


@router.put("/config-assets/content")
async def update_config_asset(request: Request, body: ConfigAssetUpdate):
    """Update one editable non-protected asset."""
    try:
        asset_path, asset = _config_asset_catalog(request).resolve(body.path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config asset not found")
    if asset.protected:
        raise HTTPException(status_code=403, detail="Protected runtime asset content is host-only")
    if not asset.editable:
        raise HTTPException(status_code=415, detail="This asset is not editable text")
    _validate_uploaded_asset(
        asset.filename,
        body.content.encode("utf-8"),
        structured=bool(asset.family or asset.scope == "shared"),
    )
    violations = _ownership_violations(
        asset.device_type,
        _asset_config_for_ownership(asset.filename, body.content.encode("utf-8")),
        _asset_role_for_ownership(asset.role, asset.mode, asset.filename),
        asset.family,
    )
    if violations:
        raise HTTPException(
            status_code=400,
            detail="Template violates the field ownership contract: " + ", ".join(violations[:12]),
        )
    try:
        temporary = asset_path.with_name(asset_path.name + ".part")
        temporary.write_text(body.content)
        os.replace(str(temporary), str(asset_path))
    except OSError as exc:
        logger.error("Failed to update config asset: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update config asset") from exc
    return {"success": True, "path": asset.path}


@router.delete("/config-assets/content")
async def delete_config_asset(request: Request, path: str):
    """Delete one editable non-protected asset."""
    try:
        asset_path, asset = _config_asset_catalog(request).resolve(path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Config asset not found")
    if asset.protected:
        raise HTTPException(status_code=403, detail="Protected PTP asset content is host-only")
    try:
        asset_path.unlink()
    except OSError as exc:
        logger.error("Failed to delete config asset: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to delete config asset") from exc
    return {"success": True, "path": asset.path}

@router.get("/configs", response_model=List[ConfigInfo])
async def list_configs(request: Request):
    """List all available config files."""
    data_path = _get_data_path(request)
    configs_path = data_path / "configs"

    if not configs_path.exists():
        return []

    config_list = []

    # Templates - organized by device type subdirectories
    templates_path = configs_path / "templates"
    if templates_path.exists():
        for item in templates_path.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                # Device type subdirectory
                device_type = item.name
                for config_file in item.iterdir():
                    if config_file.is_file() and config_file.suffix in ('.json', '.rsc', '.yaml', '.tar', '.gz'):
                        stat = config_file.stat()
                        config_list.append(ConfigInfo(
                            device_type=device_type,
                            filename=config_file.name,
                            config_type="template",
                            size=stat.st_size,
                            modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            path=str(config_file.relative_to(data_path)),
                        ))
            elif item.is_file() and item.suffix in ('.json', '.rsc', '.yaml', '.tar', '.gz'):
                # Legacy: files in root templates folder (try to detect type from filename)
                stat = item.stat()
                device_type = _get_device_type_from_filename(item.name) or "unknown"
                config_list.append(ConfigInfo(
                    device_type=device_type,
                    filename=item.name,
                    config_type="template",
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    path=str(item.relative_to(data_path)),
                ))

    # Overrides - organized by device type subdirectories
    overrides_path = configs_path / "overrides"
    if overrides_path.exists():
        for item in overrides_path.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                # Device type subdirectory
                device_type = item.name
                for config_file in item.iterdir():
                    if config_file.is_file() and config_file.suffix in ('.json', '.yaml'):
                        stat = config_file.stat()
                        config_list.append(ConfigInfo(
                            device_type=device_type,
                            filename=config_file.name,
                            config_type="override",
                            size=stat.st_size,
                            modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            path=str(config_file.relative_to(data_path)),
                        ))
            elif item.is_file() and item.suffix in ('.json', '.yaml'):
                # Legacy: files in root overrides folder
                stat = item.stat()
                device_type = _get_device_type_from_filename(item.name) or "unknown"
                config_list.append(ConfigInfo(
                    device_type=device_type,
                    filename=item.name,
                    config_type="override",
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    path=str(item.relative_to(data_path)),
                ))

    return sorted(config_list, key=lambda x: (x.config_type, x.device_type, x.filename))


@router.get("/configs/{config_type}/{device_type}/{filename}")
async def get_config_content(
    request: Request,
    config_type: str,
    device_type: str,
    filename: str,
):
    """Get the content of a config file."""
    device_type = _sanitize_path_component(device_type)
    filename = _sanitize_path_component(filename)
    data_path = _get_data_path(request)

    if config_type == "template":
        base_path = data_path / "configs" / "templates"
    elif config_type == "override":
        base_path = data_path / "configs" / "overrides"
    else:
        raise HTTPException(status_code=400, detail="Invalid config type")

    # Try new path structure first (with device_type subdirectory)
    config_path = base_path / device_type / filename

    # If not found and device_type is "unknown", check legacy path (root folder)
    if not config_path.exists() and device_type == "unknown":
        config_path = base_path / filename

    if not config_path.exists():
        raise HTTPException(status_code=404, detail="Config file not found")

    try:
        content = config_path.read_text()
        # Try to parse as JSON for validation
        if config_path.suffix == '.json':
            try:
                parsed = json.loads(content)
                if _contains_secret_key(parsed):
                    raise HTTPException(
                        status_code=403,
                        detail="Protected runtime asset content is host-only",
                    )
                return {"filename": filename, "content": content, "parsed": parsed}
            except json.JSONDecodeError:
                pass
        return {"filename": filename, "content": content}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to read config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/configs/upload")
async def upload_config(
    request: Request,
    file: UploadFile = File(...),
    config_type: str = Form(...),  # "template" or "override"
    device_type: str = Form(...),  # Required: cambium, mikrotik, tachyon, tarana
):
    """Upload a config file."""
    device_type = _validate_device_type(device_type)
    data_path = _get_data_path(request)

    if config_type == "template":
        config_path = data_path / "configs" / "templates" / device_type
    elif config_type == "override":
        config_path = data_path / "configs" / "overrides" / device_type
    else:
        raise HTTPException(status_code=400, detail="Invalid config type")

    config_path.mkdir(parents=True, exist_ok=True)

    # Sanitize filename - remove spaces, parentheses, etc.
    safe_filename = _sanitize_filename(file.filename)
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    dest_path = config_path / safe_filename

    try:
        content = await file.read()

        # Validate JSON if it's a JSON file
        if safe_filename.endswith('.json'):
            try:
                json.loads(content.decode('utf-8'))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

        _validate_uploaded_asset(safe_filename, content, structured=True)

        with open(dest_path, "wb") as f:
            f.write(content)

        stat = dest_path.stat()
        return {
            "success": True,
            "message": f"Config uploaded: {safe_filename}",
            "config": {
                "filename": safe_filename,
                "config_type": config_type,
                "device_type": device_type,
                "size": stat.st_size,
                "path": str(dest_path.relative_to(data_path)),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to upload config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/configs/{config_type}/{device_type}/{filename}")
async def update_config_content(
    request: Request,
    config_type: str,
    device_type: str,
    filename: str,
    body: dict,
):
    """Update the content of a config file."""
    device_type = _sanitize_path_component(device_type)
    filename = _sanitize_path_component(filename)
    data_path = _get_data_path(request)

    if config_type == "template":
        base_path = data_path / "configs" / "templates"
    elif config_type == "override":
        base_path = data_path / "configs" / "overrides"
    else:
        raise HTTPException(status_code=400, detail="Invalid config type")

    # Check if file exists at new path or legacy path
    config_path = base_path / device_type / filename
    legacy_path = base_path / filename

    # Use legacy path if it exists and new path doesn't
    if device_type == "unknown" and legacy_path.exists() and not config_path.exists():
        config_path = legacy_path
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)

    content = body.get("content")
    if content is None:
        raise HTTPException(status_code=400, detail="Content is required")

    try:
        # Validate JSON if it's a JSON file
        if filename.endswith('.json'):
            try:
                json.loads(content)
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

        _validate_uploaded_asset(filename, content.encode('utf-8'), structured=True)

        config_path.write_text(content)
        return {"success": True, "message": f"Config updated: {filename}"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/configs/{config_type}/{device_type}/{filename}")
async def delete_config(
    request: Request,
    config_type: str,
    device_type: str,
    filename: str,
):
    """Delete a config file."""
    device_type = _sanitize_path_component(device_type)
    filename = _sanitize_path_component(filename)
    logger.info(f"DELETE config: type={config_type}, device={device_type}, file={filename}")

    data_path = _get_data_path(request)
    logger.info(f"Data path: {data_path}")

    if config_type == "template":
        base_path = data_path / "configs" / "templates"
    elif config_type == "override":
        base_path = data_path / "configs" / "overrides"
    else:
        raise HTTPException(status_code=400, detail="Invalid config type")

    # Try new path structure first (with device_type subdirectory)
    config_path = base_path / device_type / filename
    logger.info(f"Checking new path: {config_path} (exists: {config_path.exists()})")

    # If not found and device_type is "unknown", check legacy path (root folder)
    if not config_path.exists() and device_type == "unknown":
        legacy_path = base_path / filename
        logger.info(f"Checking legacy path: {legacy_path} (exists: {legacy_path.exists()})")
        if legacy_path.exists():
            config_path = legacy_path

    if not config_path.exists():
        logger.warning(f"Config not found at {config_path}")
        # List what files ARE in the directory
        if base_path.exists():
            files = list(base_path.iterdir())
            logger.info(f"Files in {base_path}: {[f.name for f in files[:20]]}")
        raise HTTPException(status_code=404, detail=f"Config file not found: {filename}")

    try:
        config_path.unlink()
        logger.info(f"Deleted config: {config_path}")
        return {"success": True, "message": f"Deleted {filename}"}
    except Exception as e:
        logger.error(f"Failed to delete config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Device Types Info
# ============================================================================

@router.get("/device-types")
async def get_device_types():
    """Get list of supported device types."""
    return {
        "device_types": [
            {"id": "cambium", "name": "Cambium ePMP", "extensions": [".img", ".bin"]},
            {"id": "mikrotik", "name": "MikroTik RouterOS", "extensions": [".npk"]},
            {"id": "tachyon", "name": "Tachyon", "extensions": [".bin", ".img"]},
            {"id": "tarana", "name": "Tarana G1", "extensions": [".img", ".bin"]},
            {"id": "ubiquiti", "name": "Ubiquiti AirMax/Wave", "extensions": [".bin"]},
        ]
    }


@router.get("/test")
async def test_api():
    """Simple test endpoint to verify API is working."""
    return {"status": "ok", "message": "API is working"}


# ============================================================================
# Default Credentials Management
# ============================================================================

# Known factory-shipped logins for each device type, shown as read-only
# entries in the credentials UI, derived from the
# VendorSpec registry (Story 6 / #76): each vendor's default_credentials,
# unless its spec sets builtin_ui_credentials (Tarana ships
# admin/admin123, but the config default keeps an empty password because
# each fleet sets its own).
BUILTIN_CREDENTIALS = builtin_ui_credentials()


def _get_credentials_path(request: Request) -> Path:
    """Get the path to credentials.json file."""
    data_path = _get_data_path(request)
    return data_path / "credentials.json"


def _load_credentials(request: Request) -> Dict[str, List[Dict[str, str]]]:
    """Load credentials from file."""
    creds_path = _get_credentials_path(request)
    logger.debug(f"Loading credentials from {creds_path}")
    if creds_path.exists():
        try:
            with open(creds_path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load credentials from {creds_path}: {e}")
    return {}


def _save_credentials(request: Request, credentials: Dict[str, List[Dict[str, str]]]) -> None:
    """Save credentials to file."""
    creds_path = _get_credentials_path(request)
    logger.debug(f"Saving credentials to {creds_path}")
    try:
        creds_path.parent.mkdir(parents=True, exist_ok=True)
        with open(creds_path, "w") as f:
            json.dump(credentials, f, indent=2)
        logger.info(f"Saved credentials to {creds_path}")
    except Exception as e:
        logger.error(f"Failed to save credentials to {creds_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save credentials: {e}")


class DefaultCredential(BaseModel):
    """A single credential entry."""
    username: str
    password: str = ""


class DeviceCredentials(BaseModel):
    """Credentials for a device type."""
    device_type: str
    credentials: List[DefaultCredential]


@router.get("/default-credentials")
async def get_all_default_credentials(request: Request):
    """Get all credentials (custom + built-in) for all device types."""
    logger.debug("GET /default-credentials called")
    try:
        custom_creds = _load_credentials(request)

        result = []
        # provisionable_device_types() is sorted, for consistent ordering
        for device_type in provisionable_device_types():
            builtin = BUILTIN_CREDENTIALS.get(device_type, [])
            custom = custom_creds.get(device_type, [])

            # Add custom credentials (editable)
            for i, cred in enumerate(custom):
                result.append({
                    "device_type": device_type,
                    "username": cred.get("username", "admin"),
                    "password_hint": "*" * min(len(cred.get("password", "")), 8) or "(empty)",
                    "is_custom": True,
                    "index": i,
                })

            # Add builtin credentials (read-only)
            for cred in builtin:
                result.append({
                    "device_type": device_type,
                    "username": cred.get("username", "admin"),
                    "password_hint": "*" * min(len(cred.get("password", "")), 8) or "(empty)",
                    "is_custom": False,
                    "index": -1,
                })

        logger.debug(f"Returning {len(result)} credentials")
        return result
    except Exception as e:
        logger.error(f"Error in get_all_default_credentials: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/default-credentials/{device_type}")
async def get_device_credentials(request: Request, device_type: str):
    """Get credentials for a specific device type."""
    if device_type not in provisionable_device_types():
        raise HTTPException(status_code=400, detail=f"Invalid device type: {device_type}")

    custom_creds = _load_credentials(request)

    builtin = BUILTIN_CREDENTIALS.get(device_type, [])
    custom = custom_creds.get(device_type, [])

    result = []

    # Custom credentials (with index for deletion)
    for i, cred in enumerate(custom):
        result.append({
            "device_type": device_type,
            "username": cred.get("username", "admin"),
            "password_hint": "*" * min(len(cred.get("password", "")), 8) or "(empty)",
            "is_custom": True,
            "index": i,
        })

    # Built-in credentials
    for cred in builtin:
        result.append({
            "device_type": device_type,
            "username": cred.get("username", "admin"),
            "password_hint": "*" * min(len(cred.get("password", "")), 8) or "(empty)",
            "is_custom": False,
            "index": -1,
        })

    return result


@router.post("/default-credentials/{device_type}")
async def add_credential(
    request: Request,
    device_type: str,
    credential: DefaultCredential,
):
    """Add a custom credential for a device type."""
    logger.info(f"POST /default-credentials/{device_type} - Adding credential for user: {credential.username}")

    if device_type not in provisionable_device_types():
        logger.warning(f"Invalid device type: {device_type}")
        raise HTTPException(status_code=400, detail=f"Invalid device type: {device_type}")

    credentials = _load_credentials(request)

    if device_type not in credentials:
        credentials[device_type] = []

    # Check for duplicates
    for existing in credentials[device_type]:
        if existing.get("username") == credential.username and existing.get("password") == credential.password:
            return {"success": True, "message": "Credential already exists"}

    credentials[device_type].append({
        "username": credential.username,
        "password": credential.password,
    })

    _save_credentials(request, credentials)

    return {
        "success": True,
        "message": f"Credential added for {device_type}",
        "total_custom": len(credentials[device_type]),
    }


@router.delete("/default-credentials/{device_type}/{index}")
async def delete_credential(
    request: Request,
    device_type: str,
    index: int,
):
    """Delete a custom credential by index."""
    if device_type not in provisionable_device_types():
        raise HTTPException(status_code=400, detail=f"Invalid device type: {device_type}")

    credentials = _load_credentials(request)

    if device_type not in credentials:
        raise HTTPException(status_code=404, detail="No custom credentials for this device type")

    if index < 0 or index >= len(credentials[device_type]):
        raise HTTPException(status_code=404, detail=f"Credential index {index} not found")

    deleted = credentials[device_type].pop(index)
    _save_credentials(request, credentials)

    return {
        "success": True,
        "message": f"Deleted credential: {deleted.get('username')}",
        "remaining": len(credentials[device_type]),
    }


# ============================================================================
# Switch Port Events (MikroTik Webhook)
# ============================================================================

class SwitchPortEvent(BaseModel):
    """Port status event from MikroTik switch."""
    port: str  # MikroTik port name (e.g., "ether1", "ether2")
    link_up: bool  # Whether port has link
    speed: Optional[str] = None  # Link speed (e.g., "1Gbps")


@router.post("/switch/port-event")
async def switch_port_event(event: SwitchPortEvent, request: Request):
    """Receive port status events from MikroTik switch.

    The MikroTik switch sends webhooks when port link status changes.
    This allows immediate device detection without polling.

    Expected payload:
    {
        "port": "ether1",
        "link_up": true,
        "speed": "1Gbps"
    }
    """
    logger.info(f"Switch port event: {event.port} link_up={event.link_up} speed={event.speed}")

    provisioner = request.app.state.provisioner
    if not provisioner or not provisioner.port_manager:
        logger.warning("Switch port event received but provisioner not available")
        return {"success": False, "message": "Provisioner not available"}

    try:
        handled = await provisioner.port_manager.handle_switch_port_event(
            switch_port=event.port,
            link_up=event.link_up,
            speed=event.speed,
        )
        return {
            "success": handled,
            "port": event.port,
            "link_up": event.link_up,
        }
    except Exception as e:
        logger.error(f"Error handling switch port event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/switch/port-mapping")
async def get_switch_port_mapping(request: Request):
    """Get mapping of MikroTik port names to provisioner port numbers.

    Useful for debugging and configuring the switch.
    """
    provisioner = request.app.state.provisioner
    if not provisioner or not provisioner.port_manager:
        return {"ports": {}}

    return {
        "ports": provisioner.port_manager.get_switch_port_mapping(),
    }


# ============================================================================
# Display Control Endpoints
# ============================================================================

@router.post("/display/sleep")
async def sleep_display(request: Request):
    """Put display to sleep mode.

    This blanks the screen using DPMS, backlight, or framebuffer control.
    Called by frontend after idle timeout.
    """
    from ..display import get_display
    from .websocket import notify_display_state

    display = get_display()
    if not display:
        raise HTTPException(status_code=503, detail="Display controller not available")

    success = await display.sleep()

    if success:
        await notify_display_state(sleeping=True)

    return {
        "success": success,
        "sleeping": display.is_sleeping(),
    }


@router.post("/display/wake")
async def wake_display(request: Request):
    """Wake display from sleep mode.

    This turns the screen back on. Called by frontend on touch or device connect.
    """
    from ..display import get_display
    from .websocket import notify_display_state

    display = get_display()
    if not display:
        raise HTTPException(status_code=503, detail="Display controller not available")

    success = await display.wake()

    if success:
        await notify_display_state(sleeping=False)

    return {
        "success": success,
        "sleeping": display.is_sleeping(),
    }


@router.get("/display/status")
async def get_display_status(request: Request):
    """Get current display state and configuration."""
    from ..display import get_display

    display = get_display()
    if not display:
        return {
            "available": False,
            "sleeping": False,
            "sleep_timeout": 0,
            "wake_on_connect": True,
        }

    status = display.get_status()
    status["available"] = True
    return status


# ============================================================================
# Device Mode Endpoints (SM / AP / PTP)
# ============================================================================


def _validate_ptp_request(
    request: Request,
    port_manager: Any,
    port_number: int,
    status: Dict[str, Any],
    req: ApplyModeRequest,
    capabilities: Dict[str, Any],
    reserve: bool = True,
) -> str:
    """Validate the certified family pair and generated PTP settings.

    ``reserve=False`` (preview) validates without reserving the PTP side.
    """
    from ..mode_config import ModeConfigManager, make_ptp_link_id

    link_id = make_ptp_link_id(req.my_tower, req.remote_tower)
    side = port_manager.get_available_ptp_side(
        req.my_tower, req.remote_tower, port_num=port_number
    )
    peer = port_manager.get_ptp_peer(link_id, port_number)
    if peer is not None and not ptp_families_compatible(
        status.get("device_type"),
        status.get("device_model"),
        peer.get("device_type"),
        peer.get("device_model"),
    ):
        raise HTTPException(
            status_code=409,
            detail="The two device families are not certified for PTP",
        )

    if not capabilities.get("ptp_settings_required"):
        if reserve:
            _reserve_ptp_side(
                port_manager,
                req.my_tower,
                req.remote_tower,
                port_number,
                side,
                status.get("device_type"),
                status.get("device_model"),
            )
        return side

    mode = "ptp-a" if side == "a" else "ptp-b"
    manager = ModeConfigManager(
        str(_get_data_path(request) / "configs" / "templates")
    )
    template = manager.load_template(
        status.get("device_type"),
        mode,
        model=status.get("device_model"),
        link_profile=link_id,
        firmware=status.get("firmware_version"),
        require_firmware_match=True,
    )
    if template is None:
        raise HTTPException(
            status_code=409,
            detail="A certified PTP settings profile is required for this family and link",
        )

    naming = manager.generate_ptp_naming(
        req.my_tower,
        req.remote_tower,
        side,
        status.get("device_type"),
    )
    try:
        manager.generate_ptp_settings(
            template,
            naming,
            status.get("device_type"),
            side,
            status.get("device_model"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if reserve:
        _reserve_ptp_side(
            port_manager,
            req.my_tower,
            req.remote_tower,
            port_number,
            side,
            status.get("device_type"),
            status.get("device_model"),
        )
    return side


def _reserve_ptp_side(
    port_manager: Any,
    my_tower: int,
    remote_tower: int,
    port_number: int,
    side: str,
    device_type: Optional[str] = None,
    device_model: Optional[str] = None,
) -> None:
    """Reserve a side before the asynchronous mode task starts."""
    reserve = getattr(port_manager, "reserve_ptp_side", None)
    if not callable(reserve):
        return
    try:
        reserve(
            my_tower,
            remote_tower,
            port_number,
            requested_side=side,
            device_type=device_type,
            device_model=device_model,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _resolve_sm_template(
    request: Request,
    provisioner: Any,
    device_type: str,
    device_model: Optional[str],
):
    """Resolve the same standard SM template used by provisioning."""
    from ..config_resolver import ConfigResolver, JobContext, effective_role
    from ..config_store import ConfigStore

    resolver = getattr(provisioner, "config_resolver", None)
    if resolver is None:
        store = ConfigStore(str(_get_data_path(request)))
        handler_manager = getattr(provisioner, "handler_manager", None)
        resolver = ConfigResolver(store, handler_manager)

    config = getattr(provisioner, "config", None)
    provisioning_config = getattr(config, "provisioning", None)
    default_role = getattr(provisioning_config, "default_role", None)
    resolved = resolver.resolve(
        device_type,
        device_model,
        JobContext(role=effective_role(None, default_role)),
    )
    _, config_path = resolved.as_provision_args()
    if config_path is None:
        resolved.cleanup()
        return None, None
    return config_path, resolved


class ModePlan(BaseModel):
    """Validated plan for one mode change, shared by preview and apply."""

    port_number: int
    device_type: str
    device_ip: Optional[str] = None
    device_model: Optional[str] = None
    firmware: Optional[str] = None
    current_mode: Optional[str] = None
    target_mode: str
    naming: Dict[str, Any] = Field(default_factory=dict)
    ptp_link_id: Optional[str] = None
    ptp_side: Optional[str] = None
    peer: Optional[Dict[str, Any]] = None
    template_found: bool = False
    template_label: Optional[str] = None
    changes: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    sm_config_path: Optional[str] = None


def _plan_mode_change(
    request: Request,
    provisioner: Any,
    port_number: int,
    req: "ApplyModeRequest",
    reserve: bool = False,
):
    """Validate a mode change and describe what it will do.

    Every rule that ``apply-mode`` enforces lives here, so the preview shown
    to the operator is exactly what the apply will do. Raises
    ``HTTPException`` with the same codes as before. Returns
    ``(plan, resolved_sm_config)``; the caller owns the resolved artifact.
    """
    from ..config import get_config
    from ..mode_config import ModeConfigManager, make_ptp_link_id

    if not get_config().features.mode_config:
        raise HTTPException(status_code=503, detail="Mode configuration is disabled (feature flag)")
    if not provisioner:
        raise HTTPException(status_code=503, detail="Provisioner not available")
    port_manager = provisioner.port_manager
    if not port_manager:
        raise HTTPException(status_code=503, detail="Port manager not available")

    port_status = port_manager.get_port_status()
    if port_number not in port_status:
        raise HTTPException(status_code=404, detail="Port not found")
    status = port_status[port_number]
    if not status["device_detected"]:
        raise HTTPException(status_code=400, detail="No device detected on port")
    if status.get("mode_job"):
        raise HTTPException(status_code=409, detail="A mode change is already running on this port")

    device_type = status["device_type"]
    device_model = status.get("device_model")
    device_firmware = status.get("firmware_version")
    if req.mode not in ("sm", "ap", "ptp"):
        raise HTTPException(status_code=400, detail=f"Unknown mode: {req.mode}")

    capabilities = HandlerManager.operator_capabilities_for(device_type, device_model, device_firmware)
    is_sm_restore = req.mode == "sm"
    if not is_sm_restore and req.mode not in capabilities["post_provision_modes"]:
        reason = (capabilities.get("unqualified") or {}).get(req.mode)
        raise HTTPException(
            status_code=400,
            detail=reason or f"Mode configuration not supported for {device_type}",
        )

    current_mode = str(status.get("device_mode") or "")
    if is_sm_restore:
        if capabilities.get("required_baseline_mode") != "sm":
            raise HTTPException(
                status_code=400,
                detail=f"SM configuration restore not supported for {device_type}",
            )
        if current_mode != "ap" and not current_mode.startswith("ptp"):
            raise HTTPException(status_code=409, detail="The device is not in AP or PTP mode")

    baseline_mode = capabilities.get("required_baseline_mode") or ""
    baseline_label = baseline_mode.upper() if baseline_mode else "Standard"
    operation_label = "SM restore" if is_sm_restore else "AP/PTP conversion"
    if status.get("last_result") not in ("success", "complete"):
        raise HTTPException(
            status_code=409,
            detail=f"{baseline_label} provisioning must complete before {operation_label}",
        )
    if baseline_mode:
        checklist = status.get("checklist") or {}
        if checklist.get("config_upload") is not True or checklist.get("config_verify") is not True:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Verified {baseline_mode.upper()} configuration is required "
                    f"before {operation_label}"
                ),
            )

    plan = ModePlan(
        port_number=port_number,
        device_type=device_type,
        device_ip=status.get("device_ip"),
        device_model=device_model,
        firmware=device_firmware,
        current_mode=current_mode or "sm",
        target_mode=req.mode,
    )
    resolved_sm_config = None

    if is_sm_restore:
        sm_config_path, resolved_sm_config = _resolve_sm_template(
            request, provisioner, device_type, device_model
        )
        if sm_config_path is None:
            raise HTTPException(
                status_code=409,
                detail="A standard SM configuration template is required for restore",
            )
        plan.sm_config_path = sm_config_path
        plan.template_found = True
        plan.template_label = "Standard SM baseline"
        plan.changes = [
            {"field": "radio role", "from": current_mode, "to": "sm"},
            {"field": "hostname", "from": (status.get("mode_config") or {}).get("hostname"), "to": "standard SM"},
            {"field": "ssid", "from": (status.get("mode_config") or {}).get("ssid"), "to": "standard SM"},
        ]
        plan.warnings = ["PTP settings and link tracking will be cleared"] if current_mode.startswith("ptp") else []
        return plan, resolved_sm_config

    mcm = ModeConfigManager(str(_get_data_path(request) / "configs" / "templates"))
    if req.mode == "ap":
        if req.tower is None or req.direction is None:
            raise HTTPException(status_code=400, detail="AP mode requires 'tower' and 'direction'")
        naming = mcm.generate_ap_naming(req.tower, req.direction, device_type)
        mode = "ap"
        profile = req.direction.title()
        link_profile = None
    else:
        if req.my_tower is None or req.remote_tower is None:
            raise HTTPException(status_code=400, detail="PTP mode requires 'my_tower' and 'remote_tower'")
        side = _validate_ptp_request(
            request, port_manager, port_number, status, req, capabilities, reserve=reserve
        )
        plan.ptp_link_id = make_ptp_link_id(req.my_tower, req.remote_tower)
        plan.ptp_side = side
        plan.peer = port_manager.get_ptp_peer(plan.ptp_link_id, port_number) if hasattr(port_manager, "get_ptp_peer") else None
        naming = mcm.generate_ptp_naming(req.my_tower, req.remote_tower, side, device_type)
        mode = "ptp-%s" % side
        profile = None
        link_profile = plan.ptp_link_id

    plan.naming = dict(naming)
    template = mcm.load_template(
        device_type,
        mode,
        model=device_model,
        profile=profile,
        link_profile=link_profile,
        firmware=device_firmware,
        require_firmware_match=True,
    )
    plan.template_found = template is not None
    plan.template_label = "%s / %s%s" % (
        mode.upper(),
        device_model or device_type,
        (" / " + str(device_firmware)) if device_firmware else "",
    )
    if req.mode == "ptp" and capabilities.get("ptp_settings_required") and not template:
        raise HTTPException(
            status_code=409,
            detail="A certified PTP settings profile is required for this family and link",
        )
    plan.changes = [
        {"field": "radio role", "from": current_mode or "sm", "to": mode},
        {"field": "hostname", "from": "standard SM", "to": naming.get("hostname")},
        {"field": "ssid", "from": "standard SM", "to": naming.get("ssid")},
    ]
    if req.antenna_gain_db is not None:
        plan.changes.append({"field": "antenna gain", "from": "device default", "to": req.antenna_gain_db})
    return plan, None


@router.post("/ports/{port_number}/mode-preview")
async def preview_device_mode(port_number: int, req: ApplyModeRequest, request: Request):
    """Describe what a mode change would do, without changing anything.

    Identity values shown are the generated hostname and SSID only. Secrets
    are never part of the preview.
    """
    provisioner = request.app.state.provisioner
    plan, resolved = _plan_mode_change(request, provisioner, port_number, req)
    if resolved is not None:
        resolved.cleanup()
    body = plan.model_dump()
    body.pop("sm_config_path", None)
    body["ok"] = True
    return body


@router.post("/ports/{port_number}/apply-mode")
async def apply_device_mode(
    port_number: int,
    req: ApplyModeRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Apply a device mode (SM, AP, or PTP) to a provisioned device.

    After standard SM provisioning completes, this endpoint lets the user
    reconfigure the device as an AP or PTP endpoint. A device in AP or PTP
    mode can use this endpoint to restore its standard SM configuration.
    The same plan that ``mode-preview`` returns is enforced here.
    """
    provisioner = request.app.state.provisioner
    plan, resolved_sm_config = _plan_mode_change(
        request, provisioner, port_number, req, reserve=True
    )
    port_manager = provisioner.port_manager

    steps = [{"key": "connect", "label": "Connect"}, {"key": "apply", "label": "Apply"}, {"key": "verify", "label": "Verify"}]
    job_id = None
    begin = getattr(port_manager, "begin_mode_job", None)
    if callable(begin):
        job_id = begin(port_number, plan.target_mode if plan.target_mode != "ptp" else "ptp-%s" % plan.ptp_side, steps)

    background_tasks.add_task(
        _run_apply_mode,
        provisioner,
        port_number,
        plan.device_type,
        plan.device_ip,
        req,
        plan.sm_config_path,
        resolved_sm_config,
    )
    return {"success": True, "job_id": job_id, "message": f"Applying {req.mode} mode on port {port_number}"}


class HostCredentialUpdate(BaseModel):
    """Credential values to set in the host config.yaml. Never echoed back."""
    username: Optional[str] = None
    password: Optional[str] = None
    backup_password: Optional[str] = None
    wpa_key: Optional[str] = None
    snmp_community: Optional[str] = None


_host_config_restart_required = False


def _baseline_witnesses(device_type: str) -> Dict[str, Dict[str, Any]]:
    """Return ``family -> {models: [...], fresh_sm_proven: bool}`` from evidence manifests."""
    import yaml as _yaml
    from ..qualification import evidence_root, recorded_transitions
    from ..vendor_registry import config_family_for_model

    result = {}  # type: Dict[str, Dict[str, Any]]
    root = evidence_root()
    for manifest_path in sorted(root.glob("%s/*/*/manifest.yaml" % device_type)) if root.is_dir() else []:
        try:
            manifest = _yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if str(manifest.get("config_role", "")).upper() != "SM":
            continue
        family = config_family_for_model(device_type, manifest.get("model"))
        if family is None:
            continue
        entry = result.setdefault(family.directory, {"models": [], "fresh_sm_proven": False})
        label = "%s %s" % (manifest.get("model"), manifest.get("firmware"))
        if str(manifest.get("fixture_witness", "role")) == "baseline":
            entry["models"].append(label)
        if ("fresh", "sm") in recorded_transitions(device_type, manifest.get("model"), manifest.get("firmware")):
            entry["fresh_sm_proven"] = True
    return result


@router.get("/config-baselines")
async def get_config_baselines(request: Request, device_type: str):
    """Per family: the git SM baseline, its install state on the host, lint, and evidence."""
    from ..config_assets import ConfigAssetCatalog
    from ..config_templates import ConfigTemplateError, load_config_template
    from ..field_ownership import template_violations
    from ..vendor_registry import spec_for

    device_type = _validate_device_type(device_type)
    spec = spec_for(device_type)
    repo_root = _get_repo_root() / "configs" / "templates"
    data_root = _get_data_path(request)
    contract = getattr(spec.handler_cls, "FIELD_OWNERSHIP", None) if spec and spec.handler_cls else None
    runtime_assets = ConfigAssetCatalog(data_root).list_assets(device_type=device_type, config_type="template")
    witnesses = _baseline_witnesses(device_type)
    families = []
    for family in (spec.config_families if spec else ()):
        repo_sm = sorted((repo_root / device_type / family.directory).rglob("default.*"))
        repo_sm = [p for p in repo_sm if "SM" in p.relative_to(repo_root / device_type / family.directory).parts[:-1]]
        runtime_sm = [a for a in runtime_assets if a.family == family.directory and a.role and a.role.upper() == "SM"]
        repo_path = repo_sm[0] if repo_sm else None
        runtime_path = (data_root / runtime_sm[0].path) if runtime_sm else None
        in_sync = bool(repo_path and runtime_path and runtime_path.is_file() and repo_path.read_bytes() == runtime_path.read_bytes())
        lint = []  # type: List[str]
        if runtime_path and runtime_path.is_file() and contract is not None:
            try:
                config = load_config_template(str(runtime_path)).config
                lint = ["%s (%s)" % (v.path, v.reason) for v in template_violations(contract, config, "SM", family.directory, strict=True)]
            except ConfigTemplateError as exc:
                lint = ["cannot load: %s" % exc]
        if not repo_path:
            status = "no_repo_baseline"
        elif not runtime_path:
            status = "not_installed"
        elif lint:
            status = "lint_problem"
        elif not in_sync:
            status = "out_of_date"
        else:
            status = "installed"
        profiles = [a.as_dict() for a in runtime_assets if a.family == family.directory and a.role and a.role.upper() in ("AP", "PTP")]
        witness = witnesses.get(family.directory, {"models": [], "fresh_sm_proven": False})
        families.append({
            "family": family.directory,
            "name": family.name,
            "roles": list(family.roles),
            "models": list(family.model_patterns),
            "sm_baseline": {
                "status": status,
                "repo_path": str(repo_path.relative_to(_get_repo_root())) if repo_path else None,
                "runtime_path": runtime_sm[0].path if runtime_sm else None,
                "in_sync": in_sync,
                "lint": lint[:12],
                "witnesses": witness["models"],
                "fresh_sm_proven": witness["fresh_sm_proven"],
            },
            "profiles": profiles,
        })
    return {"device_type": device_type, "uses_files": bool(spec and spec.config_template_dir), "families": families}


class BaselineSyncRequest(BaseModel):
    device_type: str
    family: Optional[str] = None


@router.post("/config-baselines/sync")
async def sync_config_baselines(request: Request, body: BaselineSyncRequest):
    """Install (or refresh) the tracked repo templates for one vendor on the host."""
    device_type = _validate_device_type(body.device_type)
    if body.family:
        _validate_family_directory(device_type, body.family)
    try:
        return seed_bundled_templates(
            _get_repo_root(),
            data_path=_get_data_path(request),
            overwrite=True,
            device_type=device_type,
            family=body.family,
        )
    except Exception as exc:
        logger.error("Baseline sync failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/host-credentials")
async def get_host_credentials(request: Request):
    """Per vendor: which credential keys are set on the host. Never the values."""
    from ..config import get_config
    from ..host_config import EDITABLE_KEYS

    config = get_config()
    configured = getattr(config, "credentials", None) or {}
    rows = []
    for device_type in provisionable_device_types():
        creds = configured.get(device_type)
        handler_class = HandlerManager.handler_class_for(device_type)
        required = []
        if handler_class is not None:
            try:
                probe = handler_class(ip="0.0.0.0", credentials={k: getattr(creds, k, "") for k in ("username", "password", "wpa_key", "snmp_community")})
                required = list(probe.required_secrets())
            except Exception:
                required = []
        rows.append({
            "device_type": device_type,
            "username": getattr(creds, "username", "") or "",
            "keys": {key: bool(getattr(creds, key, "")) for key in EDITABLE_KEYS if key != "username"},
            "required_secrets": required,
            "missing_secrets": [key for key in required if not getattr(creds, key, "")],
        })
    return {"credentials": rows, "restart_required": _host_config_restart_required}


@router.put("/host-credentials/{device_type}")
async def put_host_credentials(device_type: str, body: HostCredentialUpdate):
    """Set credential keys in the host config.yaml. A service restart applies them."""
    global _host_config_restart_required
    from ..host_config import set_credential_values

    device_type = _validate_device_type(device_type)
    path = _get_system_config_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Host config file not found")
    values = {k: v for k, v in body.model_dump().items() if v is not None}
    if not values:
        raise HTTPException(status_code=400, detail="No credential values supplied")
    try:
        changed = set_credential_values(path, device_type, values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not write the host config: %s" % exc.__class__.__name__) from exc
    if changed:
        _host_config_restart_required = True
    return {"success": True, "changed": changed, "restart_required": _host_config_restart_required}


@router.get("/ptp-links")
async def get_ptp_links(request: Request):
    """Get all active PTP links.

    Returns links with side and family info so the UI can show the paired
    endpoint and the API can enforce the certified family matrix.
    """
    provisioner = request.app.state.provisioner
    if not provisioner or not provisioner.port_manager:
        return {"links": {}}

    links = provisioner.port_manager.get_ptp_links()
    return {"links": links}


async def _run_apply_mode(
    provisioner,
    port_number: int,
    device_type: str,
    device_ip: str,
    req: ApplyModeRequest,
    sm_config_path: Optional[str] = None,
    resolved_sm_config: Any = None,
):
    """Apply device mode in a background task."""
    from ..fingerprint import DeviceType, identify_device
    from ..mode_config import get_mode_config_manager, make_ptp_link_id
    from .websocket import notify_port_change

    port_manager = provisioner.port_manager
    mcm = get_mode_config_manager() if req.mode != "sm" else None
    device_model = (port_manager.get_port_status().get(port_number) or {}).get("device_model")
    device_firmware = (port_manager.get_port_status().get(port_number) or {}).get(
        "firmware_version"
    )
    ptp_link_id = None
    ptp_side = None
    ptp_reservation_active = False

    try:
        capabilities = HandlerManager.operator_capabilities_for(
            device_type, device_model, device_firmware
        )
        # Determine mode and naming
        if req.mode == "sm":
            mode = "sm"
            naming = {}
            ptp_link_id = None
        elif req.mode == "ap":
            mode = "ap"
            naming = mcm.generate_ap_naming(req.tower, req.direction, device_type)
            ptp_link_id = None
        else:
            # PTP: auto-assign side
            ptp_link_id = make_ptp_link_id(req.my_tower, req.remote_tower)
            get_reserved_side = getattr(port_manager, "get_reserved_ptp_side", None)
            if callable(get_reserved_side):
                ptp_side = get_reserved_side(ptp_link_id, port_number)
                ptp_reservation_active = ptp_side is not None
            if ptp_side is None:
                reserve = getattr(port_manager, "reserve_ptp_side", None)
                if callable(reserve):
                    ptp_side = reserve(
                        req.my_tower,
                        req.remote_tower,
                        port_number,
                        device_type=device_type,
                        device_model=device_model,
                    )
                    ptp_reservation_active = True
                else:
                    ptp_side = port_manager.get_available_ptp_side(
                        req.my_tower, req.remote_tower, port_num=port_number
                    )
            mode = f"ptp-{ptp_side}"
            naming = mcm.generate_ptp_naming(
                req.my_tower, req.remote_tower, ptp_side, device_type,
            )
            peer = port_manager.get_ptp_peer(ptp_link_id, port_number)
            if peer is not None and not ptp_families_compatible(
                device_type,
                device_model,
                peer.get("device_type"),
                peer.get("device_model"),
            ):
                logger.error(
                    "Refusing uncertified PTP family pair on port %s",
                    port_number,
                )
                return

        if req.mode == "sm":
            logger.info(
                f"Applying standard SM config to port {port_number} ({device_type})"
            )
        else:
            logger.info(
                f"Applying {mode} to port {port_number} ({device_type}): "
                f"hostname={naming['hostname']}, ssid={naming['ssid']}"
            )

        # Load the model family profile.  AP directions map directly to the
        # standard library's North/East/South/West directories.  PTP side A
        # resolves Main and side B resolves SM inside ModeConfigManager.
        profile = req.direction.title() if req.mode == "ap" and req.direction else None
        template = None
        if req.mode != "sm":
            template = mcm.load_template(
                device_type,
                mode,
                model=device_model,
                profile=profile,
                link_profile=ptp_link_id,
                firmware=device_firmware,
                require_firmware_match=True,
            )
        if req.mode == "ptp" and capabilities.get("ptp_settings_required") and not template:
            logger.error(
                "Required PTP settings profile disappeared before applying mode "
                "on port %s",
                port_number,
            )
            return

        # Create handler and connect
        interface = port_manager.get_interface_for_port(port_number)
        fingerprint = await identify_device(device_ip, mac=None, interface=interface)

        if fingerprint.device_type == DeviceType.UNKNOWN and device_type:
            fingerprint.device_type = DeviceType(device_type)

        handler = provisioner.handler_manager.get_handler(
            fingerprint, device_ip, interface=interface,
        )
        if not handler:
            logger.error(f"No handler for {device_type} on port {port_number}")
            finish = getattr(port_manager, "finish_mode_job", None)
            if callable(finish):
                finish(port_number, False, "No handler for this device")
            return

        job_update = getattr(port_manager, "update_mode_job", None)
        job_finish = getattr(port_manager, "finish_mode_job", None)

        def _step(key, status, detail=None):
            if callable(job_update):
                job_update(port_number, key, status, detail)

        _step("connect", "loading")
        connected = await handler.connect()
        if not connected:
            logger.error(f"Failed to connect to {device_type} at {device_ip} for mode config")
            _step("connect", False, "login failed")
            if callable(job_finish):
                job_finish(port_number, False, "Could not connect to the device")
            return
        _step("connect", True)

        error_detail = None
        try:
            _step("apply", "loading")
            if req.mode == "sm":
                if not sm_config_path:
                    logger.error(
                        "Cannot restore SM config without a resolved template "
                        "on port %s",
                        port_number,
                    )
                    _step("apply", False, "no SM template")
                    return
                success = await handler.apply_config_file(sm_config_path)
                _step("apply", bool(success))
                if success:
                    _step("verify", "loading")
                    expectations_hook = getattr(handler, "applied_config_expectations", None)
                    expectations = expectations_hook() if callable(expectations_hook) else None
                    if expectations:
                        success = await handler.verify_config(expectations) is True
                    else:
                        success = await handler.verify_config() is True
                    mismatches = list(getattr(handler, "last_verify_mismatches", []) or [])
                    error_detail = ("mismatch: " + ", ".join(mismatches[:6])) if (not success and mismatches) else None
                    _step("verify", bool(success), error_detail)
            # Apply config: template + generated identity/radio settings, or
            # just naming for handlers that explicitly allow the fallback.
            elif template:
                if req.mode == "ptp":
                    rendered = mcm.generate_ptp_settings(
                        template,
                        naming,
                        device_type,
                        ptp_side,
                        device_model,
                    )
                else:
                    rendered = mcm.render_template(template, naming, device_type)
                # apply_mode_config verifies fail-closed inside the handler.
                success = await handler.apply_mode_config(rendered)
                mismatches = list(getattr(handler, "last_verify_mismatches", []) or [])
                error_detail = ("mismatch: " + ", ".join(mismatches[:6])) if (not success and mismatches) else None
                _step("apply", bool(success), error_detail)
                _step("verify", bool(success))
            elif req.mode == "ptp" and capabilities.get("ptp_settings_required"):
                logger.error(
                    "Cannot apply PTP mode without the required settings profile "
                    "on port %s",
                    port_number,
                )
                _step("apply", False, "no PTP settings profile")
                return
            else:
                # No template — just apply hostname/SSID via apply_ap_naming
                success = await handler.apply_ap_naming(
                    naming["hostname"], naming["ssid"],
                )
                _step("apply", bool(success))
                _step("verify", "skipped")

            if success and req.mode != "sm":
                success = await handler.apply_antenna_gain(
                    req.antenna_gain_db,
                    model=device_model or fingerprint.model,
                )
                if not success:
                    error_detail = "antenna gain"

            if success:
                logger.info(f"Mode {mode} applied successfully on port {port_number}")
                if req.mode == "sm":
                    port_manager.clear_device_mode(port_number)
                else:
                    port_manager.set_device_mode(
                        port_number, mode, naming, ptp_link_id,
                    )
                ptp_reservation_active = False
            else:
                logger.error(f"Failed to apply {mode} config on port {port_number}")
            if callable(job_finish):
                job_finish(port_number, bool(success), None if success else (error_detail or "apply failed"))
        finally:
            await handler.disconnect()

        # Broadcast updated port status
        port_status_data = port_manager._get_single_port_status(port_number)
        await notify_port_change(port_number, port_status_data)

    except Exception as e:
        logger.exception(f"Error applying mode on port {port_number}: {e}")
        finish = getattr(port_manager, "finish_mode_job", None)
        if callable(finish):
            finish(port_number, False, "Unexpected error during mode change")
    finally:
        if getattr(port_manager, "port_states", None) is not None:
            state = port_manager.port_states.get(port_number)
            if state is not None and state.mode_job:
                port_manager.finish_mode_job(port_number, False, "Mode change did not complete")
        if ptp_reservation_active and ptp_link_id and ptp_side:
            release = getattr(port_manager, "release_ptp_side", None)
            if callable(release):
                release(ptp_link_id, port_number, ptp_side)
        if resolved_sm_config is not None:
            resolved_sm_config.cleanup()


# ============================================================================
# Vendor UI Metadata (Story 5 / #75)
# ============================================================================
#
# The kiosk dashboard's `deviceVendors` map is no longer hardcoded in
# index.html: the dashboard route (web/app.py) injects vendor_ui_metadata()
# into the template server-side, so adding a vendor to HANDLER_MAP needs
# zero JS edits and the long-lived kiosk Chromium can never serve a stale
# vendor list (see docs/KIOSK_ARCHITECTURE.md on kiosk uptimes).
#
# The vendor *list* derives from provisionable_device_types() (HANDLER_MAP,
# Story 2 / #72) plus two documented exceptions (same as
# tests/test_vendor_registry.py):
#   - evolution_digital: a real DeviceType dispatched via the main.py
#     side-door, intentionally absent from HANDLER_MAP.
#   - unknown: a UI-only fallback card, not a vendor.
#
# _VENDOR_UI_STYLE is presentation data (display name, accent color),
# derived from each VendorSpec's ui_style (Story 6 / #76): entries are
# looked up with .get() and any vendor missing from it still renders with
# derived defaults. `unknown` is the UI-only fallback card, not a vendor,
# so its style stays here rather than in the registry.

_VENDOR_UI_STYLE: Dict[str, Dict[str, str]] = dict(ui_styles())
_VENDOR_UI_STYLE["unknown"] = {"name": "Unknown", "color": "#6b7280"}

# Fallback accent for a vendor without a style entry (same gray as `unknown`).
_DEFAULT_VENDOR_COLOR = "#6b7280"

_VENDOR_ICONS_DIR = Path(__file__).parent / "static" / "vendor-icons"


def _vendor_default_user(device_type: str) -> str:
    """Default-username hint for the kiosk's custom-credentials form.

    Read-only indirection over the credentials source so the UI hint can
    never drift from it (it is the first builtin entry's username; "" when
    the vendor has no builtin credentials, e.g. evolution_digital).
    BUILTIN_CREDENTIALS itself derives from the VendorSpec registry
    (Story 6 / #76).
    """
    builtin = BUILTIN_CREDENTIALS.get(device_type, [])
    if not builtin:
        return ""
    return builtin[0].get("username", "")


def _vendor_icon(device_type: str) -> str:
    """Static icon URL for a vendor, or "" when no icon file is bundled.

    Icons live at web/static/vendor-icons/<device_type>.png by convention;
    the empty string preserves the kiosk's no-icon rendering path (used by
    `unknown` today and by any newly added vendor until an icon ships).
    """
    if (_VENDOR_ICONS_DIR / f"{device_type}.png").is_file():
        return f"/static/vendor-icons/{device_type}.png"
    return ""


def _vendor_ui_entry(device_type: str) -> Dict[str, str]:
    """Build one kiosk metadata entry (name, color, defaultUser, icon)."""
    style = _VENDOR_UI_STYLE.get(device_type, {})
    return {
        "name": style.get("name", device_type.replace("_", " ").title()),
        "color": style.get("color", _DEFAULT_VENDOR_COLOR),
        "defaultUser": _vendor_default_user(device_type),
        "icon": _vendor_icon(device_type),
    }


def vendor_ui_metadata() -> Dict[str, Dict[str, str]]:
    """Vendor metadata map injected into the dashboard template.

    Keys: every provisionable device type (from HANDLER_MAP) plus the
    documented `evolution_digital` and `unknown` exceptions. Values are the
    exact shape the kiosk JS consumes: name, color, defaultUser, icon.
    """
    metadata = {
        device_type: _vendor_ui_entry(device_type)
        for device_type in provisionable_device_types()
    }
    # Non-provisionable vendors (evolution_digital) still get a card —
    # they are real device types, just dispatched via the main.py
    # side-door instead of HANDLER_MAP.
    for device_type in nonprovisionable_device_types():
        metadata[device_type] = _vendor_ui_entry(device_type)
    unknown = _vendor_ui_entry("unknown")
    # The unknown-device card offers "admin" as the generic username hint
    # (matches the JS `vendor.defaultUser || 'admin'` fallback); it is a UI
    # affordance, not a credential-source entry.
    unknown["defaultUser"] = "admin"
    metadata["unknown"] = unknown
    return metadata
