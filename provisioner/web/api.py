"""REST API endpoints for Network Provisioner web interface."""

import asyncio
import json
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks, UploadFile, File, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(tags=["api"])


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
    device_model: Optional[str] = None
    provisioning: bool = False
    last_activity: Optional[str] = None


class ProvisionRequest(BaseModel):
    """Request to manually provision a device."""
    port_number: int
    custom_password: Optional[str] = None
    custom_username: Optional[str] = None
    skip_firmware: bool = False
    skip_config: bool = False
    config_override: Optional[Dict[str, Any]] = None


class ProvisionResponse(BaseModel):
    """Response from a provision request."""
    success: bool
    job_id: Optional[int] = None
    message: str


class ApplyModeRequest(BaseModel):
    """Request to apply a device mode (AP or PTP) after provisioning."""
    mode: str  # "ap" or "ptp"
    # AP fields
    tower: Optional[int] = None
    direction: Optional[str] = None
    # PTP fields
    my_tower: Optional[int] = None
    remote_tower: Optional[int] = None


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
        PortStatus(
            port_number=port_num,
            vlan_id=status["vlan_id"],
            link_up=status["link_up"],
            device_detected=status["device_detected"],
            device_type=status["device_type"],
            device_ip=status["device_ip"],
            provisioning=status["provisioning"],
        )
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
    return PortStatus(
        port_number=port_number,
        vlan_id=status["vlan_id"],
        link_up=status["link_up"],
        device_detected=status["device_detected"],
        device_type=status["device_type"],
        device_ip=status["device_ip"],
        provisioning=status["provisioning"],
    )


# ============================================================================
# Provisioning Endpoints
# ============================================================================

# Store temporary credential overrides (in-memory, cleared on restart)
_credential_overrides: Dict[int, CredentialOverride] = {}


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


class FirmwareUrlRequest(BaseModel):
    """Request to download firmware from URL."""
    url: str
    device_type: str
    filename: Optional[str] = None  # Auto-detect from URL if not provided


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


VALID_DEVICE_TYPES = {"cambium", "mikrotik", "tachyon", "tarana", "ubiquiti"}


def _validate_device_type(device_type: str) -> str:
    """Validate device_type is a known type. Raises HTTPException if not."""
    sanitized = os.path.basename(device_type).lower().strip()
    if sanitized not in VALID_DEVICE_TYPES:
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


def _get_device_type_from_filename(filename: str) -> Optional[str]:
    """Try to detect device type from filename."""
    filename_lower = filename.lower()
    if 'epmp' in filename_lower or 'cambium' in filename_lower:
        return 'cambium'
    elif 'routeros' in filename_lower or 'mikrotik' in filename_lower:
        return 'mikrotik'
    elif 'tachyon' in filename_lower:
        return 'tachyon'
    elif 'tarana' in filename_lower:
        return 'tarana'
    elif 'ubiquiti' in filename_lower or 'airos' in filename_lower or 'ubnt' in filename_lower:
        return 'ubiquiti'
    return None


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

    try:
        with open(dest_path, "wb") as f:
            content = await file.read()
            f.write(content)

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

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(body.url, timeout=aiohttp.ClientTimeout(total=600)) as response:
                if response.status != 200:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to download: HTTP {response.status}"
                    )

                content = await response.read()
                with open(dest_path, "wb") as f:
                    f.write(content)

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
    except aiohttp.ClientError as e:
        logger.error(f"Failed to download firmware: {e}")
        raise HTTPException(status_code=400, detail=f"Download failed: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to save firmware: {e}")
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
        raise HTTPException(status_code=503, detail="Firmware checker not enabled")

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
    channel: str  # "release", "beta", or "all"


@router.post("/firmware/set-channel")
async def firmware_set_channel(request: Request, body: ChannelUpdateRequest):
    """Set the firmware channel for a vendor source at runtime.

    Channel options:
      - "release": stable releases only
      - "beta": beta releases only
      - "all": both stable and beta
    """
    from ..firmware_checker import get_firmware_checker

    checker = get_firmware_checker()
    if not checker:
        raise HTTPException(status_code=503, detail="Firmware checker not enabled")

    if body.channel not in ("release", "beta", "all"):
        raise HTTPException(status_code=400, detail="Channel must be 'release', 'beta', or 'all'")

    source = checker._sources.get(body.vendor)
    if not source:
        raise HTTPException(status_code=404, detail=f"No source configured for vendor: {body.vendor}")

    # Update the source config in-memory
    if isinstance(source.config, dict):
        source.config["channel"] = body.channel
        source.config["include_beta"] = body.channel in ("beta", "all")
    else:
        # Pydantic model — replace with updated dict
        config_dict = source.config.model_dump()
        config_dict["channel"] = body.channel
        config_dict["include_beta"] = body.channel in ("beta", "all")
        source.config = config_dict

    return {
        "success": True,
        "vendor": body.vendor,
        "channel": body.channel,
        "message": f"Channel set to '{body.channel}' for {body.vendor}",
    }


# ============================================================================
# Config Management Endpoints
# ============================================================================

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
                return {"filename": filename, "content": content, "parsed": parsed}
            except json.JSONDecodeError:
                pass
        return {"filename": filename, "content": content}
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

# Known defaults for each device type (hardcoded fallbacks)
BUILTIN_CREDENTIALS = {
    "cambium": [
        {"username": "admin", "password": "admin"},
    ],
    "mikrotik": [
        {"username": "admin", "password": ""},
    ],
    "tachyon": [
        {"username": "root", "password": "admin"},
    ],
    "tarana": [
        {"username": "admin", "password": "admin123"},
    ],
    "ubiquiti": [
        {"username": "ubnt", "password": "ubnt"},
    ],
}


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
        # Use sorted list for consistent ordering
        for device_type in sorted(VALID_DEVICE_TYPES):
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
    if device_type not in VALID_DEVICE_TYPES:
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

    if device_type not in VALID_DEVICE_TYPES:
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
    if device_type not in VALID_DEVICE_TYPES:
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
# Device Mode Endpoints (AP / PTP)
# ============================================================================

@router.post("/ports/{port_number}/apply-mode")
async def apply_device_mode(
    port_number: int,
    req: ApplyModeRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Apply a device mode (AP or PTP) to a provisioned device.

    After standard SM provisioning completes, this endpoint lets the user
    reconfigure the device as an AP or PTP endpoint.
    """
    provisioner = request.app.state.provisioner
    if not provisioner:
        raise HTTPException(status_code=503, detail="Provisioner not available")

    port_manager = provisioner.port_manager
    if not port_manager:
        raise HTTPException(status_code=503, detail="Port manager not available")

    # Validate port
    port_status = port_manager.get_port_status()
    if port_number not in port_status:
        raise HTTPException(status_code=404, detail="Port not found")

    status = port_status[port_number]
    if not status["device_detected"]:
        raise HTTPException(status_code=400, detail="No device detected on port")

    device_type = status["device_type"]
    device_ip = status["device_ip"]

    if device_type not in ("cambium", "tachyon"):
        raise HTTPException(
            status_code=400,
            detail=f"Mode configuration not supported for {device_type}",
        )

    # Validate mode-specific parameters
    if req.mode == "ap":
        if req.tower is None or req.direction is None:
            raise HTTPException(
                status_code=400,
                detail="AP mode requires 'tower' and 'direction'",
            )
    elif req.mode == "ptp":
        if req.my_tower is None or req.remote_tower is None:
            raise HTTPException(
                status_code=400,
                detail="PTP mode requires 'my_tower' and 'remote_tower'",
            )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown mode: {req.mode}")

    # Run config application in background
    background_tasks.add_task(
        _run_apply_mode,
        provisioner,
        port_number,
        device_type,
        device_ip,
        req,
    )

    return {"success": True, "message": f"Applying {req.mode} mode on port {port_number}"}


@router.get("/ptp-links")
async def get_ptp_links(request: Request):
    """Get all active PTP links.

    Returns links with side info so the UI can show PTP-B shortcuts
    on ports where the paired device's vendor matches.
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
):
    """Apply device mode in a background task."""
    from ..mode_config import get_mode_config_manager, make_ptp_link_id
    from ..fingerprint import identify_device, DeviceType
    from .websocket import notify_port_change

    port_manager = provisioner.port_manager
    mcm = get_mode_config_manager()

    try:
        # Determine mode and naming
        if req.mode == "ap":
            mode = "ap"
            naming = mcm.generate_ap_naming(req.tower, req.direction, device_type)
            ptp_link_id = None
        else:
            # PTP: auto-assign side
            side = port_manager.get_available_ptp_side(req.my_tower, req.remote_tower)
            mode = f"ptp-{side}"
            naming = mcm.generate_ptp_naming(
                req.my_tower, req.remote_tower, side, device_type,
            )
            ptp_link_id = make_ptp_link_id(req.my_tower, req.remote_tower)

        logger.info(
            f"Applying {mode} to port {port_number} ({device_type}): "
            f"hostname={naming['hostname']}, ssid={naming['ssid']}"
        )

        # Load mode template
        template = mcm.load_template(device_type, mode)

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
            return

        connected = await handler.connect()
        if not connected:
            logger.error(f"Failed to connect to {device_type} at {device_ip} for mode config")
            return

        try:
            # Apply config: template + naming injection, or just naming if no template
            if template:
                rendered = mcm.render_template(template, naming, device_type)
                success = await handler.apply_config(rendered)
            else:
                # No template — just apply hostname/SSID via apply_ap_naming
                success = await handler.apply_ap_naming(
                    naming["hostname"], naming["ssid"],
                )

            if success:
                logger.info(f"Mode {mode} applied successfully on port {port_number}")
                port_manager.set_device_mode(
                    port_number, mode, naming, ptp_link_id,
                )
            else:
                logger.error(f"Failed to apply {mode} config on port {port_number}")
        finally:
            await handler.disconnect()

        # Broadcast updated port status
        port_status_data = port_manager._get_single_port_status(port_number)
        await notify_port_change(port_number, port_status_data)

    except Exception as e:
        logger.exception(f"Error applying mode on port {port_number}: {e}")
