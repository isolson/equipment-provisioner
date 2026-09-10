"""Handler-driven wired mode inspection and application."""
import asyncio
import hashlib
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..fingerprint import DeviceFingerprint, DeviceType
from ..handler_manager import HandlerManager
from ..qualification import qualified_modes
from .api import get_credential_override

router = APIRouter()


class NetworkModeRequest(BaseModel):
    mode: str
    device_token: str


def _port(request, port_number):
    provisioner = request.app.state.provisioner
    if not provisioner or not provisioner.port_manager:
        raise HTTPException(503, "Provisioner unavailable")
    pm = provisioner.port_manager
    status = pm.get_port_status().get(port_number)
    if not status or not status.get("device_detected"):
        raise HTTPException(404, "No device detected on this port")
    cls = HandlerManager.handler_class_for(status.get("device_type"))
    if not cls or not getattr(cls, "supports_network_modes", False):
        raise HTTPException(400, "This device has no wired mode workflow")
    if status.get("provisioning") or status.get("mode_job"):
        raise HTTPException(409, "The port already has an active operation")
    return provisioner, pm, status


def _device_token(info, interface):
    if not info.serial_number:
        raise HTTPException(409, "Device identity could not be verified")
    identity = "%s|%s|%s" % (info.serial_number, interface, info.firmware_version)
    return hashlib.sha256(identity.encode()).hexdigest()


async def _operate(request, port_number, change: Optional[NetworkModeRequest] = None):
    provisioner, pm, status = _port(request, port_number)
    slot = pm.port_states[port_number]
    # Reserve before the first await. Detection/reprovision must not compete.
    slot.provisioning = True
    slot.provisioning_task = asyncio.current_task()
    handler = None
    job_started = False
    success = False
    try:
        interface = pm.get_interface_for_port(port_number)
        override = get_credential_override(port_number)
        credentials = None
        if override:
            if override.device_type != status["device_type"]:
                raise HTTPException(409, "Stored login is for a different device type")
            credentials = {"username": override.username, "password": override.password}
        fingerprint = DeviceFingerprint(device_type=DeviceType(status["device_type"]), model=status.get("device_model"))
        handler = provisioner.handler_manager.get_handler(fingerprint, status["device_ip"], interface=interface, custom_credentials=credentials)
        if not handler or not await handler.connect():
            raise HTTPException(401, "Device login failed; enter its credentials")
        info = await handler.get_info()
        token = _device_token(info, interface)
        pm.update_port_device_info(port_number, serial=info.serial_number,
                                   model=info.model, firmware_version=info.firmware_version)
        state = await handler.network_mode_state()
        handler.validate_network_mode_layout(state)
        model = state.get("model")
        firmware = str(state.get("firmware") or "").split()[0]
        labels = handler.network_mode_labels_for_model(model)
        transitions = frozenset((source, target) for source in labels for target in labels if source != target)
        requirements = {mode: transitions for mode in labels}
        choices = qualified_modes(status["device_type"], model, firmware, labels, requirements)
        if change:
            if change.device_token != token:
                raise HTTPException(409, "Device or firmware changed; inspect the port again")
            if change.mode not in choices:
                raise HTTPException(409, "This mode is not verified for the detected model and firmware")
            pm.begin_mode_job(port_number, change.mode, [{"key": "apply", "label": "Apply and verify wired mode"}])
            job_started = True
            pm.update_mode_job(port_number, "apply", "loading")
            state = await handler.apply_network_mode(change.mode)
            # A disconnected/replaced port must never receive a stale success.
            current = pm.port_states.get(port_number)
            if current is not slot or current.device_mac != status.get("device_mac"):
                raise HTTPException(409, "The connected device changed during the operation")
            pm.set_device_mode(port_number, state["mode"], {"mode": state["mode"], "verified": True})
            pm.update_mode_job(port_number, "apply", True)
            success = True
        return {"port": port_number, "model": model, "firmware": firmware,
                "mode": state["mode"], "device_token": token,
                "choices": [{"value": mode, "label": labels[mode],
                             "description": getattr(handler, "network_mode_descriptions", {}).get(mode, "")}
                            for mode in choices],
                "management_note": getattr(handler, "network_mode_management_note", ""),
                "verified": bool(change and success)}
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(409, "Device layout does not match the supported profile; configuration was not accepted")
    except Exception:
        # RouterOS errors/config output can contain private values.
        raise HTTPException(502, "Device operation failed; inspect its current state before retrying")
    finally:
        try:
            if handler:
                await handler.disconnect()
        finally:
            if pm.port_states.get(port_number) is slot:
                slot.provisioning = False
                slot.provisioning_task = None
                if job_started:
                    pm.finish_mode_job(port_number, success, None if success else "Wired mode was not verified")


@router.get("/api/network-modes")
async def candidates(request: Request):
    p = request.app.state.provisioner
    if not p or not p.port_manager:
        return []
    result = []
    for port, status in p.port_manager.get_port_status().items():
        cls = HandlerManager.handler_class_for(status.get("device_type"))
        if status.get("device_detected") and cls and getattr(cls, "supports_network_modes", False):
            result.append({"port": port, "model": status.get("device_model"), "device_type": status["device_type"],
                           "busy": bool(status.get("provisioning") or status.get("mode_job"))})
    return result


@router.get("/api/network-modes/{port_number}")
async def inspect_mode(port_number: int, request: Request):
    return await _operate(request, port_number)


@router.post("/api/network-modes/{port_number}")
async def apply_mode(port_number: int, change: NetworkModeRequest, request: Request):
    return await _operate(request, port_number, change)


@router.get("/network-modes", response_class=HTMLResponse)
async def mode_page(request: Request):
    return request.app.state.templates.TemplateResponse(request=request, name="network-modes.html", context={})
