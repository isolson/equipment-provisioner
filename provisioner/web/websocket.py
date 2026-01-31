"""WebSocket handler for real-time updates."""

import asyncio
import json
import logging
from typing import Dict, List, Set
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manages WebSocket connections and broadcasts."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._broadcast_task: asyncio.Task = None
        self._running = False
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.debug(f"Failed to send personal message: {e}")
    
    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"Failed to broadcast to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_port_update(self, port_number: int, status: dict):
        """Broadcast a port status update."""
        await self.broadcast({
            "type": "port_update",
            "port_number": port_number,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        })
    
    async def broadcast_job_update(self, job_id: int, status: str, details: dict = None):
        """Broadcast a job status update."""
        await self.broadcast({
            "type": "job_update",
            "job_id": job_id,
            "status": status,
            "data": details or {},
            "timestamp": datetime.now().isoformat(),
        })
    
    async def broadcast_system_event(self, event: str, data: dict = None):
        """Broadcast a system event."""
        await self.broadcast({
            "type": "system_event",
            "event": event,
            "data": data or {},
            "timestamp": datetime.now().isoformat(),
        })
    
    def start_status_broadcast(self, provisioner, interval: float = 2.0):
        """Start periodic status broadcasts."""
        if self._broadcast_task is None or self._broadcast_task.done():
            self._running = True
            self._broadcast_task = asyncio.create_task(
                self._status_broadcast_loop(provisioner, interval)
            )
    
    def stop_status_broadcast(self):
        """Stop periodic status broadcasts."""
        self._running = False
        if self._broadcast_task:
            self._broadcast_task.cancel()
    
    async def _status_broadcast_loop(self, provisioner, interval: float):
        """Periodically broadcast status updates."""
        while self._running:
            try:
                if self.active_connections and provisioner:
                    # Get port status
                    if provisioner.port_manager:
                        port_status = provisioner.port_manager.get_port_status()
                        await self.broadcast({
                            "type": "status_update",
                            "data": {
                                "ports": {
                                    str(k): v for k, v in port_status.items()
                                },
                                "running": provisioner._running,
                            },
                            "timestamp": datetime.now().isoformat(),
                        })
                
                await asyncio.sleep(interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in status broadcast loop: {e}")
                await asyncio.sleep(interval)


# Global connection manager instance
manager = ConnectionManager()


@router.websocket("/status")
async def websocket_status(websocket: WebSocket):
    """WebSocket endpoint for real-time status updates."""
    await manager.connect(websocket)
    
    # Send initial status
    try:
        provisioner = websocket.app.state.provisioner
        if provisioner and provisioner.port_manager:
            port_status = provisioner.port_manager.get_port_status()
            await manager.send_personal(websocket, {
                "type": "initial_status",
                "data": {
                    "ports": {str(k): v for k, v in port_status.items()},
                    "running": provisioner._running,
                },
                "timestamp": datetime.now().isoformat(),
            })
        else:
            # Send mock data for development
            await manager.send_personal(websocket, {
                "type": "initial_status",
                "data": _get_mock_status(),
                "timestamp": datetime.now().isoformat(),
            })
    except Exception as e:
        logger.error(f"Error sending initial status: {e}")
    
    try:
        while True:
            # Wait for messages from client (ping/pong, commands, etc.)
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                await _handle_client_message(websocket, message)
            except json.JSONDecodeError:
                logger.debug(f"Invalid JSON from client: {data}")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


async def _handle_client_message(websocket: WebSocket, message: dict):
    """Handle messages received from WebSocket clients."""
    msg_type = message.get("type")
    
    if msg_type == "ping":
        await manager.send_personal(websocket, {"type": "pong"})
    
    elif msg_type == "subscribe":
        # Client wants to subscribe to specific updates
        # For now, all clients get all updates
        await manager.send_personal(websocket, {
            "type": "subscribed",
            "channels": message.get("channels", ["all"]),
        })
    
    elif msg_type == "request_status":
        # Client requesting immediate status update
        provisioner = websocket.app.state.provisioner
        if provisioner and provisioner.port_manager:
            port_status = provisioner.port_manager.get_port_status()
            await manager.send_personal(websocket, {
                "type": "status_update",
                "data": {
                    "ports": {str(k): v for k, v in port_status.items()},
                    "running": provisioner._running,
                },
                "timestamp": datetime.now().isoformat(),
            })


def _get_mock_status() -> dict:
    """Return mock status for development."""
    return {
        "ports": {
            "1": {
                "vlan_id": 1991,
                "link_up": True,
                "device_detected": True,
                "device_type": "cambium",
                "device_ip": "169.254.1.1",
                "provisioning": False,
            },
            "2": {
                "vlan_id": 1992,
                "link_up": True,
                "device_detected": True,
                "device_type": "mikrotik",
                "device_ip": "192.168.88.1",
                "provisioning": True,
            },
            "3": {
                "vlan_id": 1993,
                "link_up": False,
                "device_detected": False,
                "device_type": None,
                "device_ip": None,
                "provisioning": False,
            },
            "4": {
                "vlan_id": 1994,
                "link_up": True,
                "device_detected": True,
                "device_type": "tachyon",
                "device_ip": "169.254.1.1",
                "provisioning": False,
            },
            "5": {
                "vlan_id": 1995,
                "link_up": False,
                "device_detected": False,
                "device_type": None,
                "device_ip": None,
                "provisioning": False,
            },
            "6": {
                "vlan_id": 1996,
                "link_up": True,
                "device_detected": True,
                "device_type": "ubiquiti",
                "device_ip": "192.168.1.20",
                "provisioning": False,
            },
        },
        "running": True,
    }


# Helper functions to be called from provisioner code
async def notify_port_change(port_number: int, status: dict):
    """Notify all clients of a port status change."""
    await manager.broadcast_port_update(port_number, status)


async def notify_provisioning_started(port_number: int, device_type: str, job_id: int):
    """Notify clients that provisioning has started."""
    await manager.broadcast({
        "type": "provisioning_started",
        "port_number": port_number,
        "device_type": device_type,
        "job_id": job_id,
        "timestamp": datetime.now().isoformat(),
    })


async def notify_provisioning_completed(port_number: int, job_id: int, success: bool, details: dict = None):
    """Notify clients that provisioning has completed."""
    await manager.broadcast({
        "type": "provisioning_completed",
        "port_number": port_number,
        "job_id": job_id,
        "success": success,
        "data": details or {},
        "timestamp": datetime.now().isoformat(),
    })


async def notify_provisioning_progress(port_number: int, job_id: int, step: str, progress: int = None):
    """Notify clients of provisioning progress."""
    await manager.broadcast({
        "type": "provisioning_progress",
        "port_number": port_number,
        "job_id": job_id,
        "step": step,
        "progress": progress,
        "timestamp": datetime.now().isoformat(),
    })


async def notify_credentials_required(port_number: int, device_type: str, device_ip: str, error: str):
    """Notify clients that credentials are needed to continue provisioning."""
    await manager.broadcast({
        "type": "credentials_required",
        "port_number": port_number,
        "device_type": device_type,
        "device_ip": device_ip,
        "error": error,
        "timestamp": datetime.now().isoformat(),
    })


async def notify_display_state(sleeping: bool):
    """Notify clients of display sleep/wake state change."""
    await manager.broadcast({
        "type": "display_state",
        "sleeping": sleeping,
        "timestamp": datetime.now().isoformat(),
    })
