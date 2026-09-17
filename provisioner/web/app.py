"""FastAPI web application for Network Provisioner."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..vendor_registry import config_family_metadata
from .api import router as api_router
from .api import vendor_ui_metadata
from .snapshots import router as snapshots_router
from .websocket import router as ws_router

logger = logging.getLogger(__name__)

# Template and static file paths
TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def _deployed_version() -> str:
    """Return the deployed git short SHA (or an empty string) for the header."""
    import subprocess

    root = Path(__file__).resolve().parent.parent.parent
    # deploy.sh writes .deployed-rev next to the code (no .git on the host).
    for marker in (root / ".deployed-rev", root / "VERSION"):
        try:
            text = marker.read_text().strip()
        except OSError:
            continue
        if text:
            return text.split()[0][:20]
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).decode().strip()
    except Exception:
        return ""


def create_app(
    provisioner=None,
    title: str = "Network Provisioner",
    debug: bool = False,
) -> FastAPI:
    """Create and configure the FastAPI application.
    
    Args:
        provisioner: The Provisioner instance to use for operations
        title: Application title
        debug: Enable debug mode
    
    Returns:
        Configured FastAPI application
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Web interface starting up...")
        from .websocket import manager

        app.state.ws_manager = manager
        yield
        logger.info("Web interface shutting down...")

    app = FastAPI(
        title=title,
        description="Web interface for Network Device Auto-Provisioner",
        version="1.0.0",
        debug=debug,
        lifespan=lifespan,
    )
    
    # Store provisioner instance in app state
    app.state.provisioner = provisioner
    
    # Setup templates
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates = templates
    
    # Mount static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    
    # Include routers
    app.include_router(api_router, prefix="/api")
    app.include_router(snapshots_router, prefix="/api")
    app.include_router(ws_router, prefix="/ws")
    
    # Root route serves the dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        """Serve the main dashboard page."""
        num_ports = 6
        label_printer = {
            "enabled": False,
            "provider": "brady_web_bluetooth",
            "auto_print_mikrotik_netinstall": True,
            "copies": 1,
        }
        port_manager = getattr(provisioner, "port_manager", None) if provisioner else None
        initial_ports = {}
        if port_manager is not None:
            num_ports = port_manager.num_ports
            try:
                # Seed the first paint so a Chromium respawn never shows an
                # empty grid while the WebSocket connects.
                initial_ports = {
                    str(port): status for port, status in port_manager.get_port_status().items()
                }
            except Exception:  # pragma: no cover - presentation must not break boot
                initial_ports = {}
        config = getattr(provisioner, "config", None) if provisioner else None
        if config is not None:
            printer_config = getattr(config, "label_printer", None)
            if printer_config is not None:
                label_printer = printer_config.model_dump()
        return templates.TemplateResponse(request, "index.html", {
            "request": request,
            "title": title,
            "num_ports": num_ports,
            "label_printer": label_printer,
            # Server-injected vendor metadata (Story 5 / #75): the JS
            # `deviceVendors` map derives from the handler registry instead
            # of a hardcoded frontend copy. Injection (vs. a runtime fetch)
            # means the map exists at script-parse time — no async race at
            # first render, no stale-JS hazard on the long-lived kiosk.
            "vendor_metadata": vendor_ui_metadata(),
            "initial_ports": initial_ports,
            "deployed_version": _deployed_version(),
        })

    @app.get("/labels", response_class=HTMLResponse)
    async def labels_page(request: Request):
        """Serve the constrained field-label printing page."""
        label_printer = {
            "enabled": False,
            "provider": "brady_web_bluetooth",
            "auto_print_mikrotik_netinstall": True,
            "copies": 1,
        }
        config = getattr(provisioner, "config", None) if provisioner else None
        if config is not None:
            printer_config = getattr(config, "label_printer", None)
            if printer_config is not None:
                label_printer = printer_config.model_dump()
        return templates.TemplateResponse(request, "labels.html", {
            "request": request,
            "title": title,
            "label_printer": label_printer,
        })

    # Files management page
    @app.get("/files", response_class=HTMLResponse)
    async def files_page(request: Request):
        """Serve the files management page for firmware and configs."""
        return templates.TemplateResponse(request, "files.html", {
            "request": request,
            "title": title,
            "vendor_metadata": vendor_ui_metadata(),
            "family_metadata": config_family_metadata(),
        })

    # Firmware management page
    @app.get("/firmware", response_class=HTMLResponse)
    async def firmware_page(request: Request):
        """Serve the firmware management page."""
        return templates.TemplateResponse(request, "firmware.html", {
            "request": request,
            "title": title,
        })

    # Console Settings (bench setup tools) page
    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request):
        """Serve the console settings / bench setup page."""
        return templates.TemplateResponse(request, "setup.html", {
            "request": request,
            "title": title,
        })

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy"}

    return app


def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    provisioner=None,
    reload: bool = False,
):
    """Run the web server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        provisioner: Provisioner instance
        reload: Enable auto-reload (development only)
    """
    import uvicorn
    
    app = create_app(provisioner=provisioner)
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


async def run_server_async(
    host: str = "0.0.0.0",
    port: int = 8080,
    provisioner=None,
):
    """Run the web server asynchronously (for integration with provisioner).
    
    Args:
        host: Host to bind to
        port: Port to bind to
        provisioner: Provisioner instance
    """
    import uvicorn
    
    app = create_app(provisioner=provisioner)
    
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    await server.serve()
