"""FastAPI web application for Network Provisioner."""

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .api import router as api_router
from .websocket import router as ws_router

logger = logging.getLogger(__name__)

# Template and static file paths
TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


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
    app = FastAPI(
        title=title,
        description="Web interface for Network Device Auto-Provisioner",
        version="1.0.0",
        debug=debug,
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
    app.include_router(ws_router, prefix="/ws")
    
    # Root route serves the dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        """Serve the main dashboard page."""
        return templates.TemplateResponse("index.html", {
            "request": request,
            "title": title,
        })

    # Files management page
    @app.get("/files", response_class=HTMLResponse)
    async def files_page(request: Request):
        """Serve the files management page for firmware and configs."""
        return templates.TemplateResponse("files.html", {
            "request": request,
            "title": title,
        })

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy"}
    
    # Startup event
    @app.on_event("startup")
    async def startup_event():
        logger.info("Web interface starting up...")
        # Initialize WebSocket manager
        from .websocket import manager
        app.state.ws_manager = manager
    
    # Shutdown event
    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("Web interface shutting down...")
    
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
