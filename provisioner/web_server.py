#!/usr/bin/env python3
"""Web server entry point for Network Provisioner.

This can be run standalone or integrated with the main provisioner.
"""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console()
logger = logging.getLogger(__name__)


def setup_logging(level: str = "INFO") -> None:
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s",
        handlers=[
            RichHandler(
                console=console,
                show_time=True,
                show_path=False,
                rich_tracebacks=True,
            )
        ],
    )


async def run_standalone(
    host: str = "0.0.0.0",
    port: int = 8080,
    config_path: str = "config.yaml",
):
    """Run the web server with an integrated provisioner."""
    from .config import load_config, set_config
    from .db import init_db
    from .main import Provisioner
    from .web.app import create_app
    from .web.websocket import manager
    
    import uvicorn
    
    # Load configuration
    try:
        config = load_config(config_path)
        set_config(config)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        config = None
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        config = None
    
    # Initialize database
    db_path = config.logging.db if config else "/tmp/provisioner.db"
    try:
        await init_db(db_path)
        logger.info(f"Database initialized: {db_path}")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}")

    # Initialize display controller
    from .display import init_display, cleanup_display
    if config and config.display.sleep_timeout > 0:
        init_display(
            sleep_timeout=config.display.sleep_timeout,
            wake_on_connect=config.display.wake_on_connect,
            use_dpms=config.display.use_dpms,
            use_backlight=config.display.use_backlight,
        )
    else:
        logger.debug("Display sleep disabled (timeout=0)")
    
    # Create provisioner if config available
    provisioner = None
    if config:
        try:
            provisioner = Provisioner(config)
            await provisioner.setup()
            logger.info("Provisioner initialized")
        except Exception as e:
            logger.warning(f"Provisioner setup failed: {e}")
            provisioner = None
    
    # Create FastAPI app
    app = create_app(provisioner=provisioner)
    
    # Start WebSocket status broadcasting if provisioner available
    if provisioner:
        manager.start_status_broadcast(provisioner, interval=2.0)
    
    # Configure uvicorn
    uv_config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True,
    )
    server = uvicorn.Server(uv_config)
    
    # Run provisioner and web server concurrently
    tasks = [asyncio.create_task(server.serve())]
    
    if provisioner:
        tasks.append(asyncio.create_task(provisioner.run()))
    
    console.print(f"[bold green]Web interface running at http://{host}:{port}[/bold green]")
    
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        if provisioner:
            await provisioner.stop()
        manager.stop_status_broadcast()
        cleanup_display()


async def run_web_only(
    host: str = "0.0.0.0",
    port: int = 8080,
):
    """Run just the web server without provisioner (for development/testing)."""
    from .web.app import create_app
    import uvicorn
    
    app = create_app(provisioner=None)
    
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        reload=False,
    )
    server = uvicorn.Server(config)
    
    console.print(f"[bold green]Web interface running at http://{host}:{port}[/bold green]")
    console.print("[yellow]Running in standalone mode (no provisioner)[/yellow]")
    
    await server.serve()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Provisioner Web Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8080,
        help="Port to bind to (default: 8080)",
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Run web interface only (no provisioner)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )

    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    console.print("[bold blue]Network Provisioner - Web Interface[/bold blue]")
    console.print()
    
    # Handle signals
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    def signal_handler():
        logger.info("Shutdown signal received")
        for task in asyncio.all_tasks(loop):
            task.cancel()
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    try:
        if args.standalone:
            loop.run_until_complete(run_web_only(args.host, args.port))
        else:
            loop.run_until_complete(run_standalone(args.host, args.port, args.config))
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
