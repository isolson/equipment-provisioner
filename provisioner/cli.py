#!/usr/bin/env python3
"""
CLI tool for manual device testing and provisioning.

Usage:
    python -m provisioner.cli scan --subnet 192.168.1.0/24
    python -m provisioner.cli identify 192.168.1.100
    python -m provisioner.cli info 192.168.1.100 --type cambium
    python -m provisioner.cli backup 192.168.1.100 --type cambium --output backup.bin
    python -m provisioner.cli config 192.168.1.100 --type cambium --file config.json
    python -m provisioner.cli firmware 192.168.1.100 --type cambium --file firmware.img
    python -m provisioner.cli provision 192.168.1.100 --type cambium --config config.json --firmware fw.img
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def setup_logging(verbose: bool = False):
    """Setup logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False)]
    )


async def cmd_scan(args):
    """Scan network for devices."""
    from .detector import scan_subnet_once

    console.print(f"[bold]Scanning {args.subnet}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Scanning network...", total=None)
        devices = await scan_subnet_once(args.interface, args.subnet)

    if not devices:
        console.print("[yellow]No devices found[/yellow]")
        return

    table = Table(title=f"Devices found on {args.subnet}")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")

    for device in devices:
        table.add_row(device.ip_address, device.mac_address)

    console.print(table)
    console.print(f"\n[bold]{len(devices)} device(s) found[/bold]")


async def cmd_identify(args):
    """Identify a device type."""
    from .fingerprint import identify_device

    console.print(f"[bold]Identifying device at {args.ip}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Probing device...", total=None)
        fingerprint = await identify_device(args.ip, timeout=args.timeout)

    table = Table(title=f"Device Identification: {args.ip}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Device Type", fingerprint.device_type.value)
    table.add_row("Model", fingerprint.model or "Unknown")
    table.add_row("Firmware", fingerprint.firmware_version or "Unknown")
    table.add_row("Hostname", fingerprint.hostname or "Unknown")
    table.add_row("Confidence", f"{fingerprint.confidence:.0%}")

    console.print(table)


async def cmd_info(args):
    """Get detailed device information."""
    handler = await get_handler(args.ip, args.type, args.username, args.password)
    if not handler:
        return

    try:
        console.print(f"[bold]Connecting to {args.ip}...[/bold]")

        if not await handler.connect():
            console.print("[red]Failed to connect[/red]")
            return

        console.print("[green]Connected[/green]")
        console.print(f"[bold]Getting device info...[/bold]")

        info = await handler.get_info()

        table = Table(title=f"Device Information: {args.ip}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Device Type", info.device_type)
        table.add_row("Model", info.model or "Unknown")
        table.add_row("Serial Number", info.serial_number or "Unknown")
        table.add_row("MAC Address", info.mac_address or "Unknown")
        table.add_row("Hostname", info.hostname or "Unknown")
        table.add_row("Firmware Version", info.firmware_version or "Unknown")
        table.add_row("Hardware Version", info.hardware_version or "Unknown")

        if info.uptime:
            hours = info.uptime // 3600
            minutes = (info.uptime % 3600) // 60
            table.add_row("Uptime", f"{hours}h {minutes}m")

        for key, value in info.extra.items():
            if value is not None:
                table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)

    finally:
        await handler.disconnect()


async def cmd_backup(args):
    """Backup device configuration."""
    handler = await get_handler(args.ip, args.type, args.username, args.password)
    if not handler:
        return

    try:
        if not await handler.connect():
            console.print("[red]Failed to connect[/red]")
            return

        console.print(f"[bold]Backing up configuration from {args.ip}...[/bold]")

        backup_data = await handler.backup_config()

        output_path = Path(args.output)
        with open(output_path, "wb") as f:
            f.write(backup_data)

        console.print(f"[green]Configuration saved to {output_path}[/green]")
        console.print(f"[dim]Size: {len(backup_data)} bytes[/dim]")

    finally:
        await handler.disconnect()


async def cmd_config(args):
    """Apply configuration to device."""
    handler = await get_handler(args.ip, args.type, args.username, args.password)
    if not handler:
        return

    # Validate config file exists
    config_path = Path(args.file)
    if not config_path.exists():
        console.print(f"[red]Config file not found: {args.file}[/red]")
        return

    try:
        if not await handler.connect():
            console.print("[red]Failed to connect[/red]")
            return

        # Show current config if requested
        if args.show_current:
            console.print(f"[bold]Current configuration:[/bold]")
            try:
                current = await handler.get_config()
                console.print_json(data=current)
            except Exception as e:
                console.print(f"[yellow]Could not get current config: {e}[/yellow]")

        # Read and display new config
        with open(config_path, "r") as f:
            config = json.load(f)

        if not args.yes:
            console.print(f"\n[bold]Configuration to apply:[/bold]")
            console.print_json(data=config)
            if not console.input("\n[yellow]Apply this configuration? [y/N]: [/yellow]").lower().startswith("y"):
                console.print("[dim]Cancelled[/dim]")
                return

        console.print(f"[bold]Applying configuration to {args.ip}...[/bold]")

        if await handler.apply_config_file(str(config_path)):
            console.print("[green]Configuration applied successfully[/green]")
        else:
            console.print("[red]Failed to apply configuration[/red]")

    finally:
        await handler.disconnect()


async def cmd_firmware(args):
    """Upload and apply firmware to device."""
    handler = await get_handler(args.ip, args.type, args.username, args.password)
    if not handler:
        return

    firmware_path = Path(args.file)
    if not firmware_path.exists():
        console.print(f"[red]Firmware file not found: {args.file}[/red]")
        return

    try:
        if not await handler.connect():
            console.print("[red]Failed to connect[/red]")
            return

        # Get current firmware version
        info = await handler.get_info()
        console.print(f"[bold]Current firmware:[/bold] {info.firmware_version}")
        console.print(f"[bold]Firmware file:[/bold] {firmware_path.name} ({firmware_path.stat().st_size / 1024 / 1024:.1f} MB)")

        if not args.yes:
            if not console.input("\n[yellow]Proceed with firmware update? [y/N]: [/yellow]").lower().startswith("y"):
                console.print("[dim]Cancelled[/dim]")
                return

        # Upload firmware
        console.print(f"[bold]Uploading firmware...[/bold]")
        if not await handler.upload_firmware(str(firmware_path)):
            console.print("[red]Firmware upload failed[/red]")
            return

        console.print("[green]Firmware uploaded[/green]")

        # Trigger update
        if args.update:
            console.print(f"[bold]Triggering firmware update...[/bold]")
            bank = args.bank if args.bank else None
            if not await handler.update_firmware(bank):
                console.print("[red]Failed to trigger firmware update[/red]")
                return

            if args.reboot:
                console.print(f"[bold]Rebooting device...[/bold]")
                await handler.reboot()

                console.print(f"[bold]Waiting for device to come back online...[/bold]")
                if await handler.wait_for_reboot(timeout=args.timeout):
                    # Reconnect and verify
                    if await handler.connect():
                        new_info = await handler.get_info()
                        console.print(f"[green]New firmware version: {new_info.firmware_version}[/green]")
                    else:
                        console.print("[yellow]Device is back but couldn't reconnect[/yellow]")
                else:
                    console.print("[red]Device did not come back online[/red]")

    finally:
        await handler.disconnect()


async def cmd_provision(args):
    """Full provisioning workflow."""
    handler = await get_handler(args.ip, args.type, args.username, args.password)
    if not handler:
        return

    config_path = Path(args.config) if args.config else None
    firmware_path = Path(args.firmware) if args.firmware else None

    if config_path and not config_path.exists():
        console.print(f"[red]Config file not found: {args.config}[/red]")
        return

    if firmware_path and not firmware_path.exists():
        console.print(f"[red]Firmware file not found: {args.firmware}[/red]")
        return

    try:
        console.print(f"[bold]Starting provisioning for {args.ip}...[/bold]")

        # Load config
        config = None
        if config_path:
            with open(config_path, "r") as f:
                config = json.load(f)

        result = await handler.provision(
            config=config,
            firmware_path=str(firmware_path) if firmware_path else None,
            dual_bank=args.dual_bank,
        )

        if result.success:
            console.print("\n[bold green]Provisioning completed successfully![/bold green]")

            table = Table(title="Provisioning Result")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            if result.device_info:
                table.add_row("Device", f"{result.device_info.device_type} {result.device_info.model or ''}")
                table.add_row("Serial", result.device_info.serial_number or "N/A")

            if result.old_firmware:
                table.add_row("Old Firmware", result.old_firmware)
            if result.new_firmware:
                table.add_row("New Firmware", result.new_firmware)
            if result.config_applied:
                table.add_row("Config Applied", result.config_applied)

            table.add_row("Phases Completed", ", ".join(p.value for p in result.phases_completed))

            console.print(table)
        else:
            console.print(f"\n[bold red]Provisioning failed: {result.error_message}[/bold red]")
            if result.phases_completed:
                console.print(f"[dim]Completed phases: {', '.join(p.value for p in result.phases_completed)}[/dim]")

    finally:
        await handler.disconnect()


async def cmd_reboot(args):
    """Reboot a device."""
    handler = await get_handler(args.ip, args.type, args.username, args.password)
    if not handler:
        return

    try:
        if not await handler.connect():
            console.print("[red]Failed to connect[/red]")
            return

        if not args.yes:
            if not console.input(f"[yellow]Reboot {args.ip}? [y/N]: [/yellow]").lower().startswith("y"):
                console.print("[dim]Cancelled[/dim]")
                return

        console.print(f"[bold]Rebooting {args.ip}...[/bold]")

        if await handler.reboot():
            console.print("[green]Reboot initiated[/green]")

            if args.wait:
                console.print(f"[bold]Waiting for device to come back online...[/bold]")
                if await handler.wait_for_reboot(timeout=args.timeout):
                    console.print("[green]Device is back online[/green]")
                else:
                    console.print("[red]Device did not come back online[/red]")
        else:
            console.print("[red]Failed to reboot[/red]")

    finally:
        await handler.disconnect()


async def get_handler(ip: str, device_type: str, username: str, password: str, mock: bool = False):
    """Get the appropriate handler for a device type."""
    from .handlers import MikrotikHandler, CambiumHandler, TachyonHandler, TaranaHandler, MockHandler

    if mock:
        # Use mock handler with the specified device type for simulation
        credentials = {"username": username, "password": password}
        return MockHandler(ip=ip, credentials=credentials, device_type=device_type)

    handlers = {
        "mikrotik": MikrotikHandler,
        "cambium": CambiumHandler,
        "tachyon": TachyonHandler,
        "tarana": TaranaHandler,
    }

    handler_class = handlers.get(device_type.lower())
    if not handler_class:
        console.print(f"[red]Unknown device type: {device_type}[/red]")
        console.print(f"[dim]Supported types: {', '.join(handlers.keys())}[/dim]")
        return None

    credentials = {"username": username, "password": password}
    return handler_class(ip=ip, credentials=credentials)


async def cmd_test(args):
    """Run a test provisioning workflow with mock device."""
    from .handlers import MockHandler

    console.print("[bold]Running test provisioning with mock device...[/bold]\n")

    # Create mock handler
    credentials = {"username": "admin", "password": "test"}
    handler = MockHandler(
        ip="192.168.1.100",
        credentials=credentials,
        device_type=args.device_type,
        simulate_failures=args.failures,
        reboot_time=2.0,  # Fast reboot for testing
    )

    # Show initial state
    console.print(f"[cyan]Mock Device Type:[/cyan] {args.device_type}")
    console.print(f"[cyan]Simulate Failures:[/cyan] {args.failures}")
    console.print()

    try:
        # Connect
        console.print("[bold]Phase 1: Connecting...[/bold]")
        if not await handler.connect():
            console.print("[red]Connection failed[/red]")
            return
        console.print("[green]Connected[/green]\n")

        # Get info
        console.print("[bold]Phase 2: Getting device info...[/bold]")
        info = await handler.get_info()

        table = Table(title="Device Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Model", info.model)
        table.add_row("Serial", info.serial_number)
        table.add_row("MAC", info.mac_address)
        table.add_row("Firmware", info.firmware_version)
        console.print(table)
        console.print()

        # Backup config
        console.print("[bold]Phase 3: Backing up config...[/bold]")
        backup = await handler.backup_config()
        console.print(f"[green]Backup complete ({len(backup)} bytes)[/green]\n")

        # Apply config
        console.print("[bold]Phase 4: Applying configuration...[/bold]")
        test_config = {
            "system": {"deviceName": f"Test-{args.device_type.title()}-001"},
            "services": {"snmp": {"enabled": True}},
        }
        if await handler.apply_config(test_config):
            console.print("[green]Configuration applied[/green]\n")
        else:
            console.print("[red]Configuration failed[/red]\n")

        # Firmware update (if requested)
        if args.firmware:
            console.print("[bold]Phase 5: Firmware update...[/bold]")
            # Create a dummy firmware file for testing
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
                f.write(b"\x00" * 1024 * 100)  # 100KB dummy file
                temp_fw = f.name

            if await handler.upload_firmware(temp_fw):
                console.print("[green]Firmware uploaded[/green]")

                if await handler.update_firmware():
                    console.print("[green]Firmware update scheduled[/green]")

                    console.print("[bold]Phase 6: Rebooting...[/bold]")
                    await handler.reboot()

                    console.print("Waiting for reboot...")
                    if await handler.wait_for_reboot(timeout=30):
                        console.print("[green]Device back online[/green]")

                        # Reconnect and check new version
                        await handler.connect()
                        new_info = await handler.get_info()
                        console.print(f"[green]New firmware: {new_info.firmware_version}[/green]\n")

            import os
            os.unlink(temp_fw)

        # Final status
        console.print("[bold green]Test completed successfully![/bold green]")

    except Exception as e:
        console.print(f"[red]Test failed: {e}[/red]")
        raise

    finally:
        await handler.disconnect()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Network Device Provisioner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan network for devices")
    scan_parser.add_argument("--subnet", "-s", default="192.168.1.0/24", help="Subnet to scan")
    scan_parser.add_argument("--interface", "-i", default="eth0", help="Network interface")

    # Identify command
    identify_parser = subparsers.add_parser("identify", help="Identify device type")
    identify_parser.add_argument("ip", help="Device IP address")
    identify_parser.add_argument("--timeout", "-t", type=float, default=10, help="Probe timeout")

    # Common device arguments
    def add_device_args(p):
        p.add_argument("ip", help="Device IP address")
        p.add_argument("--type", "-t", required=True, help="Device type (cambium, mikrotik, tachyon, tarana)")
        p.add_argument("--username", "-u", default="admin", help="Device username")
        p.add_argument("--password", "-p", default="", help="Device password")

    # Info command
    info_parser = subparsers.add_parser("info", help="Get device information")
    add_device_args(info_parser)

    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Backup device configuration")
    add_device_args(backup_parser)
    backup_parser.add_argument("--output", "-o", default="backup.bin", help="Output file path")

    # Config command
    config_parser = subparsers.add_parser("config", help="Apply configuration to device")
    add_device_args(config_parser)
    config_parser.add_argument("--file", "-f", required=True, help="Configuration file (JSON)")
    config_parser.add_argument("--show-current", "-c", action="store_true", help="Show current config first")
    config_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    # Firmware command
    firmware_parser = subparsers.add_parser("firmware", help="Upload firmware to device")
    add_device_args(firmware_parser)
    firmware_parser.add_argument("--file", "-f", required=True, help="Firmware file")
    firmware_parser.add_argument("--update", action="store_true", help="Trigger firmware update after upload")
    firmware_parser.add_argument("--reboot", action="store_true", help="Reboot after update")
    firmware_parser.add_argument("--bank", type=int, help="Target firmware bank (1 or 2)")
    firmware_parser.add_argument("--timeout", type=int, default=180, help="Reboot wait timeout")
    firmware_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    # Provision command
    provision_parser = subparsers.add_parser("provision", help="Full provisioning workflow")
    add_device_args(provision_parser)
    provision_parser.add_argument("--config", "-c", help="Configuration file (JSON)")
    provision_parser.add_argument("--firmware", "-f", help="Firmware file")
    provision_parser.add_argument("--dual-bank", action="store_true", help="Update both firmware banks")

    # Reboot command
    reboot_parser = subparsers.add_parser("reboot", help="Reboot device")
    add_device_args(reboot_parser)
    reboot_parser.add_argument("--wait", "-w", action="store_true", help="Wait for device to come back")
    reboot_parser.add_argument("--timeout", type=int, default=180, help="Wait timeout in seconds")
    reboot_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    # Test command (mock device)
    test_parser = subparsers.add_parser("test", help="Test provisioning with mock device")
    test_parser.add_argument("--device-type", "-t", default="cambium",
                            choices=["cambium", "mikrotik", "tachyon", "tarana"],
                            help="Device type to simulate")
    test_parser.add_argument("--firmware", "-f", action="store_true",
                            help="Include firmware update in test")
    test_parser.add_argument("--failures", action="store_true",
                            help="Simulate random failures")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    setup_logging(args.verbose)

    # Map commands to functions
    commands = {
        "scan": cmd_scan,
        "identify": cmd_identify,
        "info": cmd_info,
        "backup": cmd_backup,
        "config": cmd_config,
        "firmware": cmd_firmware,
        "provision": cmd_provision,
        "reboot": cmd_reboot,
        "test": cmd_test,
    }

    try:
        asyncio.run(commands[args.command](args))
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted[/dim]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
