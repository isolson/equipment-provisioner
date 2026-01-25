"""Display controller for screen sleep/wake functionality."""

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class DisplayController:
    """Controls display sleep/wake via DPMS, backlight, or framebuffer."""

    def __init__(
        self,
        sleep_timeout: int = 300,
        wake_on_connect: bool = True,
        use_dpms: bool = True,
        use_backlight: bool = True,
    ):
        """Initialize display controller.

        Args:
            sleep_timeout: Seconds of inactivity before sleep (0 = disabled).
            wake_on_connect: Wake display when device connects.
            use_dpms: Try DPMS (X11) for display control.
            use_backlight: Fallback to sysfs backlight control.
        """
        self.sleep_timeout = sleep_timeout
        self.wake_on_connect = wake_on_connect
        self.use_dpms = use_dpms
        self.use_backlight = use_backlight

        self._sleeping = False
        self._saved_brightness: Optional[int] = None
        self._backlight_path: Optional[Path] = None
        self._max_brightness: int = 255

        # Find backlight device
        self._init_backlight()

    def _init_backlight(self) -> None:
        """Find and initialize backlight sysfs path."""
        backlight_base = Path("/sys/class/backlight")
        if not backlight_base.exists():
            logger.debug("No backlight sysfs directory found")
            return

        # Look for backlight devices
        for device in backlight_base.iterdir():
            brightness_path = device / "brightness"
            max_brightness_path = device / "max_brightness"

            if brightness_path.exists() and max_brightness_path.exists():
                try:
                    self._max_brightness = int(max_brightness_path.read_text().strip())
                    self._backlight_path = brightness_path
                    logger.info(f"Found backlight device: {device.name} (max: {self._max_brightness})")
                    return
                except (ValueError, PermissionError) as e:
                    logger.debug(f"Cannot use backlight {device.name}: {e}")

        logger.debug("No usable backlight device found")

    def _run_command(self, cmd: list[str]) -> bool:
        """Run a shell command, return success status."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                return True
            logger.debug(f"Command failed: {' '.join(cmd)} -> {result.stderr.decode()}")
            return False
        except subprocess.TimeoutExpired:
            logger.debug(f"Command timed out: {' '.join(cmd)}")
            return False
        except FileNotFoundError:
            logger.debug(f"Command not found: {cmd[0]}")
            return False
        except Exception as e:
            logger.debug(f"Command error: {e}")
            return False

    def _sleep_dpms(self) -> bool:
        """Put display to sleep using DPMS (X11)."""
        return self._run_command(["xset", "dpms", "force", "off"])

    def _wake_dpms(self) -> bool:
        """Wake display using DPMS (X11)."""
        return self._run_command(["xset", "dpms", "force", "on"])

    def _sleep_backlight(self) -> bool:
        """Put display to sleep using sysfs backlight."""
        if not self._backlight_path:
            return False

        try:
            # Save current brightness
            self._saved_brightness = int(self._backlight_path.read_text().strip())
            # Set to zero
            self._backlight_path.write_text("0")
            logger.debug(f"Backlight set to 0 (was {self._saved_brightness})")
            return True
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot control backlight: {e}")
            return False

    def _wake_backlight(self) -> bool:
        """Wake display using sysfs backlight."""
        if not self._backlight_path:
            return False

        try:
            # Restore saved brightness or use max
            brightness = self._saved_brightness or self._max_brightness
            self._backlight_path.write_text(str(brightness))
            logger.debug(f"Backlight restored to {brightness}")
            return True
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot control backlight: {e}")
            return False

    def _sleep_framebuffer(self) -> bool:
        """Put display to sleep using framebuffer blank."""
        fb_blank = Path("/sys/class/graphics/fb0/blank")
        if not fb_blank.exists():
            return False

        try:
            fb_blank.write_text("1")
            logger.debug("Framebuffer blanked")
            return True
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot blank framebuffer: {e}")
            return False

    def _wake_framebuffer(self) -> bool:
        """Wake display using framebuffer unblank."""
        fb_blank = Path("/sys/class/graphics/fb0/blank")
        if not fb_blank.exists():
            return False

        try:
            fb_blank.write_text("0")
            logger.debug("Framebuffer unblanked")
            return True
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot unblank framebuffer: {e}")
            return False

    async def sleep(self) -> bool:
        """Put display to sleep.

        Tries methods in order: DPMS -> backlight -> framebuffer.
        Returns True if any method succeeded.
        """
        if self._sleeping:
            logger.debug("Display already sleeping")
            return True

        success = False

        # Try DPMS first
        if self.use_dpms:
            if self._sleep_dpms():
                logger.info("Display sleeping via DPMS")
                success = True

        # Try backlight (can be used alongside DPMS)
        if self.use_backlight:
            if self._sleep_backlight():
                logger.info("Display sleeping via backlight")
                success = True

        # Last resort: framebuffer blank
        if not success:
            if self._sleep_framebuffer():
                logger.info("Display sleeping via framebuffer")
                success = True

        if success:
            self._sleeping = True
        else:
            logger.warning("Could not put display to sleep (no available method)")

        return success

    async def wake(self) -> bool:
        """Wake display from sleep.

        Tries all enabled methods to ensure display is on.
        Returns True if any method succeeded.
        """
        if not self._sleeping:
            logger.debug("Display already awake")
            return True

        success = False

        # Try all methods to ensure display is on
        if self.use_dpms:
            if self._wake_dpms():
                logger.info("Display woke via DPMS")
                success = True

        if self.use_backlight:
            if self._wake_backlight():
                logger.info("Display woke via backlight")
                success = True

        # Framebuffer unblank
        if self._wake_framebuffer():
            logger.info("Display woke via framebuffer")
            success = True

        if success:
            self._sleeping = False
        else:
            # Even if no method worked, mark as awake to allow retry
            self._sleeping = False
            logger.warning("Could not wake display (no available method)")

        return success

    def is_sleeping(self) -> bool:
        """Check if display is currently sleeping."""
        return self._sleeping

    def get_status(self) -> dict:
        """Get display controller status."""
        return {
            "sleeping": self._sleeping,
            "sleep_timeout": self.sleep_timeout,
            "wake_on_connect": self.wake_on_connect,
            "dpms_available": self.use_dpms,
            "backlight_available": self._backlight_path is not None,
            "backlight_path": str(self._backlight_path) if self._backlight_path else None,
        }


# Global display controller instance
_display: Optional[DisplayController] = None


def get_display() -> Optional[DisplayController]:
    """Get the global display controller instance."""
    return _display


def init_display(
    sleep_timeout: int = 300,
    wake_on_connect: bool = True,
    use_dpms: bool = True,
    use_backlight: bool = True,
) -> DisplayController:
    """Initialize the global display controller instance."""
    global _display
    _display = DisplayController(
        sleep_timeout=sleep_timeout,
        wake_on_connect=wake_on_connect,
        use_dpms=use_dpms,
        use_backlight=use_backlight,
    )
    logger.info(f"Display controller initialized (timeout: {sleep_timeout}s)")
    return _display


def cleanup_display() -> None:
    """Cleanup display controller resources."""
    global _display
    if _display and _display.is_sleeping():
        # Ensure display is on when shutting down
        asyncio.create_task(_display.wake())
    _display = None
