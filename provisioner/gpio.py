"""GPIO control for OrangePi LED and buzzer indicators."""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import GPIO library
try:
    import OPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    try:
        import RPi.GPIO as GPIO
        GPIO_AVAILABLE = True
    except ImportError:
        GPIO = None
        GPIO_AVAILABLE = False
        logger.warning("GPIO library not available - running in simulation mode")


class GPIOController:
    """Controls LEDs and buzzer via GPIO pins."""

    def __init__(
        self,
        green_led: int = 7,
        red_led: int = 8,
        yellow_led: int = 9,
        buzzer: int = 10,
        enabled: bool = True,
    ):
        """Initialize GPIO controller.

        Args:
            green_led: GPIO pin for green LED (success).
            red_led: GPIO pin for red LED (error).
            yellow_led: GPIO pin for yellow LED (in progress).
            buzzer: GPIO pin for buzzer.
            enabled: Whether GPIO control is enabled.
        """
        self.green_led = green_led
        self.red_led = red_led
        self.yellow_led = yellow_led
        self.buzzer = buzzer
        self.enabled = enabled and GPIO_AVAILABLE
        self._initialized = False
        self._blink_task: Optional[asyncio.Task] = None

    def setup(self) -> None:
        """Setup GPIO pins."""
        if not self.enabled:
            logger.info("GPIO disabled or unavailable - using simulation mode")
            return

        try:
            GPIO.setmode(GPIO.BOARD)
            GPIO.setwarnings(False)

            # Setup output pins
            for pin in [self.green_led, self.red_led, self.yellow_led, self.buzzer]:
                GPIO.setup(pin, GPIO.OUT)
                GPIO.output(pin, GPIO.LOW)

            self._initialized = True
            logger.info("GPIO initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize GPIO: {e}")
            self.enabled = False

    def cleanup(self) -> None:
        """Cleanup GPIO resources."""
        if self._blink_task:
            self._blink_task.cancel()

        if self._initialized and self.enabled:
            try:
                # Turn off all outputs
                for pin in [self.green_led, self.red_led, self.yellow_led, self.buzzer]:
                    GPIO.output(pin, GPIO.LOW)
                GPIO.cleanup()
            except Exception as e:
                logger.error(f"GPIO cleanup error: {e}")

        self._initialized = False

    def _set_pin(self, pin: int, state: bool) -> None:
        """Set a GPIO pin state."""
        if not self.enabled or not self._initialized:
            logger.debug(f"GPIO simulation: pin {pin} = {state}")
            return

        try:
            GPIO.output(pin, GPIO.HIGH if state else GPIO.LOW)
        except Exception as e:
            logger.error(f"Failed to set GPIO pin {pin}: {e}")

    async def set_status(self, status: str) -> None:
        """Set LED status indicator.

        Args:
            status: One of "idle", "in_progress", "success", "error".
        """
        # Cancel any existing blink task
        if self._blink_task:
            self._blink_task.cancel()
            self._blink_task = None

        if status == "idle":
            self._set_pin(self.green_led, False)
            self._set_pin(self.yellow_led, False)
            self._set_pin(self.red_led, False)

        elif status == "in_progress":
            self._set_pin(self.green_led, False)
            self._set_pin(self.red_led, False)
            # Blink yellow LED
            self._blink_task = asyncio.create_task(
                self._blink_led(self.yellow_led, interval=0.5)
            )

        elif status == "success":
            self._set_pin(self.yellow_led, False)
            self._set_pin(self.red_led, False)
            self._set_pin(self.green_led, True)

        elif status == "error":
            self._set_pin(self.yellow_led, False)
            self._set_pin(self.green_led, False)
            self._set_pin(self.red_led, True)

    async def _blink_led(self, pin: int, interval: float = 0.5) -> None:
        """Blink an LED continuously."""
        state = False
        try:
            while True:
                state = not state
                self._set_pin(pin, state)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            self._set_pin(pin, False)

    async def beep(self, count: int = 1, duration: float = 0.2, pause: float = 0.2) -> None:
        """Sound the buzzer.

        Args:
            count: Number of beeps.
            duration: Duration of each beep in seconds.
            pause: Pause between beeps in seconds.
        """
        for i in range(count):
            self._set_pin(self.buzzer, True)
            await asyncio.sleep(duration)
            self._set_pin(self.buzzer, False)
            if i < count - 1:
                await asyncio.sleep(pause)

    async def success_pattern(self) -> None:
        """Play success indication pattern."""
        await self.set_status("success")
        await self.beep(count=2, duration=0.1, pause=0.1)

    async def error_pattern(self) -> None:
        """Play error indication pattern."""
        await self.set_status("error")
        await self.beep(count=3, duration=0.3, pause=0.2)

    async def startup_pattern(self) -> None:
        """Play startup indication pattern."""
        # Flash all LEDs briefly
        for pin in [self.green_led, self.yellow_led, self.red_led]:
            self._set_pin(pin, True)
        await asyncio.sleep(0.3)
        for pin in [self.green_led, self.yellow_led, self.red_led]:
            self._set_pin(pin, False)

        # Single beep
        await self.beep(count=1, duration=0.1)

        # Set to idle
        await self.set_status("idle")


# Global GPIO controller instance
_gpio: Optional[GPIOController] = None


def get_gpio() -> Optional[GPIOController]:
    """Get the global GPIO controller instance."""
    return _gpio


def init_gpio(
    green_led: int = 7,
    red_led: int = 8,
    yellow_led: int = 9,
    buzzer: int = 10,
    enabled: bool = True,
) -> GPIOController:
    """Initialize the global GPIO controller instance."""
    global _gpio
    _gpio = GPIOController(
        green_led=green_led,
        red_led=red_led,
        yellow_led=yellow_led,
        buzzer=buzzer,
        enabled=enabled,
    )
    _gpio.setup()
    return _gpio


def cleanup_gpio() -> None:
    """Cleanup GPIO resources."""
    global _gpio
    if _gpio:
        _gpio.cleanup()
        _gpio = None
