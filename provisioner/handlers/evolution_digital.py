"""Evolution Digital refurb router qualification handler.

These routers are cloud-managed via Plume and have no local management
interface.  They are qualified purely by observing link behaviour:

  * Both ports must come up at 1Gbps.
  * Link may flap periodically (~every 146 seconds) while the router
    retries its cloud registration; a bounded amount of co-flap is
    acceptable.
  * A solo-port flap (only one side drops link) indicates a bad cable
    or port — hard fail.
  * A deep-reboot burst (2+ co-flaps within the window) is inconclusive
    and the qualification is retried once.

Dispatched directly from main.py — does NOT go through handler_manager
because it needs the port_manager reference to cross-check link events
on the paired-port side of the test.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Settle period before starting the analysis window (covers plug-in bounce).
SETTLE_SECONDS = 5
# Length of the analysis window.
WATCH_WINDOW_SECONDS = 60
# Max time diff between paired port flaps to count as a co-flap.
CO_FLAP_MATCH_SECONDS = 3
# Minimum acceptable negotiated link speed.
REQUIRED_LINK_SPEED = "1Gbps"
# BURST results trigger a single retry.
MAX_RETRIES = 1


@dataclass
class QualificationResult:
    passed: bool
    caution: bool
    verdict: str  # "CLEAN" | "BURST" | "DEFECT"
    reason: str
    flap_count: int
    partner_port_connected: bool
    primary_mac: Optional[str]
    vendor_oui: Optional[str]
    vendor_name: Optional[str]


class EvolutionDigitalHandler:
    """Passive qualification handler for Evolution Digital refurb routers."""

    def __init__(
        self,
        port_manager,
        port_num: int,
        interface: Optional[str] = None,
    ):
        self.port_manager = port_manager
        self.port_num = port_num
        self.interface = interface

    def _get_partner_port(self) -> Optional[int]:
        """Find another port carrying the same ED MAC (bridged LAN partner)."""
        own_state = self.port_manager.port_states.get(self.port_num)
        if not own_state or not own_state.device_mac:
            return None
        own_mac = own_state.device_mac.upper()
        for other_num, other_state in self.port_manager.port_states.items():
            if other_num == self.port_num:
                continue
            if other_state.device_type != "evolution_digital":
                continue
            other_mac = (other_state.device_mac or "").upper()
            if other_mac and other_mac == own_mac:
                return other_num
        return None

    def _classify(
        self,
        own_events: List[Tuple[float, bool, Optional[str]]],
        partner_events: List[Tuple[float, bool, Optional[str]]],
        partner_present: bool,
    ) -> Tuple[str, str, int]:
        """Return (verdict, reason, flap_count)."""
        # Any speed change below 1Gbps on either port is a hard failure.
        for _, up, speed in own_events + partner_events:
            if up and speed and speed != REQUIRED_LINK_SPEED:
                return "DEFECT", f"link negotiated below {REQUIRED_LINK_SPEED}: {speed}", 0

        own_down = [e for e in own_events if not e[1]]
        partner_down = [e for e in partner_events if not e[1]]
        flap_count = len(own_down) + len(partner_down)

        def has_match(t: float, other: List[Tuple[float, bool, Optional[str]]]) -> bool:
            for ts, up, _ in other:
                if up:
                    continue
                if abs(ts - t) <= CO_FLAP_MATCH_SECONDS:
                    return True
            return False

        if partner_present:
            solo_own = [e for e in own_down if not has_match(e[0], partner_down)]
            solo_partner = [e for e in partner_down if not has_match(e[0], own_down)]
            if solo_own or solo_partner:
                return "DEFECT", "solo-port link flap (partner stayed up)", flap_count

            co_flaps = 0
            matched: set = set()
            for ts, _, _ in own_down:
                for idx, (pts, pup, _) in enumerate(partner_down):
                    if pup or idx in matched:
                        continue
                    if abs(pts - ts) <= CO_FLAP_MATCH_SECONDS:
                        co_flaps += 1
                        matched.add(idx)
                        break
        else:
            # No partner port — treat each own flap as a co-flap-equivalent.
            co_flaps = len(own_down)

        if co_flaps <= 1:
            return "CLEAN", "stable link", flap_count

        return "BURST", f"flap burst detected ({co_flaps} co-flaps)", flap_count

    async def _run_window(
        self,
        notify: Callable[[str, object, Optional[str]], Awaitable[None]],
        attempt: int,
    ) -> Tuple[str, str, int, bool]:
        """Run one SETTLE + WATCH_WINDOW pass and classify."""
        await notify(
            "link_qualification",
            "loading",
            f"attempt {attempt}: settle {SETTLE_SECONDS}s then watch {WATCH_WINDOW_SECONDS}s",
        )
        await asyncio.sleep(SETTLE_SECONDS)

        partner_port = self._get_partner_port()
        partner_present = partner_port is not None

        own_state = self.port_manager.port_states.get(self.port_num)
        if not own_state:
            return "DEFECT", "port state missing", 0, partner_present
        if not own_state.link_up:
            return "DEFECT", "link down at window start", 0, partner_present
        if own_state.link_speed and own_state.link_speed != REQUIRED_LINK_SPEED:
            return (
                "DEFECT",
                f"link at {own_state.link_speed}, needs {REQUIRED_LINK_SPEED}",
                0,
                partner_present,
            )

        t0 = time.time()
        await asyncio.sleep(WATCH_WINDOW_SECONDS)

        own_events = self.port_manager.get_link_events_since(self.port_num, t0)
        partner_events: List[Tuple[float, bool, Optional[str]]] = []
        if partner_port is not None:
            partner_events = self.port_manager.get_link_events_since(partner_port, t0)

        verdict, reason, flap_count = self._classify(
            own_events, partner_events, partner_present
        )

        own_state = self.port_manager.port_states.get(self.port_num)
        if own_state and not own_state.link_up:
            verdict = "DEFECT"
            reason = "link did not recover before window end"

        return verdict, reason, flap_count, partner_present

    async def provision(
        self,
        on_progress: Optional[Callable[[str, object, Optional[str]], Awaitable[None]]] = None,
    ) -> QualificationResult:
        """Run the passive qualification flow (with one BURST retry)."""

        async def notify(step: str, status, detail: Optional[str] = None):
            if on_progress:
                try:
                    await on_progress(step, status, detail)
                except Exception:
                    pass

        from ..fingerprint import evolution_digital_vendor_name

        own_state = self.port_manager.port_states.get(self.port_num)
        mac = (own_state.device_mac if own_state else None) or None
        oui = mac[:8].upper() if mac and len(mac) >= 8 else None
        vendor_name = evolution_digital_vendor_name(mac) if mac else None
        oui_label = f"{vendor_name} ({oui})" if vendor_name and oui else (oui or "")

        # Vendor tag already reads "Evolution"; put just the OEM brand in the
        # model slot so the tech sees Kaon/Actiontec/Adtran at a glance.
        model_label = vendor_name or "Refurb Router"
        await notify("model_confirmed", True, model_label)
        if mac:
            await notify("device_info", True, f"mac:{mac}|serial:")

        verdict = "DEFECT"
        reason = "qualification did not run"
        flap_count = 0
        partner_present = False

        for attempt in range(1, MAX_RETRIES + 2):
            verdict, reason, flap_count, partner_present = await self._run_window(
                notify, attempt
            )
            if verdict in ("CLEAN", "DEFECT"):
                break
            if attempt > MAX_RETRIES:
                break
            logger.info(
                f"Port {self.port_num} ED qualification attempt {attempt} "
                f"classified BURST — retrying"
            )

        passed = verdict == "CLEAN"
        caution = passed and not partner_present

        # Single-port CLEAN is promoted to CAUTION so the tech doesn't read a
        # green PASS and ship a router whose second LAN jack might be dead.
        if caution:
            status = "CAUTION"
            display_reason = "If both cables are plugged in, this unit is malfunctioning"
        elif passed:
            status = "PASS"
            display_reason = reason
        else:
            status = "FAIL"
            display_reason = reason

        await notify("link_qualification", status, display_reason)
        await notify("partner_port_connected", partner_present, None)
        await notify("flap_count", True, str(flap_count))
        await notify("result_reason", True, display_reason)
        await notify("vendor_oui", True, oui_label)

        return QualificationResult(
            passed=passed,
            caution=caution,
            verdict=verdict,
            reason=display_reason,
            flap_count=flap_count,
            partner_port_connected=partner_present,
            primary_mac=mac,
            vendor_oui=oui,
            vendor_name=vendor_name,
        )
