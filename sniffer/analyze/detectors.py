"""Security anomaly detectors: port-scan detection."""

from collections import defaultdict, deque
import logging
import threading
import time
from typing import Callable, Deque, Dict, Optional, Set, Tuple

from sniffer.decode.packet import Packet

logger = logging.getLogger(__name__)


class PortScanDetector:
    """
    Detects potential port-scanning activity by tracking distinct destination ports
    contacted by a source IP within a sliding time window.
    """

    def __init__(
        self,
        threshold: int = 15,
        window_seconds: float = 10.0,
        on_alert: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize the detector.

        Args:
            threshold: Number of distinct destination ports to trigger an alert.
            window_seconds: Sliding time window in seconds.
            on_alert: Optional callback invoked with the alert string.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.on_alert = on_alert
        self._lock = threading.Lock()

        # Map: src_ip -> deque of (timestamp, dst_ip, dst_port)
        self._history: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)
        # Track already alerted IPs to avoid alert spamming
        self._alerted_ips: Dict[str, float] = {}
        self.alerts_count: int = 0

    def handle(self, packet: Packet) -> None:
        """
        Analyze a decoded packet for port scan signatures.

        Args:
            packet: Standardized Packet dataclass instance.
        """
        if packet.dport is None or not packet.src or packet.src == "unknown":
            return

        now = packet.timestamp or time.time()

        with self._lock:
            history = self._history[packet.src]
            history.append((now, packet.dst, packet.dport))

            # Evict entries older than sliding window
            cutoff = now - self.window_seconds
            while history and history[0][0] < cutoff:
                history.popleft()

            # Count distinct destination ports in the current window
            distinct_ports: Set[int] = {port for _, _, port in history}

            if len(distinct_ports) >= self.threshold:
                last_alert_time = self._alerted_ips.get(packet.src, 0.0)
                # Suppress duplicate alerts for the same source for at least window_seconds
                if now - last_alert_time >= self.window_seconds:
                    self._alerted_ips[packet.src] = now
                    self.alerts_count += 1
                    target_hosts = {dst for _, dst, _ in history}
                    alert_msg = (
                        f"[SECURITY ALERT] Port scan detected from {packet.src} -> "
                        f"scanned {len(distinct_ports)} distinct ports across {len(target_hosts)} host(s) "
                        f"in {self.window_seconds:.1f}s!"
                    )
                    logger.warning(alert_msg)
                    if self.on_alert:
                        try:
                            self.on_alert(alert_msg)
                        except Exception as e:
                            logger.error("Error executing alert callback: %s", e)

    def reset(self) -> None:
        """Reset all detector history and state."""
        with self._lock:
            self._history.clear()
            self._alerted_ips.clear()
            self.alerts_count = 0
