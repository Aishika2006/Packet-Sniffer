"""Real-time packet statistics analyzer."""

from collections import Counter
import threading
import time
from typing import Any, Optional

from sniffer.decode.packet import Packet


class StatsAnalyzer:
    """
    Computes running counters and aggregates metrics across hosts, protocols, and ports.

    Thread-safe and decoupled: relies exclusively on the Packet dataclass.
    """

    def __init__(self) -> None:
        """Initialize all counters and timing tracking."""
        self._lock = threading.Lock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        self.proto_counts: Counter[str] = Counter()
        self.proto_bytes: Counter[str] = Counter()
        self.src_ip_counts: Counter[str] = Counter()
        self.dst_ip_counts: Counter[str] = Counter()
        self.port_counts: Counter[int] = Counter()
        self.conversation_counts: Counter[str] = Counter()

    def handle(self, packet: Packet) -> None:
        """
        Record a newly decoded packet into the statistics tables.

        Args:
            packet: Standardized Packet dataclass instance.
        """
        with self._lock:
            if self.start_time is None:
                self.start_time = packet.timestamp or time.time()
            self.end_time = packet.timestamp or time.time()

            self.total_packets += 1
            self.total_bytes += packet.size

            # Protocol breakdown
            self.proto_counts[packet.proto] += 1
            self.proto_bytes[packet.proto] += packet.size

            # Host breakdown
            if packet.src and packet.src != "unknown":
                self.src_ip_counts[packet.src] += 1
            if packet.dst and packet.dst != "unknown":
                self.dst_ip_counts[packet.dst] += 1

            # Port breakdown (track destination / service ports primarily)
            if packet.dport is not None:
                self.port_counts[packet.dport] += 1

            # Conversation breakdown
            if packet.src and packet.dst:
                conv = f"{packet.src} -> {packet.dst}"
                self.conversation_counts[conv] += 1

    def get_summary(self) -> dict[str, Any]:
        """
        Return snapshot dictionary of computed metrics.

        Returns:
            Dictionary containing aggregated statistics.
        """
        with self._lock:
            now = time.time()
            start = self.start_time or now
            end = self.end_time or now
            duration = max(0.001, end - start)

            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration_seconds": duration,
                "packets_per_sec": self.total_packets / duration,
                "kbps": (self.total_bytes * 8) / (duration * 1000),
                "protocols": dict(self.proto_counts),
                "protocol_bytes": dict(self.proto_bytes),
                "top_sources": self.src_ip_counts.most_common(10),
                "top_destinations": self.dst_ip_counts.most_common(10),
                "top_ports": self.port_counts.most_common(10),
                "top_conversations": self.conversation_counts.most_common(5),
            }

    def format_summary(self, top_n: int = 5) -> str:
        """
        Generate a human-readable ASCII summary table suitable for console display.

        Args:
            top_n: Number of top items to display per category.

        Returns:
            Formatted multi-line summary string.
        """
        with self._lock:
            if self.total_packets == 0:
                return "\n=== Network Traffic Summary ===\nNo packets captured.\n"

            now = time.time()
            start = self.start_time or now
            end = self.end_time or now
            duration = max(0.001, end - start)
            pps = self.total_packets / duration
            kbps = (self.total_bytes * 8) / (duration * 1000)

            lines = [
                "\n" + "=" * 65,
                "                 NETWORK TRAFFIC SUMMARY",
                "=" * 65,
                f"Duration:            {duration:.2f} seconds",
                f"Total Packets:       {self.total_packets:,}",
                f"Total Data Volume:   {self.total_bytes / (1024 * 1024):.3f} MB ({self.total_bytes:,} bytes)",
                f"Average Throughput:  {pps:.1f} pkts/s | {kbps:.2f} Kbps",
                "-" * 65,
                f"{'Protocol Breakdown:':<30} {'Count':<15} {'Bytes':<15}",
                "-" * 65,
            ]

            for proto, count in self.proto_counts.most_common():
                b_count = self.proto_bytes.get(proto, 0)
                pct = (count / self.total_packets) * 100
                lines.append(f"  {proto:<28} {count:<6} ({pct:4.1f}%)    {b_count:<15,}")

            lines.append("-" * 65)
            lines.append(f"{'Top Source Hosts:':<40} {'Packets':<15}")
            for src, count in self.src_ip_counts.most_common(top_n):
                lines.append(f"  {src:<38} {count:<15,}")

            lines.append("-" * 65)
            lines.append(f"{'Top Destination Hosts:':<40} {'Packets':<15}")
            for dst, count in self.dst_ip_counts.most_common(top_n):
                lines.append(f"  {dst:<38} {count:<15,}")

            if self.port_counts:
                lines.append("-" * 65)
                lines.append(f"{'Top Target Ports / Services:':<40} {'Packets':<15}")
                for port, count in self.port_counts.most_common(top_n):
                    lines.append(f"  Port {port:<33} {count:<15,}")

            lines.append("=" * 65 + "\n")
            return "\n".join(lines)
