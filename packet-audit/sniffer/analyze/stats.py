"""Traffic statistics analyzer — counters, top-N, and summary generation.

Depends only on Packet dataclass; no Scapy types.
"""

from __future__ import annotations

import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class StatsSnapshot:
    """Point-in-time statistics snapshot."""
    ts: str
    total_packets: int
    total_bytes: int
    proto_counts: dict[str, int]
    top_talkers_src: list[tuple[str, int]]
    top_talkers_dst: list[tuple[str, int]]
    top_ports_dst: list[tuple[int, int]]
    dropped_packets: int


class StatsAnalyzer:
    """Thread-safe real-time traffic counters.

    Attributes:
        drop_count: Incremented by the capture thread on queue-full events.
    """

    def __init__(self, top_n: int = 10) -> None:
        self._lock = threading.Lock()
        self._top_n = top_n
        self._total_packets = 0
        self._total_bytes = 0
        self._proto_counts: Counter[str] = Counter()
        self._src_bytes: Counter[str] = Counter()
        self._dst_bytes: Counter[str] = Counter()
        self._dst_port_counts: Counter[int] = Counter()
        self.drop_count = 0

    # ------------------------------------------------------------------
    # Plugin interface
    # ------------------------------------------------------------------

    def handle(self, packet: Any) -> None:
        """Update counters from *packet*."""
        with self._lock:
            self._total_packets += 1
            self._total_bytes += packet.size
            self._proto_counts[packet.proto] += 1
            self._src_bytes[packet.src] += packet.size
            self._dst_bytes[packet.dst] += packet.size
            if packet.dport is not None:
                self._dst_port_counts[packet.dport] += 1

    def close(self) -> None:
        """No-op; kept for plugin interface parity."""

    # ------------------------------------------------------------------
    # Snapshot / summary
    # ------------------------------------------------------------------

    def snapshot(self) -> StatsSnapshot:
        """Return a thread-safe snapshot of current counters."""
        with self._lock:
            return StatsSnapshot(
                ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                proto_counts=dict(self._proto_counts),
                top_talkers_src=self._src_bytes.most_common(self._top_n),
                top_talkers_dst=self._dst_bytes.most_common(self._top_n),
                top_ports_dst=[
                    (p, c) for p, c in self._dst_port_counts.most_common(self._top_n)
                ],
                dropped_packets=self.drop_count,
            )

    def print_summary(self) -> None:
        """Print a formatted summary to stdout."""
        s = self.snapshot()
        print("\n" + "=" * 60)
        print("  TRAFFIC STATISTICS SUMMARY")
        print("=" * 60)
        print(f"  Capture time:    {s.ts}")
        print(f"  Total packets:   {s.total_packets:,}")
        print(f"  Total bytes:     {s.total_bytes:,}")
        print(f"  Dropped packets: {s.dropped_packets:,}")
        print()
        print("  Protocol breakdown:")
        for proto, cnt in sorted(s.proto_counts.items(), key=lambda x: -x[1]):
            print(f"    {proto:<14} {cnt:>8,}")
        print()
        print(f"  Top {self._top_n} source IP (bytes):")
        for ip, b in s.top_talkers_src:
            print(f"    {ip:<20} {b:>12,} B")
        print()
        print(f"  Top {self._top_n} destination IP (bytes):")
        for ip, b in s.top_talkers_dst:
            print(f"    {ip:<20} {b:>12,} B")
        print()
        print(f"  Top {self._top_n} destination ports:")
        for port, cnt in s.top_ports_dst:
            print(f"    :{port:<6}  {cnt:>8,} packets")
        print("=" * 60)
