"""Packet dataclass — the canonical, Scapy-free representation of a decoded packet.

All downstream analyzers, detectors, and output plugins depend *only* on this type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Packet:
    """Decoded network packet.

    Attributes:
        ts:          Capture timestamp (Unix epoch float).
        src:         Source IP address string.
        dst:         Destination IP address string.
        sport:       Source port (None for ICMP/ARP).
        dport:       Destination port (None for ICMP/ARP).
        proto:       Protocol label: "TCP", "UDP", "DNS", "HTTP", "HTTPS",
                     "ICMP", "ICMPv6", "ARP", "VLAN", "GRE", "ESP", etc.
        size:        Total frame size in bytes.
        flags:       TCP flag string e.g. "S", "SA", "PA" (empty for non-TCP).
        ttl:         IP TTL / IPv6 hop-limit, or None.
        frag:        True if packet is a fragment.
        truncated:   True if payload was truncated during capture.
        vlan_id:     VLAN tag ID if present, else None.
        ip_version:  4 or 6, or None for Layer-2 only (ARP).
        raw_payload: Application-layer bytes (None unless log_payload is enabled).
        raw_frame:   Full frame bytes for pcap re-writing (always populated).
        metadata:    Protocol-specific enrichment (dns, http, tls dicts).
    """

    ts: float
    src: str
    dst: str
    proto: str
    size: int
    sport: int | None = None
    dport: int | None = None
    flags: str = ""
    ttl: int | None = None
    frag: bool = False
    truncated: bool = False
    vlan_id: int | None = None
    ip_version: int | None = None
    raw_payload: bytes | None = None
    raw_frame: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    info: str = ""

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    @property
    def formatted_ts(self) -> str:
        """Return ISO-8601 timestamp string."""
        return datetime.fromtimestamp(self.ts).strftime("%H:%M:%S.%f")[:-3]

    @property
    def endpoint(self) -> str:
        """Return 'src[:sport] -> dst[:dport]' endpoint string."""
        s = f"{self.src}:{self.sport}" if self.sport is not None else self.src
        d = f"{self.dst}:{self.dport}" if self.dport is not None else self.dst
        return f"{s} -> {d}"

    def __str__(self) -> str:
        """Canonical console format: src:sport -> dst:dport [PROTO] len=N."""
        return f"{self.endpoint} [{self.proto}] len={self.size}"
