"""Packet dataclass representing decoded network packet data."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class Packet:
    """
    Decoupled representation of a captured network packet.

    Analyzers and output plugins MUST depend only on this dataclass,
    never on raw Scapy packet types.
    """
    src: str
    dst: str
    proto: str
    size: int
    timestamp: float
    sport: Optional[int] = None
    dport: Optional[int] = None
    info: str = ""
    raw_payload: Optional[bytes] = None
    raw_frame: Optional[bytes] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def formatted_time(self) -> str:
        """Return ISO formatted timestamp string."""
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def endpoint_summary(self) -> str:
        """Format endpoints: src[:sport] -> dst[:dport]."""
        src_str = f"{self.src}:{self.sport}" if self.sport is not None else self.src
        dst_str = f"{self.dst}:{self.dport}" if self.dport is not None else self.dst
        return f"{src_str} -> {dst_str}"

    def __str__(self) -> str:
        """Format packet in canonical format: src:sport -> dst:dport [PROTO] len=N."""
        return f"{self.endpoint_summary} [{self.proto}] len={self.size}"
