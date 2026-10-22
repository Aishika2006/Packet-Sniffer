"""Output plugin base interface."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sniffer.decode.packet import Packet


@runtime_checkable
class OutputPlugin(Protocol):
    """Every output plugin must implement this interface."""

    def handle(self, packet: Packet) -> None:
        """Process one decoded packet."""
        ...

    def close(self) -> None:
        """Flush buffers and release resources."""
        ...
