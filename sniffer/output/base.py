"""Base output plugin interface for packet handlers."""

from abc import ABC, abstractmethod
from sniffer.decode.packet import Packet


class BaseOutput(ABC):
    """Abstract base class for all output plugins."""

    @abstractmethod
    def handle(self, packet: Packet) -> None:
        """
        Process a decoded packet.

        Args:
            packet: Standardized Packet dataclass instance.
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Flush buffers and release any held resources (files, sockets, DB connections)."""
        pass
