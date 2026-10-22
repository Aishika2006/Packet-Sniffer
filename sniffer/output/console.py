"""Live formatted console output plugin."""

import sys
import threading
from sniffer.decode.packet import Packet
from sniffer.output.base import BaseOutput


class ConsoleOutput(BaseOutput):
    """Prints decoded packets to standard output in real-time."""

    # Protocol color mapping for terminal styling
    COLOR_MAP = {
        "TCP": "\033[92m",    # Green
        "UDP": "\033[96m",    # Cyan
        "ICMP": "\033[93m",   # Yellow
        "DNS": "\033[95m",    # Magenta
        "HTTP": "\033[94m",   # Blue
        "ARP": "\033[90m",    # Bright Black / Gray
    }
    RESET_COLOR = "\033[0m"

    def __init__(self, colored: bool = True, show_timestamp: bool = False):
        """
        Initialize ConsoleOutput.

        Args:
            colored: Whether to use ANSI terminal color codes.
            show_timestamp: Whether to prefix output with a timestamp.
        """
        self.colored = colored and sys.stdout.isatty()
        self.show_timestamp = show_timestamp
        self._lock = threading.Lock()

    def handle(self, packet: Packet) -> None:
        """
        Format and print a packet: src:sport -> dst:dport [PROTO] len=N.

        Args:
            packet: Decoded Packet dataclass instance.
        """
        line = str(packet)
        if packet.info:
            line = f"{line} ({packet.info})"

        if self.show_timestamp:
            line = f"[{packet.formatted_time}] {line}"

        if self.colored:
            proto_upper = packet.proto.upper()
            color = self.COLOR_MAP.get(proto_upper, "")
            if color:
                line = f"{color}{line}{self.RESET_COLOR}"

        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def close(self) -> None:
        """Flush standard output stream."""
        with self._lock:
            sys.stdout.flush()
