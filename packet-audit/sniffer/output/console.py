"""Console output plugin — coloured real-time packet display."""

from __future__ import annotations

import sys
from typing import TextIO

from sniffer.decode.packet import Packet

# ANSI colour codes
_C_RESET = "\033[0m"
_C_GREY = "\033[90m"

_PROTO_COLOURS: dict[str, str] = {
    "TCP": "\033[36m",     # cyan
    "UDP": "\033[33m",     # yellow
    "DNS": "\033[35m",     # magenta
    "HTTP": "\033[31m",    # red (cleartext alert!)
    "HTTPS": "\033[32m",   # green
    "ICMP": "\033[34m",    # blue
    "ICMPv6": "\033[34m",
    "ARP": "\033[37m",
    "GRE": "\033[90m",
    "ESP": "\033[90m",
}

_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "\033[1;41m",   # bold red bg
    "HIGH": "\033[1;31m",       # bold red
    "MEDIUM": "\033[1;33m",     # bold yellow
    "LOW": "\033[1;34m",        # bold blue
    "INFO": "\033[90m",         # grey
}


class ConsoleOutput:
    """Prints decoded packets to a stream (default: stdout).

    Args:
        colored:  Use ANSI colour codes.
        stream:   Output stream; default is sys.stdout.
    """

    def __init__(self, colored: bool = True, stream: TextIO | None = None) -> None:
        self._colored = colored and sys.stdout.isatty()
        self._stream = stream or sys.stdout

    def handle(self, packet: Packet) -> None:
        """Format and print *packet*."""
        ts = packet.formatted_ts
        proto = packet.proto
        info = f" {packet.info}" if packet.info else ""
        flags = f" [{packet.flags}]" if packet.flags else ""
        size = packet.size
        endpoint = packet.endpoint

        if self._colored:
            pc = _PROTO_COLOURS.get(proto, "\033[0m")
            line = (
                f"{_C_GREY}{ts}{_C_RESET} "
                f"{pc}{proto:<8}{_C_RESET} "
                f"{endpoint}{flags}{info} "
                f"{_C_GREY}len={size}{_C_RESET}"
            )
        else:
            line = f"{ts} {proto:<8} {endpoint}{flags}{info} len={size}"

        print(line, file=self._stream)

    def print_event(self, rule: str, severity: str, message: str) -> None:
        """Print an audit event alert."""
        if self._colored:
            sc = _SEVERITY_COLOURS.get(severity, "")
            line = f"  {sc}[AUDIT {severity}]{_C_RESET} [{rule}] {message}"
        else:
            line = f"  [AUDIT {severity}] [{rule}] {message}"
        print(line, file=self._stream)

    def close(self) -> None:
        """No-op; stdout is not owned by this class."""
