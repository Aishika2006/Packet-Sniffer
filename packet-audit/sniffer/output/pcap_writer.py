"""PCAP writer output plugin — writes captured packets to standard pcap file."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

import scapy.all as scapy

from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)


class PcapWriterOutput:
    """Writes packets to a .pcap file using Scapy's PcapWriter.

    Thread-safe; synchronized across threads if needed.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._writer = scapy.PcapWriter(str(self.path), append=True, sync=True)
        log.info("PCAP output opened at %s", self.path)

    def handle(self, packet: Packet) -> None:
        """Write raw frame of packet to pcap."""
        if not packet.raw_frame:
            return
        with self._lock:
            try:
                raw_scapy_pkt = scapy.Ether(packet.raw_frame)
                raw_scapy_pkt.time = packet.ts
                self._writer.write(raw_scapy_pkt)
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("PCAP write failed: %s", exc)

    def close(self) -> None:
        """Close underlying pcap writer."""
        with self._lock:
            try:
                self._writer.close()
                log.info("PCAP writer closed")
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("Error closing PCAP writer: %s", exc)
