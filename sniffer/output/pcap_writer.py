"""PCAP file output plugin for persistent packet storage."""

import logging
from pathlib import Path
import threading
from typing import Optional

import scapy.all as scapy
from scapy.utils import RawPcapWriter

from sniffer.decode.packet import Packet
from sniffer.output.base import BaseOutput

logger = logging.getLogger(__name__)


class PcapWriterOutput(BaseOutput):
    """
    Output plugin that persists captured packets to standard .pcap format.

    Depends strictly on the Packet dataclass, writing raw frame bytes
    or synthesizing valid IP frames if raw frame bytes are absent.
    """

    def __init__(self, filepath: str | Path, sync: bool = True) -> None:
        """
        Initialize the PCAP writer plugin.

        Args:
            filepath: Destination file path for the .pcap file.
            sync: Whether to synchronously flush each packet to disk.
        """
        self.filepath = Path(filepath)
        self.sync = sync
        self._lock = threading.Lock()
        self.packets_written: int = 0
        self._writer: Optional[RawPcapWriter] = None

        # Ensure directory exists
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Default to standard Ethernet (linktype=1 / DLT_EN10MB)
            self._writer = RawPcapWriter(str(self.filepath), linktype=1, append=False, sync=self.sync)
            logger.info("Initialized PCAP writer output: %s", self.filepath)
        except Exception as e:
            logger.error("Failed to initialize PCAP file %s: %s", self.filepath, e)
            self._writer = None

    def handle(self, packet: Packet) -> None:
        """
        Write a Packet dataclass instance to the .pcap file.

        Args:
            packet: Standardized Packet dataclass instance.
        """
        if self._writer is None:
            return

        with self._lock:
            try:
                frame_bytes: Optional[bytes] = packet.raw_frame

                # If raw_frame is missing (e.g. mocked packet), synthesize a valid frame
                if not frame_bytes:
                    frame_bytes = self._synthesize_frame(packet)

                if frame_bytes:
                    self._writer.write(frame_bytes)
                    self.packets_written += 1
            except Exception as e:
                logger.error("Error writing packet to PCAP file %s: %s", self.filepath, e)

    def _synthesize_frame(self, packet: Packet) -> bytes:
        """Fallback to synthesize Ethernet/IP frame bytes from Packet dataclass fields."""
        try:
            proto_upper = packet.proto.upper()
            payload = packet.raw_payload or b""

            if proto_upper == "TCP":
                l4 = scapy.TCP(sport=packet.sport or 0, dport=packet.dport or 0) / payload
            elif proto_upper == "UDP":
                l4 = scapy.UDP(sport=packet.sport or 0, dport=packet.dport or 0) / payload
            elif proto_upper == "ICMP":
                l4 = scapy.ICMP() / payload
            else:
                l4 = scapy.Raw(load=payload)

            ip_pkt = scapy.IP(src=packet.src, dst=packet.dst) / l4
            eth_pkt = scapy.Ether() / ip_pkt
            return bytes(eth_pkt)
        except Exception as e:
            logger.debug("Could not synthesize packet frame: %s", e)
            return b""

    def close(self) -> None:
        """Flush and safely close the PCAP file writer."""
        with self._lock:
            if self._writer is not None:
                try:
                    self._writer.flush()
                    self._writer.close()
                    logger.info("PCAP writer closed. Saved %d packets to %s", self.packets_written, self.filepath)
                except Exception as e:
                    logger.error("Error closing PCAP writer: %s", e)
                finally:
                    self._writer = None
