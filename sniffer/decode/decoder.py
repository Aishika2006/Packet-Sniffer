"""Decodes raw Scapy packets into clean, decoupled Packet dataclass instances."""

import logging
import time
from typing import Any, List, Optional, Protocol
import scapy.all as scapy
from sniffer.decode.packet import Packet

logger = logging.getLogger(__name__)

# Standard IP protocol numbers to human-readable names
PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Route",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


class ProtocolParser(Protocol):
    """Protocol parser interface for layer-7 decoders (DNS, HTTP, etc.)."""
    def parse(self, raw_pkt: Any, packet: Packet) -> None:
        """Enrich the decoded Packet dataclass instance in-place."""
        ...


class PacketDecoder:
    """
    Decodes raw Scapy packets into clean Packet dataclass instances.
    Maintains zero Scapy dependency leakage into downstream pipeline.
    """

    def __init__(self, parsers: Optional[List[ProtocolParser]] = None) -> None:
        """
        Initialize the decoder with optional protocol parsers.
        If None, default DNS and HTTP/TLS protocol parsers are enabled.

        Args:
            parsers: List of protocol parser instances (e.g. DNS, HTTP).
        """
        if parsers is None:
            from sniffer.decode.protocols.dns import DNSParser
            from sniffer.decode.protocols.http import HTTPParser
            self.parsers: List[ProtocolParser] = [DNSParser(), HTTPParser()]
        else:
            self.parsers = list(parsers)

    def register_parser(self, parser: ProtocolParser) -> None:
        """Register a protocol parser."""
        self.parsers.append(parser)

    def decode(self, raw_pkt: Any) -> Optional[Packet]:
        """
        Transform a raw Scapy packet into a decoupled Packet dataclass.

        Args:
            raw_pkt: Raw Scapy packet.

        Returns:
            Packet instance, or None if packet could not be parsed.
        """
        try:
            pkt_time = float(getattr(raw_pkt, "time", time.time()))
            pkt_size = len(raw_pkt)

            src = "unknown"
            dst = "unknown"
            proto = "RAW"
            sport: Optional[int] = None
            dport: Optional[int] = None
            info = ""
            raw_payload: Optional[bytes] = None
            metadata: dict[str, Any] = {}

            # 1. Network Layer (Layer 3)
            if raw_pkt.haslayer(scapy.IP):
                ip_layer = raw_pkt[scapy.IP]
                src = ip_layer.src
                dst = ip_layer.dst
                proto = PROTO_NAMES.get(ip_layer.proto, f"IP({ip_layer.proto})")
                metadata["ttl"] = ip_layer.ttl
                metadata["ip_version"] = 4
            elif raw_pkt.haslayer(scapy.IPv6):
                ipv6_layer = raw_pkt[scapy.IPv6]
                src = ipv6_layer.src
                dst = ipv6_layer.dst
                proto = PROTO_NAMES.get(ipv6_layer.nh, f"IPv6({ipv6_layer.nh})")
                metadata["hop_limit"] = ipv6_layer.hlim
                metadata["ip_version"] = 6
            elif raw_pkt.haslayer(scapy.ARP):
                arp_layer = raw_pkt[scapy.ARP]
                src = arp_layer.psrc or arp_layer.hwsrc
                dst = arp_layer.pdst or arp_layer.hwdst
                proto = "ARP"
                op = "who-has" if arp_layer.op == 1 else "is-at" if arp_layer.op == 2 else f"op={arp_layer.op}"
                info = f"{op} {dst}"
                metadata["arp_op"] = arp_layer.op
            elif raw_pkt.haslayer(scapy.Ether):
                eth_layer = raw_pkt[scapy.Ether]
                src = eth_layer.src
                dst = eth_layer.dst
                proto = f"Ether(0x{eth_layer.type:04x})"

            # 2. Transport Layer (Layer 4)
            if raw_pkt.haslayer(scapy.TCP):
                tcp_layer = raw_pkt[scapy.TCP]
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
                proto = "TCP"
                flags = str(tcp_layer.flags)
                if flags:
                    info = f"flags={flags}"
                metadata["tcp_flags"] = flags
                metadata["seq"] = tcp_layer.seq
                metadata["ack"] = tcp_layer.ack
            elif raw_pkt.haslayer(scapy.UDP):
                udp_layer = raw_pkt[scapy.UDP]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
                proto = "UDP"
            elif raw_pkt.haslayer(scapy.ICMP):
                icmp_layer = raw_pkt[scapy.ICMP]
                proto = "ICMP"
                info = f"type={icmp_layer.type} code={icmp_layer.code}"
                metadata["icmp_type"] = icmp_layer.type
                metadata["icmp_code"] = icmp_layer.code
            elif raw_pkt.haslayer(scapy.ICMPv6Unknown):
                proto = "ICMPv6"

            # 3. Raw Payload and Raw Frame Extraction
            raw_frame: Optional[bytes] = None
            try:
                raw_frame = bytes(raw_pkt)
            except Exception:
                raw_frame = None

            if raw_pkt.haslayer(scapy.Raw):
                try:
                    raw_payload = bytes(raw_pkt[scapy.Raw].load)
                except Exception:
                    raw_payload = None

            packet = Packet(
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                proto=proto,
                size=pkt_size,
                timestamp=pkt_time,
                info=info,
                raw_payload=raw_payload,
                raw_frame=raw_frame,
                metadata=metadata,
            )

            # 4. Optional higher-layer protocol parsers (DNS, HTTP)
            for parser in self.parsers:
                try:
                    parser.parse(raw_pkt, packet)
                except Exception as e:
                    logger.debug("Protocol parser %s error: %s", parser.__class__.__name__, e)

            return packet

        except Exception as e:
            logger.debug("Failed to decode packet: %s", e)
            return None


# Default global decoder instance
_DEFAULT_DECODER = PacketDecoder()


def decode_packet(raw_pkt: Any) -> Optional[Packet]:
    """Convenience function using the default PacketDecoder."""
    return _DEFAULT_DECODER.decode(raw_pkt)
