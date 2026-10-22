"""PacketDecoder — transforms raw Scapy frames into Packet dataclass instances.

Handles:
- IPv4 and IPv6 network layers
- VLAN (802.1Q) encapsulation
- IP fragmentation detection
- TCP / UDP / ICMP / ICMPv6 / ARP transport layers
- Truncated / malformed packet detection
- Optional payload logging (gated by log_payload flag)
- Protocol parsers: DNS, HTTP, TLS
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional, Protocol, runtime_checkable

import scapy.all as scapy

from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)

_PROTO_NAMES: dict[int, str] = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
    58: "ICMPv6", 89: "OSPF",
}


@runtime_checkable
class ProtocolParser(Protocol):
    """Interface all layer-7 parsers must satisfy."""

    def parse(self, raw_pkt: Any, packet: Packet) -> None:
        """Enrich *packet* in place from *raw_pkt*."""
        ...


class PacketDecoder:
    """Decodes Scapy packets into Packet dataclasses.

    Args:
        log_payload: If True, stores raw application-layer bytes in
                     ``Packet.raw_payload``. Off by default for privacy.
        parsers:     Protocol parsers applied in order after L3/L4 decode.
                     Defaults to [DNSParser(), HTTPParser(), TLSParser()].
    """

    def __init__(
        self,
        log_payload: bool = False,
        parsers: list[ProtocolParser] | None = None,
    ) -> None:
        self.log_payload = log_payload
        if parsers is None:
            from sniffer.decode.protocols.dns import DNSParser
            from sniffer.decode.protocols.http import HTTPParser
            from sniffer.decode.protocols.tls import TLSParser
            self.parsers: list[ProtocolParser] = [DNSParser(), HTTPParser(), TLSParser()]
        else:
            self.parsers = list(parsers)

    def decode(self, raw_pkt: Any) -> Optional[Packet]:
        """Decode *raw_pkt* into a Packet dataclass.

        Returns:
            A ``Packet`` instance, or ``None`` if decoding fails entirely.
        """
        try:
            return self._decode(raw_pkt)
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("Decode error (dropping packet): %s", exc)
            return None

    # ------------------------------------------------------------------
    # Internal decode logic
    # ------------------------------------------------------------------

    def _decode(self, raw_pkt: Any) -> Packet:
        ts = float(getattr(raw_pkt, "time", time.time()))
        size = len(raw_pkt)

        src = dst = "unknown"
        proto = "RAW"
        sport: Optional[int] = None
        dport: Optional[int] = None
        flags = ""
        ttl: Optional[int] = None
        frag = False
        truncated = False
        vlan_id: Optional[int] = None
        ip_version: Optional[int] = None
        raw_payload: Optional[bytes] = None
        info = ""
        metadata: dict[str, Any] = {}

        # ---- VLAN --------------------------------------------------------
        if raw_pkt.haslayer(scapy.Dot1Q):
            vlan_id = int(raw_pkt[scapy.Dot1Q].vlan)

        # ---- Layer 3 -----------------------------------------------------
        if raw_pkt.haslayer(scapy.IP):
            ip = raw_pkt[scapy.IP]
            src, dst = ip.src, ip.dst
            ip_version = 4
            ttl = int(ip.ttl)
            # Detect IP fragmentation (MF flag or non-zero frag offset)
            frag = bool(ip.flags & 0x1) or (ip.frag != 0)
            proto = _PROTO_NAMES.get(ip.proto, f"IP({ip.proto})")
            metadata["ttl"] = ttl
            metadata["ip_version"] = 4
        elif raw_pkt.haslayer(scapy.IPv6):
            ip6 = raw_pkt[scapy.IPv6]
            src, dst = ip6.src, ip6.dst
            ip_version = 6
            ttl = int(ip6.hlim)
            proto = _PROTO_NAMES.get(ip6.nh, f"IPv6({ip6.nh})")
            metadata["hop_limit"] = ttl
            metadata["ip_version"] = 6
        elif raw_pkt.haslayer(scapy.ARP):
            arp = raw_pkt[scapy.ARP]
            src = arp.psrc or arp.hwsrc
            dst = arp.pdst or arp.hwdst
            proto = "ARP"
            op = {1: "who-has", 2: "is-at"}.get(arp.op, f"op={arp.op}")
            info = f"{op} {dst}"
            metadata["arp_op"] = arp.op
        elif raw_pkt.haslayer(scapy.Ether):
            eth = raw_pkt[scapy.Ether]
            src, dst = eth.src, eth.dst
            proto = f"Ether(0x{eth.type:04x})"

        # ---- Layer 4 -----------------------------------------------------
        if raw_pkt.haslayer(scapy.TCP):
            tcp = raw_pkt[scapy.TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            proto = "TCP"
            flags = str(tcp.flags)
            info = f"flags={flags}"
            metadata.update(tcp_flags=flags, seq=tcp.seq, ack=tcp.ack)
        elif raw_pkt.haslayer(scapy.UDP):
            udp = raw_pkt[scapy.UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            proto = "UDP"
        elif raw_pkt.haslayer(scapy.ICMP):
            icmp = raw_pkt[scapy.ICMP]
            proto = "ICMP"
            info = f"type={icmp.type} code={icmp.code}"
            metadata.update(icmp_type=icmp.type, icmp_code=icmp.code)
        elif raw_pkt.haslayer(scapy.ICMPv6Unknown):
            proto = "ICMPv6"

        # ---- Payload / truncation check ----------------------------------
        raw_frame: Optional[bytes] = None
        try:
            raw_frame = bytes(raw_pkt)
        except Exception:  # pylint: disable=broad-except
            truncated = True

        # Capture layer-7 bytes for protocol parsers
        if raw_pkt.haslayer(scapy.Raw):
            try:
                app_bytes = bytes(raw_pkt[scapy.Raw].load)
            except Exception:  # pylint: disable=broad-except
                app_bytes = None
                truncated = True
        else:
            app_bytes = None

        # Detect obvious truncation (captured less than expected)
        if raw_frame and size > len(raw_frame):
            truncated = True

        packet = Packet(
            ts=ts,
            src=src,
            dst=dst,
            sport=sport,
            dport=dport,
            proto=proto,
            size=size,
            flags=flags,
            ttl=ttl,
            frag=frag,
            truncated=truncated,
            vlan_id=vlan_id,
            ip_version=ip_version,
            raw_payload=app_bytes if self.log_payload else None,
            raw_frame=raw_frame,
            metadata=metadata,
            info=info,
        )

        # Store app bytes for protocol parsers regardless of log_payload setting
        # (parsers need them but we gate storage separately)
        _saved_payload = packet.raw_payload
        if app_bytes is not None:
            packet = Packet(  # re-create to bypass slots restriction
                ts=packet.ts, src=packet.src, dst=packet.dst, sport=packet.sport,
                dport=packet.dport, proto=packet.proto, size=packet.size,
                flags=packet.flags, ttl=packet.ttl, frag=packet.frag,
                truncated=packet.truncated, vlan_id=packet.vlan_id,
                ip_version=packet.ip_version,
                raw_payload=app_bytes,  # temporarily set for parsers
                raw_frame=packet.raw_frame, metadata=packet.metadata, info=packet.info,
            )

        # ---- Protocol parsers --------------------------------------------
        for parser in self.parsers:
            try:
                parser.parse(raw_pkt, packet)
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("Parser %s failed: %s", type(parser).__name__, exc)

        # Enforce payload privacy: clear if not explicitly enabled
        if not self.log_payload:
            object.__setattr__(packet, "raw_payload", None)

        return packet
