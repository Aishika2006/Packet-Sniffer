"""DNS protocol decoder for parsing DNS queries and responses."""

import logging
from typing import Any, List, Optional
import scapy.all as scapy
from sniffer.decode.packet import Packet

logger = logging.getLogger(__name__)

# Standard DNS Query / Resource Record types
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

# Standard DNS response codes
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DNSParser:
    """Protocol parser for decoding DNS traffic."""

    def parse(self, raw_pkt: Any, packet: Packet) -> None:
        """
        Inspect raw packet for DNS layer and enrich the Packet instance.

        Args:
            raw_pkt: Raw Scapy packet.
            packet: Target Packet dataclass to enrich.
        """
        if not raw_pkt.haslayer(scapy.DNS):
            return

        try:
            dns_layer = raw_pkt[scapy.DNS]
            packet.proto = "DNS"

            is_response = bool(dns_layer.qr == 1)
            tx_id = int(dns_layer.id)
            rcode = int(getattr(dns_layer, "rcode", 0))
            rcode_name = DNS_RCODES.get(rcode, f"RCODE_{rcode}")

            qname = ""
            qtype_name = ""
            if raw_pkt.haslayer(scapy.DNSQR):
                dnsqr = raw_pkt[scapy.DNSQR]
                raw_qname = dnsqr.qname
                if isinstance(raw_qname, bytes):
                    qname = raw_qname.decode(errors="replace").rstrip(".")
                else:
                    qname = str(raw_qname).rstrip(".")
                qtype = int(getattr(dnsqr, "qtype", 1))
                qtype_name = DNS_TYPES.get(qtype, f"TYPE_{qtype}")

            answers: List[str] = []
            if is_response and dns_layer.an:
                # dns_layer.an can be an iterable list of DNSRR or a chained Scapy layer
                records = dns_layer.an if hasattr(dns_layer.an, "__iter__") else [dns_layer.an]
                for curr in records:
                    if hasattr(curr, "type") and hasattr(curr, "rdata"):
                        r_type = int(curr.type)
                        r_type_name = DNS_TYPES.get(r_type, f"TYPE_{r_type}")
                        r_data = curr.rdata
                        if isinstance(r_data, bytes):
                            r_data = r_data.decode(errors="replace").rstrip(".")
                        answers.append(f"{r_type_name}: {r_data}")

            # Build human-readable info string
            if is_response:
                if answers:
                    packet.info = f"Resp {qname} -> {', '.join(answers[:3])}"
                    if len(answers) > 3:
                        packet.info += f" (+{len(answers)-3} more)"
                else:
                    packet.info = f"Resp {qname} [{rcode_name}]"
            else:
                packet.info = f"Query {qtype_name} {qname}" if qname else "DNS Query"

            # Attach structured metadata
            packet.metadata["dns"] = {
                "transaction_id": hex(tx_id),
                "type": "response" if is_response else "query",
                "qname": qname,
                "qtype": qtype_name,
                "rcode": rcode_name,
                "answers": answers,
            }

        except Exception as e:
            logger.debug("Failed to parse DNS packet: %s", e)
