"""DNS protocol parser — decodes queries and responses, no raw data stored."""

from __future__ import annotations

import logging
import math
from typing import Any

import scapy.all as scapy

from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)

DNS_QTYPES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

DNS_RCODES: dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


def _shannon_entropy(name: str) -> float:
    """Compute Shannon entropy (bits/char) of *name*."""
    if not name:
        return 0.0
    freq: dict[str, int] = {}
    for ch in name:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(name)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class DNSParser:
    """Enriches a Packet with DNS metadata. Never stores query payloads."""

    def parse(self, raw_pkt: Any, packet: Packet) -> None:  # noqa: D102
        if not raw_pkt.haslayer(scapy.DNS):
            return
        try:
            dns = raw_pkt[scapy.DNS]
            is_response = bool(dns.qr == 1)
            tx_id = int(dns.id)
            rcode = int(getattr(dns, "rcode", 0))
            rcode_name = DNS_RCODES.get(rcode, f"RCODE_{rcode}")

            qname = ""
            qtype_name = ""
            if raw_pkt.haslayer(scapy.DNSQR):
                qr = raw_pkt[scapy.DNSQR]
                raw_qname: bytes | str = qr.qname
                qname = (
                    raw_qname.decode(errors="replace") if isinstance(raw_qname, bytes) else str(raw_qname)
                ).rstrip(".")
                qtype_name = DNS_QTYPES.get(int(getattr(qr, "qtype", 1)), "UNKNOWN")

            answers: list[str] = []
            if is_response and dns.an:
                records = dns.an if hasattr(dns.an, "__iter__") else [dns.an]
                for rr in records:
                    if not (hasattr(rr, "type") and hasattr(rr, "rdata")):
                        continue
                    r_type = DNS_QTYPES.get(int(rr.type), f"TYPE_{rr.type}")
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode(errors="replace").rstrip(".")
                    answers.append(f"{r_type}:{rdata}")

            entropy = _shannon_entropy(qname)

            packet.proto = "DNS"
            if is_response:
                packet.info = f"Resp {qname or '?'} [{rcode_name}]" + (
                    f" -> {answers[0]}" if answers else ""
                )
            else:
                packet.info = f"Query {qtype_name} {qname}" if qname else "DNS Query"

            packet.metadata["dns"] = {
                "tx_id": hex(tx_id),
                "type": "response" if is_response else "query",
                "qname": qname,
                "qtype": qtype_name,
                "rcode": rcode_name,
                "answers": answers,
                "entropy": round(entropy, 3),
            }
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("DNS parse error: %s", exc)
