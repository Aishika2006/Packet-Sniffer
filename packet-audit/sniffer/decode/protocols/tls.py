"""TLS metadata parser — extracts SNI and version from handshake records.

PRIVACY: Only structural metadata is recorded. Encrypted payload bytes are
never read, stored, or decoded. No decryption is attempted.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)

_TLS_CONTENT_TYPES: dict[int, str] = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "Heartbeat",
}

_TLS_VERSIONS: dict[tuple[int, int], str] = {
    (0x03, 0x00): "SSL 3.0",
    (0x03, 0x01): "TLS 1.0",
    (0x03, 0x02): "TLS 1.1",
    (0x03, 0x03): "TLS 1.2",
    (0x03, 0x04): "TLS 1.3",
}


def _extract_sni(payload: bytes) -> Optional[str]:
    """Parse Server Name Indication from a TLS Client Hello record."""
    try:
        pos = 5  # skip TLS record header (1+2+2)
        if pos >= len(payload) or payload[pos] != 0x01:
            return None
        pos += 4  # handshake type (1) + length (3)
        pos += 2  # client_version
        pos += 32  # random
        if pos >= len(payload):
            return None
        sess_len = payload[pos]
        pos += 1 + sess_len
        if pos + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[pos: pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[pos: pos + 2], "big")
        pos += 2
        end_ext = pos + ext_total
        while pos + 4 <= end_ext and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos: pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2: pos + 4], "big")
            pos += 4
            if ext_type == 0 and pos + 5 <= len(payload):
                name_len = int.from_bytes(payload[pos + 3: pos + 5], "big")
                return payload[pos + 5: pos + 5 + name_len].decode("utf-8", errors="replace")
            pos += ext_len
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("SNI extraction error: %s", exc)
    return None


class TLSParser:
    """Enriches Packet with TLS/HTTPS structural metadata."""

    def parse(self, raw_pkt: Any, packet: Packet) -> None:  # noqa: D102
        payload = packet.raw_payload
        if not payload or len(payload) < 5:
            return
        if payload[0] not in _TLS_CONTENT_TYPES or payload[1] != 0x03:
            return
        try:
            ct_name = _TLS_CONTENT_TYPES.get(payload[0], f"Type_{payload[0]}")
            ver_tuple = (payload[1], payload[2])
            version_name = _TLS_VERSIONS.get(ver_tuple, f"{payload[1]}.{payload[2]}")
            record_len = int.from_bytes(payload[3:5], "big")
            sni: Optional[str] = None
            if payload[0] == 0x16 and len(payload) > 5 and payload[5] == 0x01:
                sni = _extract_sni(payload)

            packet.proto = "HTTPS"
            if sni:
                packet.info = f"TLS Client Hello [SNI: {sni}]"
            elif payload[0] == 0x16:
                packet.info = f"TLS Handshake ({version_name})"
            elif payload[0] == 0x17:
                packet.info = f"TLS AppData (encrypted, {record_len} bytes)"
            else:
                packet.info = f"TLS {ct_name} ({version_name})"

            packet.metadata["tls"] = {
                "encrypted": True,
                "record_type": ct_name,
                "version": version_name,
                "record_length": record_len,
                "sni": sni,
            }
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("TLS parse error: %s", exc)
            packet.proto = "HTTPS"
            packet.info = "Encrypted TLS"
            packet.metadata["tls"] = {"encrypted": True}
