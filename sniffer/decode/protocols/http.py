"""HTTP and TLS protocol parser.

Parses request lines, status lines, and headers for unencrypted HTTP traffic.
Extracts metadata only (TLS record types, versions, SNI) for encrypted traffic.
"""

import logging
import re
from typing import Any, Dict, Optional, Tuple

import scapy.all as scapy
from sniffer.decode.packet import Packet

logger = logging.getLogger(__name__)

# Standard HTTP methods
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

# TLS Content Types
TLS_CONTENT_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "Heartbeat",
}

# TLS Versions
TLS_VERSIONS = {
    (0x03, 0x00): "SSL 3.0",
    (0x03, 0x01): "TLS 1.0",
    (0x03, 0x02): "TLS 1.1",
    (0x03, 0x03): "TLS 1.2",
    (0x03, 0x04): "TLS 1.3",
}


class HTTPParser:
    """Protocol parser for unencrypted HTTP and encrypted HTTPS/TLS metadata."""

    def parse(self, raw_pkt: Any, packet: Packet) -> None:
        """
        Inspect packet payload for HTTP requests/responses or TLS metadata.

        Args:
            raw_pkt: Raw Scapy packet.
            packet: Target Packet dataclass to enrich.
        """
        # Only inspect packets with TCP layer and a raw payload
        if packet.proto != "TCP" and not raw_pkt.haslayer(scapy.TCP):
            return

        payload = packet.raw_payload
        if not payload:
            return

        sport = packet.sport or 0
        dport = packet.dport or 0

        # 1. Check for Encrypted TLS/HTTPS Traffic
        if sport == 443 or dport == 443 or self._looks_like_tls(payload):
            self._parse_tls_metadata(payload, packet)
            return

        # 2. Check for Unencrypted HTTP Traffic
        if sport in (80, 8080, 8000, 8888) or dport in (80, 8080, 8000, 8888) or self._looks_like_http(payload):
            self._parse_http(payload, packet)

    def _looks_like_tls(self, payload: bytes) -> bool:
        """Check if payload begins with standard TLS record header."""
        if len(payload) >= 5:
            # First byte is ContentType (0x14 - 0x18), followed by version 0x03, 0x00-0x04
            return payload[0] in TLS_CONTENT_TYPES and payload[1] == 0x03
        return False

    def _looks_like_http(self, payload: bytes) -> bool:
        """Check if payload begins with an HTTP method or HTTP response banner."""
        if len(payload) < 4:
            return False
        first_word = payload[:10].split(b" ")[0].decode("ascii", errors="ignore")
        return first_word.upper() in HTTP_METHODS or payload.startswith(b"HTTP/")

    def _parse_http(self, payload: bytes, packet: Packet) -> None:
        """Parse unencrypted HTTP request or response lines and headers."""
        try:
            # Decode header segment up to double CRLF
            header_end = payload.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = payload.find(b"\n\n")
            
            raw_headers = payload[:header_end] if header_end != -1 else payload[:1024]
            text = raw_headers.decode("iso-8859-1", errors="replace")
            lines = text.splitlines()

            if not lines:
                return

            first_line = lines[0].strip()
            parts = first_line.split(" ", 2)

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

            packet.proto = "HTTP"

            # Check if Request: METHOD PATH VERSION
            if len(parts) >= 2 and parts[0].upper() in HTTP_METHODS:
                method = parts[0].upper()
                path = parts[1]
                version = parts[2] if len(parts) > 2 else "HTTP/1.1"
                host = headers.get("host", "")

                info = f"{method} {path}"
                if host:
                    info += f" [Host: {host}]"
                packet.info = info

                packet.metadata["http"] = {
                    "type": "request",
                    "method": method,
                    "path": path,
                    "version": version,
                    "host": host,
                    "headers": headers,
                }

            # Check if Response: VERSION STATUS REASON
            elif len(parts) >= 2 and parts[0].startswith("HTTP/"):
                version = parts[0]
                status_code = parts[1]
                reason = parts[2] if len(parts) > 2 else ""

                packet.info = f"HTTP {status_code} {reason}".strip()

                packet.metadata["http"] = {
                    "type": "response",
                    "version": version,
                    "status_code": status_code,
                    "reason": reason,
                    "headers": headers,
                }

        except Exception as e:
            logger.debug("Failed to parse HTTP payload: %s", e)

    def _parse_tls_metadata(self, payload: bytes, packet: Packet) -> None:
        """
        Extract non-sensitive structural metadata from encrypted TLS traffic.
        Does not attempt decryption.
        """
        try:
            content_type = payload[0]
            ct_name = TLS_CONTENT_TYPES.get(content_type, f"Type_{content_type}")
            version_tuple = (payload[1], payload[2])
            version_name = TLS_VERSIONS.get(version_tuple, f"{payload[1]}.{payload[2]}")
            record_len = int.from_bytes(payload[3:5], "big")

            packet.proto = "HTTPS"
            sni = None

            # If Handshake Client Hello, try to extract SNI (Server Name Indication)
            if content_type == 0x16 and len(payload) > 5 and payload[5] == 0x01:
                sni = self._extract_sni(payload)

            if sni:
                packet.info = f"TLS Client Hello [SNI: {sni}]"
            elif content_type == 0x16:
                packet.info = f"TLS Handshake ({version_name})"
            elif content_type == 0x17:
                packet.info = f"TLS Application Data (encrypted, len={record_len})"
            else:
                packet.info = f"TLS {ct_name} ({version_name})"

            packet.metadata["tls"] = {
                "encrypted": True,
                "record_type": ct_name,
                "version": version_name,
                "record_length": record_len,
                "sni": sni,
            }

        except Exception as e:
            logger.debug("Failed to extract TLS metadata: %s", e)
            packet.proto = "HTTPS"
            packet.info = f"Encrypted TLS traffic (len={len(payload)})"
            packet.metadata["tls"] = {"encrypted": True}

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Parse Server Name Indication (SNI) extension from TLS Client Hello bytes."""
        try:
            pos = 5
            if pos >= len(payload) or payload[pos] != 0x01:
                return None
            pos += 4  # Skip Handshake type (1) + length (3)
            pos += 2  # Skip client_version (2)
            pos += 32  # Skip random (32)

            if pos >= len(payload):
                return None
            sess_len = payload[pos]
            pos += 1 + sess_len

            if pos + 2 > len(payload):
                return None
            cipher_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + cipher_len

            if pos >= len(payload):
                return None
            comp_len = payload[pos]
            pos += 1 + comp_len

            if pos + 2 > len(payload):
                return None
            ext_total_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            end_ext = pos + ext_total_len

            # Walk extensions
            while pos + 4 <= end_ext and pos + 4 <= len(payload):
                ext_type = int.from_bytes(payload[pos:pos+2], "big")
                ext_len = int.from_bytes(payload[pos+2:pos+4], "big")
                pos += 4
                if ext_type == 0:  # server_name extension
                    # server_name_list length (2) + name_type (1) + name_length (2)
                    if pos + 5 <= len(payload):
                        name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                        return payload[pos+5:pos+5+name_len].decode("utf-8", errors="replace")
                pos += ext_len

        except Exception:
            return None
        return None
