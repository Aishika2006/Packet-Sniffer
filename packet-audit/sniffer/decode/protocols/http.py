"""HTTP parser — request/response lines and headers for cleartext traffic.

PRIVACY: Authorization, Cookie, and password-like header values are
redacted to '<REDACTED>' before being stored in metadata.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import scapy.all as scapy

from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)

HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
)

# Headers whose *values* must always be redacted
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {"authorization", "cookie", "set-cookie", "proxy-authorization"}
)

# Patterns indicating credential fields in query-strings or form bodies
_CREDENTIAL_RE = re.compile(
    r"(password|passwd|token|api[_-]?key|secret)[=:]\S+",
    re.IGNORECASE,
)


def _redact_value(value: str) -> str:
    """Return '<REDACTED>' unconditionally."""
    return "<REDACTED>"


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key_lower = key.strip().lower()
        val_stripped = val.strip()
        headers[key_lower] = (
            _redact_value(val_stripped)
            if key_lower in SENSITIVE_HEADERS
            else val_stripped
        )
    return headers


class HTTPParser:
    """Enriches Packet with HTTP request/response metadata."""

    def parse(self, raw_pkt: Any, packet: Packet) -> None:  # noqa: D102
        if packet.proto not in {"TCP"} and not raw_pkt.haslayer(scapy.TCP):
            return
        payload = packet.raw_payload
        if not payload:
            return

        # Skip TLS-looking traffic — handled by TLSParser
        if len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17, 0x18) and payload[1] == 0x03:
            return

        dport = packet.dport or 0
        sport = packet.sport or 0
        if not (
            dport in (80, 8080, 8000, 8008, 8888)
            or sport in (80, 8080, 8000, 8008, 8888)
            or payload[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"OPTI", b"PATC", b"HTTP")
        ):
            return

        try:
            sep = payload.find(b"\r\n\r\n")
            header_bytes = payload[:sep] if sep != -1 else payload[:2048]
            text = header_bytes.decode("iso-8859-1", errors="replace")
            lines = text.splitlines()
            if not lines:
                return

            first = lines[0].strip()
            parts = first.split(" ", 2)
            headers = _parse_headers(lines[1:])

            has_credentials = bool(_CREDENTIAL_RE.search(text))

            if len(parts) >= 2 and parts[0].upper() in HTTP_METHODS:
                packet.proto = "HTTP"
                method, path = parts[0].upper(), parts[1]
                host = headers.get("host", "")
                packet.info = f"{method} {path}" + (f" [Host: {host}]" if host else "")
                packet.metadata["http"] = {
                    "type": "request",
                    "method": method,
                    "path": path,
                    "version": parts[2] if len(parts) > 2 else "HTTP/1.1",
                    "host": host,
                    "headers": headers,
                    "has_credentials": has_credentials,
                }
            elif len(parts) >= 2 and parts[0].startswith("HTTP/"):
                packet.proto = "HTTP"
                status = parts[1]
                reason = parts[2] if len(parts) > 2 else ""
                packet.info = f"HTTP {status} {reason}".strip()
                packet.metadata["http"] = {
                    "type": "response",
                    "version": parts[0],
                    "status_code": status,
                    "reason": reason,
                    "headers": headers,
                    "has_credentials": has_credentials,
                }

        except Exception as exc:  # pylint: disable=broad-except
            log.debug("HTTP parse error: %s", exc)
