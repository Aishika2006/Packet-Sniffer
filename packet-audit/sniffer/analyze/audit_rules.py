"""Audit rules engine.

Seven configurable rules, each a class implementing ``AuditRule``.
Every rule receives a ``Packet`` and returns zero or more ``AuditEvent``
objects. No rule ever stores or logs raw credential values.

Rules:
    1. CleartextProtocolRule  — HTTP, FTP, Telnet, SMTP without TLS
    2. DeprecatedTLSRule      — SSLv3, TLS 1.0, TLS 1.1
    3. AllowlistRule          — traffic to/from hosts/ports outside allowlist
    4. DNSAnomalyRule         — NXDOMAIN rate, long names, high entropy
    5. PortScanRule           — one src touching many dst ports in a window
    6. VolumeAnomalyRule      — bytes-per-minute threshold per host
    7. CleartextCredentialRule— credential-keyword detection (flag only, no values stored)
"""

from __future__ import annotations

import ipaddress
import logging
import math
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from typing import Any, Protocol, runtime_checkable

from sniffer.audit.events import AuditEvent
from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)


@runtime_checkable
class AuditRule(Protocol):
    """Interface all audit rules must satisfy."""

    name: str
    severity: str
    enabled: bool

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        """Return any audit events triggered by *packet*."""
        ...


# ---------------------------------------------------------------------------
# Rule 1 — Cleartext Protocols
# ---------------------------------------------------------------------------

_CLEARTEXT_PROTO_PORTS: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 23: "Telnet",
    25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
}


class CleartextProtocolRule:
    """Flag traffic on well-known cleartext protocol ports."""

    name = "cleartext_protocols"
    severity = "HIGH"

    def __init__(self, enabled: bool = True, ports: list[int] | None = None) -> None:
        self.enabled = enabled
        self._ports: dict[int, str] = (
            {p: _CLEARTEXT_PROTO_PORTS.get(p, f"PORT_{p}") for p in ports}
            if ports
            else _CLEARTEXT_PROTO_PORTS
        )

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled:
            return []
        dport = packet.dport or 0
        sport = packet.sport or 0
        matched_port = self._ports.get(dport) or self._ports.get(sport)
        if not matched_port:
            return []
        # Don't double-flag what the TLS parser already identified as encrypted
        if "tls" in packet.metadata:
            return []
        port_num = dport if dport in self._ports else sport
        return [AuditEvent(
            rule=self.name,
            severity=self.severity,
            src=packet.src,
            dst=packet.dst,
            sport=packet.sport,
            dport=packet.dport,
            proto=packet.proto,
            message=f"Cleartext protocol {matched_port} (port {port_num}) detected",
            evidence={"protocol_name": matched_port, "port": port_num},
        )]


# ---------------------------------------------------------------------------
# Rule 2 — Deprecated TLS
# ---------------------------------------------------------------------------

_DEPRECATED_TLS: frozenset[str] = frozenset({"SSL 3.0", "TLS 1.0", "TLS 1.1"})


class DeprecatedTLSRule:
    """Flag connections using deprecated TLS/SSL versions."""

    name = "deprecated_tls"
    severity = "HIGH"

    def __init__(self, enabled: bool = True, flagged_versions: list[str] | None = None) -> None:
        self.enabled = enabled
        self._versions = frozenset(flagged_versions) if flagged_versions else _DEPRECATED_TLS

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled:
            return []
        tls = packet.metadata.get("tls")
        if not tls:
            return []
        version = tls.get("version", "")
        if version not in self._versions:
            return []
        return [AuditEvent(
            rule=self.name,
            severity=self.severity,
            src=packet.src,
            dst=packet.dst,
            sport=packet.sport,
            dport=packet.dport,
            proto=packet.proto,
            message=f"Deprecated TLS version {version} detected",
            evidence={"tls_version": version, "sni": tls.get("sni")},
        )]


# ---------------------------------------------------------------------------
# Rule 3 — Allowlist
# ---------------------------------------------------------------------------

def _parse_network(spec: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return None


def _ip_in_networks(ip_str: str, nets: list[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in nets if net is not None)
    except ValueError:
        return False


class AllowlistRule:
    """Flag traffic from/to IPs or ports outside the configured allowlist."""

    name = "allowlist"
    severity = "MEDIUM"

    def __init__(
        self,
        enabled: bool = False,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> None:
        self.enabled = enabled
        self._host_nets = [_parse_network(h) for h in (allowed_hosts or [])]
        self._allowed_ports: frozenset[int] = (
            frozenset(allowed_ports) if allowed_ports else frozenset()
        )

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled:
            return []

        events: list[AuditEvent] = []

        # Host check
        if self._host_nets:
            src_ok = _ip_in_networks(packet.src, self._host_nets)
            dst_ok = _ip_in_networks(packet.dst, self._host_nets)
            if not src_ok:
                events.append(AuditEvent(
                    rule=self.name, severity=self.severity,
                    src=packet.src, dst=packet.dst,
                    sport=packet.sport, dport=packet.dport,
                    proto=packet.proto,
                    message=f"Source IP {packet.src} is not in the host allowlist",
                    evidence={"direction": "src"},
                ))
            if not dst_ok:
                events.append(AuditEvent(
                    rule=self.name, severity=self.severity,
                    src=packet.src, dst=packet.dst,
                    sport=packet.sport, dport=packet.dport,
                    proto=packet.proto,
                    message=f"Destination IP {packet.dst} is not in the host allowlist",
                    evidence={"direction": "dst"},
                ))

        # Port check (destination port per specification)
        if self._allowed_ports and packet.dport is not None:
            if packet.dport not in self._allowed_ports:
                events.append(AuditEvent(
                    rule=self.name, severity=self.severity,
                    src=packet.src, dst=packet.dst,
                    sport=packet.sport, dport=packet.dport,
                    proto=packet.proto,
                    message=f"Port {packet.dport} is not in the port allowlist",
                    evidence={"port": packet.dport},
                ))

        return events


# ---------------------------------------------------------------------------
# Rule 4 — DNS Anomalies
# ---------------------------------------------------------------------------

def _shannon_entropy(name: str) -> float:
    if not name:
        return 0.0
    freq: dict[str, int] = {}
    for ch in name:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(name)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class DNSAnomalyRule:
    """Detect NXDOMAIN flood, oversized queries, and high-entropy hostnames."""

    name = "dns_anomaly"
    severity = "MEDIUM"

    def __init__(
        self,
        enabled: bool = True,
        nxdomain_rate_threshold: int = 10,
        long_name_threshold: int = 50,
        high_entropy_threshold: float = 4.0,
    ) -> None:
        self.enabled = enabled
        self._nx_threshold = nxdomain_rate_threshold
        self._name_threshold = long_name_threshold
        self._entropy_threshold = high_entropy_threshold
        self._lock = threading.Lock()
        # src -> deque of NXDOMAIN timestamps in current minute
        self._nxdomain_ts: dict[str, deque[float]] = defaultdict(deque)

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled:
            return []
        dns = packet.metadata.get("dns")
        if not dns:
            return []

        events: list[AuditEvent] = []
        qname: str = dns.get("qname", "")
        rcode: str = dns.get("rcode", "")
        entropy: float = dns.get("entropy", 0.0)
        now = time.time()

        # NXDOMAIN rate
        if rcode == "NXDOMAIN":
            with self._lock:
                window = self._nxdomain_ts[packet.src]
                window.append(now)
                cutoff = now - 60.0
                while window and window[0] < cutoff:
                    window.popleft()
                count = len(window)
            if count >= self._nx_threshold:
                events.append(AuditEvent(
                    rule=self.name, severity=self.severity,
                    src=packet.src, dst=packet.dst,
                    sport=packet.sport, dport=packet.dport,
                    proto=packet.proto,
                    message=(
                        f"High NXDOMAIN rate from {packet.src}: "
                        f"{count} in last 60 s (threshold {self._nx_threshold})"
                    ),
                    evidence={"nxdomain_count_60s": count, "threshold": self._nx_threshold},
                ))

        # Long query name
        if qname and len(qname) >= self._name_threshold:
            events.append(AuditEvent(
                rule=self.name, severity=self.severity,
                src=packet.src, dst=packet.dst,
                sport=packet.sport, dport=packet.dport,
                proto=packet.proto,
                message=f"Unusually long DNS query name ({len(qname)} chars)",
                evidence={"qname_length": len(qname), "threshold": self._name_threshold},
            ))

        # High entropy (potential DGA / DNS tunnel)
        if qname and entropy >= self._entropy_threshold:
            events.append(AuditEvent(
                rule=self.name, severity=self.severity,
                src=packet.src, dst=packet.dst,
                sport=packet.sport, dport=packet.dport,
                proto=packet.proto,
                message=(
                    f"High-entropy DNS query ({entropy:.2f} bits/char) — "
                    "possible DGA or DNS tunnelling"
                ),
                evidence={"entropy": entropy, "threshold": self._entropy_threshold},
            ))

        return events


# ---------------------------------------------------------------------------
# Rule 5 — Port Scan
# ---------------------------------------------------------------------------

class PortScanRule:
    """Flag a source touching many distinct destination ports in a short window."""

    name = "port_scan"
    severity = "HIGH"

    def __init__(
        self,
        enabled: bool = True,
        distinct_ports_threshold: int = 15,
        window_seconds: float = 10.0,
    ) -> None:
        self.enabled = enabled
        self._threshold = distinct_ports_threshold
        self._window = window_seconds
        self._lock = threading.Lock()
        # src -> deque of (timestamp, dst_port) tuples
        self._hits: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        # src -> set of reported ports to avoid duplicate firing
        self._reported: dict[str, int] = {}

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled or packet.dport is None:
            return []

        now = time.time()
        src = packet.src

        with self._lock:
            window_deque = self._hits[src]
            window_deque.append((now, packet.dport))
            cutoff = now - self._window
            while window_deque and window_deque[0][0] < cutoff:
                window_deque.popleft()

            distinct_ports = {p for _, p in window_deque}
            count = len(distinct_ports)
            last_reported = self._reported.get(src, 0)

        if count >= self._threshold and count != last_reported:
            with self._lock:
                self._reported[src] = count
            return [AuditEvent(
                rule=self.name,
                severity=self.severity,
                src=src,
                dst=packet.dst,
                sport=packet.sport,
                dport=packet.dport,
                proto=packet.proto,
                message=(
                    f"Port-scan behaviour from {src}: "
                    f"{count} distinct ports in {self._window:.0f} s"
                ),
                evidence={
                    "distinct_ports": count,
                    "threshold": self._threshold,
                    "window_seconds": self._window,
                },
            )]
        return []


# ---------------------------------------------------------------------------
# Rule 6 — Volume Anomaly
# ---------------------------------------------------------------------------

class VolumeAnomalyRule:
    """Flag hosts transmitting above the bytes-per-minute threshold."""

    name = "volume_anomaly"
    severity = "MEDIUM"

    def __init__(
        self,
        enabled: bool = True,
        bytes_per_minute_threshold: int = 10_485_760,
    ) -> None:
        self.enabled = enabled
        self._threshold = bytes_per_minute_threshold
        self._lock = threading.Lock()
        # src -> deque of (timestamp, bytes) pairs
        self._bytes: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled:
            return []

        now = time.time()
        src = packet.src

        with self._lock:
            q = self._bytes[src]
            q.append((now, packet.size))
            cutoff = now - 60.0
            while q and q[0][0] < cutoff:
                q.popleft()
            total_bytes = sum(b for _, b in q)
            last_alert = self._last_alerted.get(src, 0.0)

        if total_bytes >= self._threshold and (now - last_alert) >= 60.0:
            with self._lock:
                self._last_alerted[src] = now
            return [AuditEvent(
                rule=self.name,
                severity=self.severity,
                src=src,
                dst=packet.dst,
                sport=packet.sport,
                dport=packet.dport,
                proto=packet.proto,
                message=(
                    f"Volume anomaly from {src}: "
                    f"{total_bytes:,} bytes/min "
                    f"(threshold {self._threshold:,})"
                ),
                evidence={
                    "bytes_per_minute": total_bytes,
                    "threshold": self._threshold,
                },
            )]
        return []


# ---------------------------------------------------------------------------
# Rule 7 — Cleartext Credentials
# ---------------------------------------------------------------------------

import re as _re

_CRED_PATTERNS: list[tuple[str, _re.Pattern[str]]] = [
    ("Authorization header", _re.compile(r"^authorization:", _re.IGNORECASE | _re.MULTILINE)),
    ("Cookie header", _re.compile(r"^cookie:", _re.IGNORECASE | _re.MULTILINE)),
    ("Password field", _re.compile(r"(password|passwd)=", _re.IGNORECASE)),
    ("Token field", _re.compile(r"\btoken=", _re.IGNORECASE)),
    ("API key field", _re.compile(r"api[_-]?key=", _re.IGNORECASE)),
]


class CleartextCredentialRule:
    """Detect credential-like patterns in plaintext traffic.

    PRIVACY: only the *presence* and *host/port* are logged.
    The actual credential value is NEVER stored or logged.
    """

    name = "cleartext_credentials"
    severity = "CRITICAL"

    def __init__(self, enabled: bool = True, patterns: list[str] | None = None) -> None:
        self.enabled = enabled
        # Build custom patterns if provided; fall back to defaults
        if patterns:
            self._patterns = [
                (p, _re.compile(_re.escape(p), _re.IGNORECASE))
                for p in patterns
            ]
        else:
            self._patterns = _CRED_PATTERNS

    def analyze(self, packet: Packet) -> list[AuditEvent]:
        if not self.enabled:
            return []
        # Only relevant for cleartext (non-TLS) TCP traffic
        if "tls" in packet.metadata:
            return []
        if packet.proto not in {"HTTP", "TCP", "UDP"}:
            return []

        # Check metadata — HTTP parser already redacts values
        http = packet.metadata.get("http", {})
        has_cred = http.get("has_credentials", False)

        # Also scan raw_payload bytes if available (log_payload mode)
        raw = packet.raw_payload
        cred_kinds: list[str] = []

        if has_cred:
            cred_kinds.append("HTTP credential field detected in request")

        if raw:
            try:
                text = raw.decode("iso-8859-1", errors="replace")
                for kind, pat in self._patterns:
                    if pat.search(text):
                        cred_kinds.append(kind)
            except Exception:  # pylint: disable=broad-except
                pass

        if not cred_kinds:
            return []

        return [AuditEvent(
            rule=self.name,
            severity=self.severity,
            src=packet.src,
            dst=packet.dst,
            sport=packet.sport,
            dport=packet.dport,
            proto=packet.proto,
            message=(
                f"Cleartext credential indicator on {packet.src} -> {packet.dst}: "
                + "; ".join(dict.fromkeys(cred_kinds))
            ),
            # Evidence records the fact only — never the credential value
            evidence={"indicators": list(dict.fromkeys(cred_kinds))},
        )]


# ---------------------------------------------------------------------------
# Rule registry / factory
# ---------------------------------------------------------------------------

def build_rules(cfg: dict) -> list[Any]:
    """Instantiate all audit rules from config dict.

    Args:
        cfg: The ``audit.rules`` section of the parsed config.

    Returns:
        List of rule instances in evaluation order.
    """
    r = cfg or {}

    def _get(section: str, key: str, default: Any) -> Any:
        return r.get(section, {}).get(key, default)

    rules: list[Any] = [
        CleartextProtocolRule(
            enabled=_get("cleartext_protocols", "enabled", True),
            ports=_get("cleartext_protocols", "ports", None),
        ),
        DeprecatedTLSRule(
            enabled=_get("deprecated_tls", "enabled", True),
            flagged_versions=_get("deprecated_tls", "flagged_versions", None),
        ),
        AllowlistRule(
            enabled=_get("allowlist", "enabled", False),
            allowed_hosts=_get("allowlist", "allowed_hosts", []),
            allowed_ports=_get("allowlist", "allowed_ports", []),
        ),
        DNSAnomalyRule(
            enabled=_get("dns_anomaly", "enabled", True),
            nxdomain_rate_threshold=_get("dns_anomaly", "nxdomain_rate_threshold", 10),
            long_name_threshold=_get("dns_anomaly", "long_name_threshold", 50),
            high_entropy_threshold=_get("dns_anomaly", "high_entropy_threshold", 4.0),
        ),
        PortScanRule(
            enabled=_get("port_scan", "enabled", True),
            distinct_ports_threshold=_get("port_scan", "distinct_ports_threshold", 15),
            window_seconds=_get("port_scan", "window_seconds", 10.0),
        ),
        VolumeAnomalyRule(
            enabled=_get("volume_anomaly", "enabled", True),
            bytes_per_minute_threshold=_get("volume_anomaly", "bytes_per_minute_threshold", 10_485_760),
        ),
        CleartextCredentialRule(
            enabled=_get("cleartext_credentials", "enabled", True),
            patterns=_get("cleartext_credentials", "patterns", None),
        ),
    ]
    return rules
