"""AuditEvent dataclass — the canonical record for each rule finding."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class AuditEvent:
    """A single audit rule finding.

    Attributes:
        id:        UUID4 string, unique per event.
        ts:        ISO-8601 UTC timestamp string.
        rule:      Rule identifier e.g. "cleartext_protocols".
        severity:  "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO".
        src:       Source IP (always recorded).
        dst:       Destination IP (always recorded).
        sport:     Source port or None.
        dport:     Destination port or None.
        proto:     Protocol label.
        evidence:  Dict of supporting facts; must never contain raw credentials.
        message:   Human-readable summary.
    """

    rule: str
    severity: str
    src: str
    dst: str
    proto: str
    message: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )
    sport: int | None = None
    dport: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialisable representation (no raw bytes)."""
        return {
            "id": self.id,
            "ts": self.ts,
            "rule": self.rule,
            "severity": self.severity,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "proto": self.proto,
            "message": self.message,
            "evidence": self.evidence,
        }
