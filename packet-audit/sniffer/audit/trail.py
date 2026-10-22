"""Append-only audit trail with SHA-256 hash chain.

Each JSONL line is a JSON object::

    {
        "seq":        <int>,
        "type":       "event" | "meta",
        "prev_hash":  "<hex SHA-256 of previous line>",
        "payload":    { ... }
    }

The first entry has ``prev_hash`` = "0" * 64 (genesis).

Tamper detection
----------------
Use ``AuditTrail.verify()`` or the CLI ``verify`` sub-command to replay the
chain. A missing, reordered, or edited entry breaks the chain and is reported.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64


class AuditTrail:
    """Append-only JSONL audit trail backed by a SHA-256 hash chain.

    Args:
        path:    File path for the JSONL trail (created/appended on open).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = _GENESIS_HASH

        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Resume from existing trail if present
        if self._path.is_file():
            self._resume()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, record_type: str, payload: dict[str, Any]) -> None:
        """Append a record to the trail and advance the hash chain.

        Args:
            record_type: "event" or "meta".
            payload:     Serialisable dict (must not contain raw bytes).
        """
        with self._lock:
            entry: dict[str, Any] = {
                "seq": self._seq,
                "type": record_type,
                "prev_hash": self._prev_hash,
                "payload": payload,
            }
            line = json.dumps(entry, ensure_ascii=False, default=str)
            self._prev_hash = hashlib.sha256(line.encode()).hexdigest()
            self._seq += 1

            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def close(self) -> None:
        """No persistent handle to close; kept for interface parity."""

    @property
    def path(self) -> Path:
        """Trail file path."""
        return self._path

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, list[str]]:
        """Verify the hash chain in *path*.

        Returns:
            ``(ok, errors)`` — *ok* is True if the chain is intact.
            *errors* is a list of human-readable problem descriptions.
        """
        trail_path = Path(path)
        if not trail_path.is_file():
            return False, [f"Trail file not found: {trail_path}"]

        errors: list[str] = []
        prev_hash = _GENESIS_HASH
        expected_seq = 0

        with trail_path.open("r", encoding="utf-8") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                raw_line = raw_line.rstrip("\n")
                if not raw_line.strip():
                    continue
                try:
                    entry = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    errors.append(f"Line {lineno}: JSON parse error — {exc}")
                    # Cannot continue chain verification after malformed line
                    break

                seq = entry.get("seq")
                claimed_prev = entry.get("prev_hash", "")

                if seq != expected_seq:
                    errors.append(f"Line {lineno}: seq={seq}, expected {expected_seq} (gap or reorder)")

                if claimed_prev != prev_hash:
                    errors.append(
                        f"Line {lineno} (seq={seq}): prev_hash mismatch — "
                        f"expected {prev_hash[:16]}... got {claimed_prev[:16]}..."
                    )

                # Re-hash this line to build the expected prev_hash for the next entry
                prev_hash = hashlib.sha256(raw_line.encode()).hexdigest()
                expected_seq = (seq or 0) + 1

        return (len(errors) == 0), errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resume(self) -> None:
        """Re-read the existing trail to restore seq and prev_hash state."""
        last_line: str | None = None
        last_seq: int = -1

        with self._path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                raw_line = raw_line.rstrip("\n")
                if not raw_line.strip():
                    continue
                try:
                    entry = json.loads(raw_line)
                    seq = entry.get("seq", 0)
                    if seq >= last_seq:
                        last_seq = seq
                        last_line = raw_line
                except json.JSONDecodeError:
                    pass

        if last_line is not None:
            self._prev_hash = hashlib.sha256(last_line.encode()).hexdigest()
            self._seq = last_seq + 1
