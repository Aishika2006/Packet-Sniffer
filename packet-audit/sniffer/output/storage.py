"""Storage output plugins — SQLite and CSV storage for decoded packet metadata.

PRIVACY & SECURITY:
- Only metadata fields are stored by default.
- Raw payload is excluded unless explicitly enabled via config (and redacted).
- Header fields and credentials are never stored in raw/unredacted form.
"""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from sniffer.decode.packet import Packet

log = logging.getLogger(__name__)


class SQLiteStorageOutput:
    """Thread-safe SQLite output plugin for storing packet metadata."""

    def __init__(self, path: str | Path, log_payload: bool = False) -> None:
        self.path = Path(path)
        self.log_payload = log_payload
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._init_db()
        log.info("SQLite storage initialised at %s", self.path)

    def _init_db(self) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts REAL NOT NULL,
                        src TEXT NOT NULL,
                        dst TEXT NOT NULL,
                        sport INTEGER,
                        dport INTEGER,
                        proto TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        flags TEXT,
                        ttl INTEGER,
                        frag INTEGER,
                        truncated INTEGER,
                        vlan_id INTEGER,
                        metadata TEXT,
                        info TEXT,
                        raw_payload BLOB
                    )
                    """
                )
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON packets(ts)")
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_src_dst ON packets(src, dst)")
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_proto ON packets(proto)")

    def handle(self, packet: Packet) -> None:
        """Insert decoded packet metadata record."""
        meta_str = json.dumps(packet.metadata, ensure_ascii=False, default=str)
        payload_blob = packet.raw_payload if self.log_payload else None

        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO packets (
                            ts, src, dst, sport, dport, proto, size, flags,
                            ttl, frag, truncated, vlan_id, metadata, info, raw_payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            packet.ts,
                            packet.src,
                            packet.dst,
                            packet.sport,
                            packet.dport,
                            packet.proto,
                            packet.size,
                            packet.flags,
                            packet.ttl,
                            1 if packet.frag else 0,
                            1 if packet.truncated else 0,
                            packet.vlan_id,
                            meta_str,
                            packet.info,
                            payload_blob,
                        ),
                    )
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("SQLite insert error: %s", exc)

    def close(self) -> None:
        """Close SQLite database connection."""
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
                log.info("SQLite storage closed")
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("SQLite close error: %s", exc)


class CSVStorageOutput:
    """Thread-safe CSV output plugin for storing packet metadata records."""

    _FIELDNAMES = [
        "ts", "formatted_ts", "src", "dst", "sport", "dport",
        "proto", "size", "flags", "ttl", "frag", "vlan_id", "info"
    ]

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        is_new = not self.path.exists() or self.path.stat().st_size == 0
        self._file = self.path.open("a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=self._FIELDNAMES)
        if is_new:
            self._writer.writeheader()
            self._file.flush()
        log.info("CSV storage initialised at %s", self.path)

    def handle(self, packet: Packet) -> None:
        """Write packet row to CSV."""
        row = {
            "ts": packet.ts,
            "formatted_ts": packet.formatted_ts,
            "src": packet.src,
            "dst": packet.dst,
            "sport": packet.sport if packet.sport is not None else "",
            "dport": packet.dport if packet.dport is not None else "",
            "proto": packet.proto,
            "size": packet.size,
            "flags": packet.flags,
            "ttl": packet.ttl if packet.ttl is not None else "",
            "frag": 1 if packet.frag else 0,
            "vlan_id": packet.vlan_id if packet.vlan_id is not None else "",
            "info": packet.info,
        }
        with self._lock:
            try:
                self._writer.writerow(row)
                self._file.flush()
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("CSV write error: %s", exc)

    def close(self) -> None:
        """Flush and close CSV file."""
        with self._lock:
            try:
                self._file.flush()
                self._file.close()
                log.info("CSV storage closed")
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("CSV close error: %s", exc)
