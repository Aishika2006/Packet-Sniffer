"""Persistent storage output plugins supporting SQLite database and CSV file export."""

import csv
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import List, Optional

from sniffer.decode.packet import Packet
from sniffer.output.base import BaseOutput

logger = logging.getLogger(__name__)


class SQLiteStorageOutput(BaseOutput):
    """Stores captured packets in a SQLite database with indexed query fields."""

    def __init__(self, db_path: str | Path, batch_size: int = 50) -> None:
        """
        Initialize SQLite storage plugin.

        Args:
            db_path: Path to the SQLite database file.
            batch_size: Number of records to accumulate before committing a transaction.
        """
        self.db_path = Path(db_path)
        self.batch_size = max(1, batch_size)
        self._lock = threading.Lock()
        self._buffer: List[tuple] = []
        self.packets_saved: int = 0

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db()
        logger.info("Initialized SQLite storage at %s", self.db_path)

    def _init_db(self) -> None:
        """Create database tables and performance indexes."""
        with self._lock:
            with self._conn:
                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        formatted_time TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        size INTEGER,
                        info TEXT,
                        metadata_json TEXT
                    )
                """)
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_proto ON packets(protocol)")
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_src ON packets(src_ip)")
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_dst ON packets(dst_ip)")

    def handle(self, packet: Packet) -> None:
        """Buffer and commit packet records."""
        # Serialize metadata without binary payload
        meta_clean = {k: v for k, v in packet.metadata.items() if k not in ("raw_bytes", "raw_frame")}
        meta_str = json.dumps(meta_clean, default=str)

        row = (
            packet.timestamp,
            packet.formatted_time,
            packet.src,
            packet.dst,
            packet.sport,
            packet.dport,
            packet.proto,
            packet.size,
            packet.info,
            meta_str,
        )

        with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self.batch_size:
                self._flush_locked()

    def _flush_locked(self) -> None:
        """Write and commit buffered records (must be called with _lock held)."""
        if not self._buffer or self._conn is None:
            return
        try:
            with self._conn:
                self._conn.executemany("""
                    INSERT INTO packets (
                        timestamp, formatted_time, src_ip, dst_ip, src_port,
                        dst_port, protocol, size, info, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, self._buffer)
            self.packets_saved += len(self._buffer)
            self._buffer.clear()
        except Exception as e:
            logger.error("Failed to commit packets to SQLite: %s", e)

    def close(self) -> None:
        """Flush remaining records and close SQLite connection."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._flush_locked()
                    self._conn.close()
                    logger.info("SQLite storage closed. Saved %d packets to %s", self.packets_saved, self.db_path)
                except Exception as e:
                    logger.error("Error closing SQLite storage: %s", e)
                finally:
                    self._conn = None


class CSVStorageOutput(BaseOutput):
    """Appends captured packets to a standard CSV file."""

    HEADERS = [
        "timestamp",
        "formatted_time",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "size",
        "info",
    ]

    def __init__(self, csv_path: str | Path) -> None:
        """
        Initialize CSV storage plugin.

        Args:
            csv_path: Destination path for the CSV file.
        """
        self.csv_path = Path(csv_path)
        self._lock = threading.Lock()
        self.packets_saved: int = 0

        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        file_exists = self.csv_path.is_file() and self.csv_path.stat().st_size > 0

        self._file = open(self.csv_path, mode="a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._file)

        if not file_exists:
            self._writer.writerow(self.HEADERS)
            self._file.flush()

        logger.info("Initialized CSV storage at %s", self.csv_path)

    def handle(self, packet: Packet) -> None:
        """Write a packet row to the CSV file."""
        row = [
            packet.timestamp,
            packet.formatted_time,
            packet.src,
            packet.sport or "",
            packet.dst,
            packet.dport or "",
            packet.proto,
            packet.size,
            packet.info,
        ]
        with self._lock:
            try:
                self._writer.writerow(row)
                self.packets_saved += 1
            except Exception as e:
                logger.error("Error writing packet to CSV %s: %s", self.csv_path, e)

    def close(self) -> None:
        """Flush and close CSV file handle."""
        with self._lock:
            if self._file is not None:
                try:
                    self._file.flush()
                    self._file.close()
                    logger.info("CSV storage closed. Saved %d packets to %s", self.packets_saved, self.csv_path)
                except Exception as e:
                    logger.error("Error closing CSV file: %s", e)
                finally:
                    self._file = None


def create_storage_output(storage_type: str, file_path: str | Path) -> BaseOutput:
    """
    Factory function for instantiating storage output plugins.

    Args:
        storage_type: 'sqlite' or 'csv'.
        file_path: Destination file path.

    Returns:
        BaseOutput plugin instance.
    """
    st_lower = str(storage_type).strip().lower()
    if st_lower == "csv":
        return CSVStorageOutput(file_path)
    return SQLiteStorageOutput(file_path)
