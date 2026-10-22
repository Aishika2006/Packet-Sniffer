"""Tests for SQLite and CSV storage outputs."""

import sqlite3
import csv
from pathlib import Path
from sniffer.decode.packet import Packet
from sniffer.output.storage import SQLiteStorageOutput, CSVStorageOutput


def test_sqlite_storage(tmp_path: Path):
    db_file = tmp_path / "test.db"
    out = SQLiteStorageOutput(db_file, log_payload=False)

    pkt = Packet(
        ts=1700000000.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=1234,
        dport=80,
        proto="HTTP",
        size=150,
        flags="PA",
        info="GET / HTTP/1.1",
        metadata={"http": {"method": "GET"}},
    )
    out.handle(pkt)
    out.close()

    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT src, dst, proto, size, raw_payload FROM packets")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][0] == "10.0.0.1"
    assert rows[0][1] == "10.0.0.2"
    assert rows[0][2] == "HTTP"
    assert rows[0][3] == 150
    # Payload not logged
    assert rows[0][4] is None


def test_csv_storage(tmp_path: Path):
    csv_file = tmp_path / "test.csv"
    out = CSVStorageOutput(csv_file)

    pkt = Packet(
        ts=1700000000.0,
        src="192.168.1.10",
        dst="192.168.1.1",
        sport=5000,
        dport=53,
        proto="DNS",
        size=80,
        info="Query A example.com",
    )
    out.handle(pkt)
    out.close()

    with csv_file.open("r", encoding="utf-8") as fh:
        reader = list(csv.DictReader(fh))
        assert len(reader) == 1
        assert reader[0]["src"] == "192.168.1.10"
        assert reader[0]["proto"] == "DNS"
