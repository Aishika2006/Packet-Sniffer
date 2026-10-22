"""Unit tests for output plugins (PCAP, SQLite, CSV) and PortScanDetector."""

import csv
from pathlib import Path
import queue
import sqlite3
import time
import pytest
from scapy.utils import rdpcap

from sniffer.analyze.detectors import PortScanDetector
from sniffer.decode.decoder import PacketDecoder
from sniffer.decode.packet import Packet
from sniffer.decode.worker import PacketWorker, STOP_SENTINEL
from sniffer.output.console import ConsoleOutput
from sniffer.output.pcap_writer import PcapWriterOutput
from sniffer.output.storage import CSVStorageOutput, SQLiteStorageOutput, create_storage_output

SAMPLE_PCAP = Path(__file__).parent / "samples" / "sample.pcap"


@pytest.fixture
def decoded_packets():
    """Decode all packets from sample fixture."""
    decoder = PacketDecoder()
    raw = rdpcap(str(SAMPLE_PCAP))
    return [decoder.decode(p) for p in raw if p is not None]


def test_pcap_writer_output(tmp_path, decoded_packets):
    """Verify PcapWriterOutput writes a valid .pcap readable by rdpcap."""
    out_file = tmp_path / "written.pcap"
    writer = PcapWriterOutput(out_file)

    for pkt in decoded_packets:
        writer.handle(pkt)
    writer.close()

    assert out_file.is_file()
    assert writer.packets_written == 12

    # Verify written file can be read by Scapy rdpcap
    read_back = rdpcap(str(out_file))
    assert len(read_back) == 12


def test_sqlite_storage_output(tmp_path, decoded_packets):
    """Verify SQLiteStorageOutput correctly logs packets and structured metadata."""
    db_file = tmp_path / "packets.db"
    storage = SQLiteStorageOutput(db_file, batch_size=5)

    for pkt in decoded_packets:
        storage.handle(pkt)
    storage.close()

    assert db_file.is_file()
    assert storage.packets_saved == 12

    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM packets")
    count = cur.fetchone()[0]
    assert count == 12

    # Query protocol distribution from SQLite
    cur.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
    proto_map = dict(cur.fetchall())
    assert "DNS" in proto_map
    assert "HTTP" in proto_map
    conn.close()


def test_csv_storage_output(tmp_path, decoded_packets):
    """Verify CSVStorageOutput logs headers and packet rows."""
    csv_file = tmp_path / "packets.csv"
    storage = CSVStorageOutput(csv_file)

    for pkt in decoded_packets:
        storage.handle(pkt)
    storage.close()

    assert csv_file.is_file()
    assert storage.packets_saved == 12

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        assert len(reader) == 13  # 1 header + 12 packets
        assert reader[0] == CSVStorageOutput.HEADERS


def test_storage_factory(tmp_path):
    """Verify create_storage_output factory creates appropriate classes."""
    sqlite_out = create_storage_output("sqlite", tmp_path / "test.db")
    assert isinstance(sqlite_out, SQLiteStorageOutput)
    sqlite_out.close()

    csv_out = create_storage_output("csv", tmp_path / "test.csv")
    assert isinstance(csv_out, CSVStorageOutput)
    csv_out.close()


def test_port_scan_detector():
    """Verify PortScanDetector detects rapid scanning across distinct destination ports."""
    alerts = []
    detector = PortScanDetector(threshold=5, window_seconds=5.0, on_alert=alerts.append)

    base_time = time.time()
    for port in range(1, 8):
        pkt = Packet(
            src="10.0.0.99",
            dst="10.0.0.1",
            sport=45000 + port,
            dport=port,
            proto="TCP",
            size=60,
            timestamp=base_time + (port * 0.1),
        )
        detector.handle(pkt)

    assert len(alerts) == 1
    assert "10.0.0.99" in alerts[0]
    assert "5 distinct ports" in alerts[0]
    assert detector.alerts_count == 1


def test_packet_worker_queue_pipeline(decoded_packets):
    """Verify PacketWorker consumes raw packets, decodes, and drains gracefully."""
    packet_queue = queue.Queue()
    raw_packets = rdpcap(str(SAMPLE_PCAP))

    # Push raw packets into queue
    for p in raw_packets:
        packet_queue.put(p)

    handled = []
    worker = PacketWorker(
        packet_queue=packet_queue,
        decoder=PacketDecoder(),
        handlers=[handled.append],
    )
    worker.start()

    # Request stop and join (draining queue)
    worker.stop()
    worker.join(timeout=3.0)

    assert not worker.is_alive()
    assert len(handled) == 12
    assert worker.packets_decoded == 12
    assert worker.decode_errors == 0
