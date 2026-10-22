"""Unit tests for StatsAnalyzer using sample.pcap replay."""

from pathlib import Path
import pytest
from scapy.utils import rdpcap

from sniffer.analyze.stats import StatsAnalyzer
from sniffer.decode.decoder import PacketDecoder

SAMPLE_PCAP = Path(__file__).parent / "samples" / "sample.pcap"


@pytest.fixture
def decoded_packets():
    """Decode all packets from the sample replay fixture."""
    decoder = PacketDecoder()
    raw_packets = rdpcap(str(SAMPLE_PCAP))
    return [decoder.decode(p) for p in raw_packets if p is not None]


def test_stats_initial_state():
    """Verify clean state on new StatsAnalyzer."""
    analyzer = StatsAnalyzer()
    summary = analyzer.get_summary()
    assert summary["total_packets"] == 0
    assert summary["total_bytes"] == 0
    assert len(summary["protocols"]) == 0
    assert "No packets captured" in analyzer.format_summary()


def test_stats_counters_aggregation(decoded_packets):
    """Verify counters by host, protocol, and port across sample packets."""
    analyzer = StatsAnalyzer()
    for pkt in decoded_packets:
        analyzer.handle(pkt)

    summary = analyzer.get_summary()

    # Packet and byte totals
    assert summary["total_packets"] == 12
    assert summary["total_bytes"] == sum(p.size for p in decoded_packets)

    # Protocols tracked
    protos = summary["protocols"]
    assert "TCP" in protos
    assert "UDP" in protos or "DNS" in protos
    assert "HTTP" in protos
    assert "ICMP" in protos
    assert "ARP" in protos
    assert "HTTPS" in protos

    # Host counters
    top_srcs = dict(summary["top_sources"])
    assert "192.168.1.100" in top_srcs
    assert top_srcs["192.168.1.100"] >= 6

    top_dsts = dict(summary["top_destinations"])
    assert "93.184.216.34" in top_dsts

    # Port counters
    top_ports = dict(summary["top_ports"])
    assert 80 in top_ports
    assert 53 in top_ports or 443 in top_ports


def test_stats_format_summary_table(decoded_packets):
    """Verify ASCII table generation with formatting markers."""
    analyzer = StatsAnalyzer()
    for pkt in decoded_packets:
        analyzer.handle(pkt)

    output = analyzer.format_summary()

    assert "NETWORK TRAFFIC SUMMARY" in output
    assert "Total Packets:       12" in output
    assert "Protocol Breakdown:" in output
    assert "Top Source Hosts:" in output
    assert "Top Destination Hosts:" in output
    assert "Top Target Ports / Services:" in output
    assert "HTTP" in output
    assert "TCP" in output
