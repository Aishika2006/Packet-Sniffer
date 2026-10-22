"""Unit tests for PacketDecoder and protocol decoders using sample.pcap replay."""

from pathlib import Path
import pytest
import scapy.all as scapy
from scapy.utils import rdpcap

from sniffer.decode.decoder import PacketDecoder, decode_packet
from sniffer.decode.packet import Packet

SAMPLE_PCAP = Path(__file__).parent / "samples" / "sample.pcap"


@pytest.fixture(scope="module")
def sample_packets():
    """Load packets from replay fixture without requiring live traffic or root."""
    assert SAMPLE_PCAP.is_file(), f"Fixture {SAMPLE_PCAP} does not exist"
    return rdpcap(str(SAMPLE_PCAP))


def test_fixture_integrity(sample_packets):
    """Verify sample.pcap contains expected packets."""
    assert len(sample_packets) == 12


def test_decode_returns_packet_dataclass(sample_packets):
    """Verify all packets decode to the clean Packet dataclass without Scapy leakage."""
    decoder = PacketDecoder()
    for raw_pkt in sample_packets:
        decoded = decoder.decode(raw_pkt)
        assert isinstance(decoded, Packet)
        assert isinstance(decoded.src, str)
        assert isinstance(decoded.dst, str)
        assert isinstance(decoded.proto, str)
        assert isinstance(decoded.size, int)
        assert decoded.size > 0
        assert isinstance(decoded.timestamp, float)


def test_dns_query_decoding(sample_packets):
    """Verify DNS Query packet decoding."""
    dns_query_raw = sample_packets[0]
    packet = decode_packet(dns_query_raw)

    assert packet is not None
    assert packet.proto == "DNS"
    assert packet.src == "192.168.1.100"
    assert packet.dst == "8.8.8.8"
    assert packet.dport == 53
    assert "Query" in packet.info
    assert "example.com" in packet.info
    assert "dns" in packet.metadata
    assert packet.metadata["dns"]["type"] == "query"
    assert packet.metadata["dns"]["qname"] == "example.com"


def test_dns_response_decoding(sample_packets):
    """Verify DNS Response packet decoding and answers extraction."""
    dns_resp_raw = sample_packets[1]
    packet = decode_packet(dns_resp_raw)

    assert packet is not None
    assert packet.proto == "DNS"
    assert packet.src == "8.8.8.8"
    assert packet.dst == "192.168.1.100"
    assert packet.sport == 53
    assert "Resp" in packet.info
    assert "93.184.216.34" in packet.info
    assert packet.metadata["dns"]["type"] == "response"
    assert packet.metadata["dns"]["rcode"] == "NOERROR"
    assert any("93.184.216.34" in ans for ans in packet.metadata["dns"]["answers"])


def test_tcp_handshake_decoding(sample_packets):
    """Verify TCP SYN, SYN-ACK, and ACK flags extraction."""
    # SYN
    syn_pkt = decode_packet(sample_packets[2])
    assert syn_pkt.proto == "TCP"
    assert syn_pkt.sport == 48210
    assert syn_pkt.dport == 80
    assert "flags=S" in syn_pkt.info
    assert syn_pkt.metadata.get("tcp_flags") == "S"

    # SYN-ACK
    sa_pkt = decode_packet(sample_packets[3])
    assert sa_pkt.proto == "TCP"
    assert sa_pkt.sport == 80
    assert sa_pkt.dport == 48210
    assert "flags=SA" in sa_pkt.info

    # ACK
    ack_pkt = decode_packet(sample_packets[4])
    assert ack_pkt.proto == "TCP"
    assert "flags=A" in ack_pkt.info


def test_http_request_decoding(sample_packets):
    """Verify unencrypted HTTP GET request line and header extraction."""
    http_req_raw = sample_packets[5]
    packet = decode_packet(http_req_raw)

    assert packet is not None
    assert packet.proto == "HTTP"
    assert packet.sport == 48210
    assert packet.dport == 80
    assert "GET /" in packet.info
    assert "Host: example.com" in packet.info

    http_meta = packet.metadata.get("http")
    assert http_meta is not None
    assert http_meta["type"] == "request"
    assert http_meta["method"] == "GET"
    assert http_meta["path"] == "/"
    assert http_meta["host"] == "example.com"
    assert "mozilla" in http_meta["headers"]["user-agent"].lower()


def test_http_response_decoding(sample_packets):
    """Verify unencrypted HTTP response status line and header parsing."""
    http_resp_raw = sample_packets[6]
    packet = decode_packet(http_resp_raw)

    assert packet is not None
    assert packet.proto == "HTTP"
    assert packet.sport == 80
    assert "HTTP 200 OK" in packet.info

    http_meta = packet.metadata.get("http")
    assert http_meta is not None
    assert http_meta["type"] == "response"
    assert http_meta["status_code"] == "200"
    assert http_meta["reason"] == "OK"
    assert "text/html" in http_meta["headers"].get("content-type", "")


def test_https_tls_metadata_extraction(sample_packets):
    """Verify encrypted traffic exposes non-sensitive metadata only without decryption."""
    tls_raw = sample_packets[7]
    packet = decode_packet(tls_raw)

    assert packet is not None
    assert packet.proto == "HTTPS"
    assert packet.dport == 443
    assert "TLS" in packet.info
    assert "tls" in packet.metadata
    assert packet.metadata["tls"]["encrypted"] is True
    assert packet.metadata["tls"]["record_type"] == "Handshake"


def test_icmp_decoding(sample_packets):
    """Verify ICMP echo request and reply decoding."""
    req_pkt = decode_packet(sample_packets[8])
    assert req_pkt.proto == "ICMP"
    assert "type=8" in req_pkt.info
    assert req_pkt.metadata.get("icmp_type") == 8

    reply_pkt = decode_packet(sample_packets[9])
    assert reply_pkt.proto == "ICMP"
    assert "type=0" in reply_pkt.info
    assert reply_pkt.metadata.get("icmp_type") == 0


def test_arp_decoding(sample_packets):
    """Verify ARP request and reply decoding."""
    arp_req = decode_packet(sample_packets[10])
    assert arp_req.proto == "ARP"
    assert "who-has 192.168.1.1" in arp_req.info

    arp_rep = decode_packet(sample_packets[11])
    assert arp_rep.proto == "ARP"
    assert "is-at 192.168.1.100" in arp_rep.info


def test_canonical_string_format(sample_packets):
    """Verify packet formatting conforms to required 'src:sport -> dst:dport [PROTO] len=N'."""
    tcp_pkt = decode_packet(sample_packets[2])
    formatted = str(tcp_pkt)
    assert formatted.startswith("192.168.1.100:48210 -> 93.184.216.34:80 [TCP] len=")
