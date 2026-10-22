"""Tests for PacketDecoder and protocol parsing."""

from pathlib import Path
import scapy.all as scapy
from sniffer.decode.decoder import PacketDecoder


def test_decode_sample_pcap():
    pcap_path = Path(__file__).parent / "samples" / "sample.pcap"
    if not pcap_path.exists():
        return

    scapy_pkts = scapy.rdpcap(str(pcap_path))
    decoder = PacketDecoder(log_payload=False)

    decoded = []
    for raw in scapy_pkts:
        pkt = decoder.decode(raw)
        if pkt is not None:
            decoded.append(pkt)

    assert len(decoded) == len(scapy_pkts)
    assert all(pkt.src != "unknown" for pkt in decoded)
    # Ensure default privacy: raw_payload is None
    assert all(pkt.raw_payload is None for pkt in decoded)


def test_decoder_synthetic_http_and_redaction():
    # Build synthetic HTTP packet with Authorization header
    raw_pkt = (
        scapy.Ether() /
        scapy.IP(src="192.168.1.10", dst="93.184.216.34") /
        scapy.TCP(sport=50000, dport=80) /
        scapy.Raw(load=b"GET /secret HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer topsecrettoken123\r\nCookie: session=xyz999\r\n\r\n")
    )

    decoder = PacketDecoder(log_payload=False)
    pkt = decoder.decode(raw_pkt)

    assert pkt is not None
    assert pkt.proto == "HTTP"
    assert "http" in pkt.metadata
    headers = pkt.metadata["http"]["headers"]
    # Verify Authorization and Cookie headers are redacted
    assert headers.get("authorization") == "<REDACTED>"
    assert headers.get("cookie") == "<REDACTED>"
    assert "topsecrettoken123" not in str(pkt.metadata)
