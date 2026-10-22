"""Tests for all 7 audit rules in sniffer.analyze.audit_rules."""

import time
import pytest
from sniffer.analyze.audit_rules import (
    CleartextProtocolRule,
    DeprecatedTLSRule,
    AllowlistRule,
    DNSAnomalyRule,
    PortScanRule,
    VolumeAnomalyRule,
    CleartextCredentialRule,
)
from sniffer.decode.packet import Packet


def test_cleartext_protocol_rule():
    rule = CleartextProtocolRule(enabled=True)
    # HTTP on port 80
    pkt_http = Packet(
        ts=time.time(), src="192.168.1.10", dst="93.184.216.34",
        dport=80, sport=54321, proto="TCP", size=100
    )
    events = rule.analyze(pkt_http)
    assert len(events) == 1
    assert events[0].rule == "cleartext_protocols"
    assert events[0].severity == "HIGH"

    # HTTPS on port 443 (not cleartext)
    pkt_https = Packet(
        ts=time.time(), src="192.168.1.10", dst="93.184.216.34",
        dport=443, sport=54321, proto="HTTPS", size=100
    )
    assert len(rule.analyze(pkt_https)) == 0


def test_deprecated_tls_rule():
    rule = DeprecatedTLSRule(enabled=True)
    # Deprecated TLS 1.0
    pkt_bad_tls = Packet(
        ts=time.time(), src="192.168.1.10", dst="1.1.1.1",
        dport=443, sport=50000, proto="HTTPS", size=200,
        metadata={"tls": {"version": "TLS 1.0", "sni": "legacy.example.com"}}
    )
    events = rule.analyze(pkt_bad_tls)
    assert len(events) == 1
    assert "TLS 1.0" in events[0].message

    # Modern TLS 1.3
    pkt_good_tls = Packet(
        ts=time.time(), src="192.168.1.10", dst="1.1.1.1",
        dport=443, sport=50000, proto="HTTPS", size=200,
        metadata={"tls": {"version": "TLS 1.3", "sni": "secure.example.com"}}
    )
    assert len(rule.analyze(pkt_good_tls)) == 0


def test_allowlist_rule():
    rule = AllowlistRule(
        enabled=True,
        allowed_hosts=["192.168.1.0/24", "10.0.0.1"],
        allowed_ports=[80, 443]
    )
    # Allowed
    pkt_ok = Packet(
        ts=time.time(), src="192.168.1.50", dst="10.0.0.1",
        dport=443, sport=40000, proto="TCP", size=100
    )
    assert len(rule.analyze(pkt_ok)) == 0

    # Disallowed host
    pkt_bad_host = Packet(
        ts=time.time(), src="192.168.1.50", dst="8.8.8.8",
        dport=443, sport=40000, proto="TCP", size=100
    )
    events = rule.analyze(pkt_bad_host)
    assert any("Destination IP 8.8.8.8" in e.message for e in events)

    # Disallowed port
    pkt_bad_port = Packet(
        ts=time.time(), src="192.168.1.50", dst="10.0.0.1",
        dport=22, sport=40000, proto="TCP", size=100
    )
    events = rule.analyze(pkt_bad_port)
    assert any("Port 22" in e.message for e in events)


def test_dns_anomaly_rule():
    rule = DNSAnomalyRule(
        enabled=True,
        nxdomain_rate_threshold=3,
        long_name_threshold=30,
        high_entropy_threshold=3.5,
    )
    # Long query name
    pkt_long = Packet(
        ts=time.time(), src="10.0.0.5", dst="8.8.8.8",
        dport=53, sport=12345, proto="DNS", size=150,
        metadata={"dns": {"qname": "a" * 35 + ".evil.example.com", "rcode": "NOERROR", "entropy": 2.1}}
    )
    events = rule.analyze(pkt_long)
    assert any("long DNS query" in e.message for e in events)

    # High entropy query
    pkt_entropy = Packet(
        ts=time.time(), src="10.0.0.5", dst="8.8.8.8",
        dport=53, sport=12345, proto="DNS", size=150,
        metadata={"dns": {"qname": "v8q9x1z4m7p3k2.example.com", "rcode": "NOERROR", "entropy": 3.8}}
    )
    events = rule.analyze(pkt_entropy)
    assert any("High-entropy DNS" in e.message for e in events)


def test_port_scan_rule():
    rule = PortScanRule(enabled=True, distinct_ports_threshold=3, window_seconds=5.0)
    src = "192.168.1.99"
    # Touch 3 distinct ports
    e1 = rule.analyze(Packet(ts=time.time(), src=src, dst="10.0.0.1", dport=21, sport=1000, proto="TCP", size=60))
    assert len(e1) == 0
    e2 = rule.analyze(Packet(ts=time.time(), src=src, dst="10.0.0.1", dport=22, sport=1000, proto="TCP", size=60))
    assert len(e2) == 0
    e3 = rule.analyze(Packet(ts=time.time(), src=src, dst="10.0.0.1", dport=23, sport=1000, proto="TCP", size=60))
    assert len(e3) == 1
    assert "Port-scan" in e3[0].message


def test_volume_anomaly_rule():
    rule = VolumeAnomalyRule(enabled=True, bytes_per_minute_threshold=1000)
    src = "192.168.1.150"
    e1 = rule.analyze(Packet(ts=time.time(), src=src, dst="10.0.0.1", dport=80, sport=1000, proto="TCP", size=600))
    assert len(e1) == 0
    e2 = rule.analyze(Packet(ts=time.time(), src=src, dst="10.0.0.1", dport=80, sport=1000, proto="TCP", size=600))
    assert len(e2) == 1
    assert "Volume anomaly" in e2[0].message


def test_cleartext_credentials_rule_and_redaction():
    rule = CleartextCredentialRule(enabled=True)
    # Packet with password parameter in cleartext payload
    pkt = Packet(
        ts=time.time(), src="192.168.1.200", dst="93.184.216.34",
        dport=80, sport=50000, proto="HTTP", size=300,
        raw_payload=b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&password=SuperSecretPassword123",
        metadata={"http": {"has_credentials": True}}
    )
    events = rule.analyze(pkt)
    assert len(events) == 1
    assert events[0].severity == "CRITICAL"
    # CRITICAL: Verify secret password value is NOT in event or evidence
    assert "SuperSecretPassword123" not in events[0].message
    assert "SuperSecretPassword123" not in str(events[0].evidence)
