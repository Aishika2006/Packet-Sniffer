"""Tests for audit report generation in Markdown and HTML."""

from pathlib import Path
from sniffer.audit.trail import AuditTrail
from sniffer.audit.report import generate_report


def test_generate_markdown_and_html_report(tmp_path: Path):
    trail_file = tmp_path / "trail.jsonl"
    trail = AuditTrail(trail_file)
    trail.append("meta", {"event": "session_start", "operator": "auditor_sec"})
    trail.append("event", {
        "rule": "cleartext_protocols",
        "severity": "HIGH",
        "src": "192.168.1.10",
        "dst": "93.184.216.34",
        "sport": 54321,
        "dport": 80,
        "proto": "TCP",
        "message": "Cleartext protocol HTTP detected",
        "evidence": {"port": 80},
    })
    trail.append("event", {
        "rule": "deprecated_tls",
        "severity": "HIGH",
        "src": "192.168.1.10",
        "dst": "1.1.1.1",
        "sport": 54322,
        "dport": 443,
        "proto": "HTTPS",
        "message": "Deprecated TLS 1.0 detected",
        "evidence": {"version": "TLS 1.0"},
    })
    trail.append("meta", {"event": "session_end"})
    trail.close()

    # Generate Markdown report
    md_path = generate_report(trail_file, tmp_path, fmt="markdown", operator="auditor_sec")
    assert md_path.exists()
    content_md = md_path.read_text(encoding="utf-8")
    assert "# Network Traffic Audit Report" in content_md
    assert "cleartext_protocols" in content_md
    assert "deprecated_tls" in content_md
    assert "auditor_sec" in content_md

    # Generate HTML report
    html_path = generate_report(trail_file, tmp_path, fmt="html", operator="auditor_sec")
    assert html_path.exists()
    content_html = html_path.read_text(encoding="utf-8")
    assert "<title>Network Traffic Audit Report</title>" in content_html
    assert "cleartext_protocols" in content_html
