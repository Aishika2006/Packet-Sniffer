"""CLI parser for the packet audit tool."""

from __future__ import annotations

import argparse
from typing import Any


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser with sub-commands."""
    parser = argparse.ArgumentParser(
        prog="packet-audit",
        description="Modular Passive Network Traffic Auditing Tool with Integrity Verification",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # ------------------------------------------------------------------
    # 1. capture (live or offline capture with audit)
    # ------------------------------------------------------------------
    capture_parser = subparsers.add_parser("capture", help="Start packet capture and real-time audit")
    capture_parser.add_argument("-i", "--interface", type=str, help="Network interface to capture from")
    capture_parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter string (e.g. 'tcp port 80')")
    capture_parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    capture_parser.add_argument("-d", "--duration", type=int, default=0, help="Duration in seconds (0 = infinite)")
    capture_parser.add_argument("-r", "--offline", type=str, help="Read packets from .pcap file instead of live capture")
    capture_parser.add_argument("-w", "--pcap", type=str, help="Save raw captured packets to .pcap file")
    capture_parser.add_argument("--db", type=str, help="SQLite database path for packet metadata")
    capture_parser.add_argument("--csv", type=str, help="CSV file path for packet metadata")
    capture_parser.add_argument("--trail", type=str, help="Audit trail JSONL output file")
    capture_parser.add_argument("--operator", type=str, help="Operator ID for audit record header")
    capture_parser.add_argument("--no-console", action="store_true", help="Disable console packet stream")
    capture_parser.add_argument("--log-payload", action="store_true", help="Enable raw payload capture (PRIVACY WARNING)")

    # ------------------------------------------------------------------
    # 2. audit (offline pcap audit)
    # ------------------------------------------------------------------
    audit_parser = subparsers.add_parser("audit", help="Run audit rules against an existing .pcap file")
    audit_parser.add_argument("pcap_file", type=str, help="Path to .pcap file to audit")
    audit_parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter string")
    audit_parser.add_argument("--trail", type=str, help="Audit trail JSONL output file")
    audit_parser.add_argument("--report-dir", type=str, help="Directory for generated audit report")
    audit_parser.add_argument("--report-format", choices=["markdown", "html"], default="markdown", help="Report format")
    audit_parser.add_argument("--operator", type=str, help="Operator ID for audit trail")

    # ------------------------------------------------------------------
    # 3. verify (tamper verification of audit trail)
    # ------------------------------------------------------------------
    verify_parser = subparsers.add_parser("verify", help="Verify the cryptographic integrity of an audit trail")
    verify_parser.add_argument(
        "trail_file",
        type=str,
        nargs="?",
        default="reports/audit_trail.jsonl",
        help="Path to JSONL audit trail (default: reports/audit_trail.jsonl)",
    )

    # ------------------------------------------------------------------
    # 4. report (generate report from audit trail)
    # ------------------------------------------------------------------
    report_parser = subparsers.add_parser("report", help="Generate an audit report from an existing audit trail")
    report_parser.add_argument(
        "trail_file",
        type=str,
        nargs="?",
        default="reports/audit_trail.jsonl",
        help="Path to JSONL audit trail (default: reports/audit_trail.jsonl)",
    )
    report_parser.add_argument(
        "-o", "--out-dir",
        type=str,
        default="reports",
        help="Output directory for generated report (default: reports)",
    )
    report_parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report format: markdown or html (default: markdown)",
    )
    report_parser.add_argument(
        "--operator",
        type=str,
        default="",
        help="Operator ID for report header",
    )

    # ------------------------------------------------------------------
    # 5. list-interfaces
    # ------------------------------------------------------------------
    subparsers.add_parser("list-interfaces", help="List available network interfaces and exit")

    return parser
