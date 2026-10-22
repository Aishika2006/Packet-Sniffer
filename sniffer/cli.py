"""Command-line interface argument parsing for the packet sniffer."""

import argparse
import sys
from typing import List, Optional


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        prog="packet-sniffer",
        description="Modular network packet sniffer and traffic analyzer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-i", "--iface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0, or Windows interface name).",
    )

    parser.add_argument(
        "-f", "--filter",
        type=str,
        default=None,
        help='BPF filter string (e.g. "tcp port 443", "udp and port 53", "icmp").',
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=None,
        help="Number of packets to capture before exiting (0 for unlimited).",
    )

    parser.add_argument(
        "-o", "--out",
        type=str,
        default=None,
        help="Path to save captured packets in .pcap format.",
    )

    parser.add_argument(
        "-r", "--offline",
        type=str,
        default=None,
        help="Path to .pcap file to read/replay instead of live interface sniffing.",
    )

    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to SQLite database to log captured packets (e.g. captures/packets.db).",
    )

    parser.add_argument(
        "--csv",
        type=str,
        default=None,
        help="Path to CSV file to log captured packets (e.g. captures/packets.csv).",
    )

    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to YAML configuration file.",
    )

    parser.add_argument(
        "-l", "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )

    parser.add_argument(
        "--no-console",
        action="store_true",
        help="Disable live console packet stream output.",
    )

    return parser


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = create_parser()
    return parser.parse_args(args if args is not None else sys.argv[1:])
