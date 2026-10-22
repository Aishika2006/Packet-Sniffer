import logging
import os
from pathlib import Path
import signal
import sys
import time
from typing import List, Optional

# Suppress verbose Scapy import and runtime warnings on Windows
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from sniffer.capture.capturer import PacketCapturer, get_available_interfaces
from sniffer.cli import parse_args
from sniffer.config import AppConfig, load_config
from sniffer.decode.decoder import decode_packet
from sniffer.output.base import BaseOutput
from sniffer.output.console import ConsoleOutput
from sniffer.utils.logging import setup_logging

logger = logging.getLogger("packet-sniffer")


def print_interfaces_table(interfaces: List[dict[str, str]]) -> None:
    """Print available network interfaces in an aligned table format."""
    if not interfaces:
        print("No network interfaces detected.")
        return

    print("\nAvailable Network Interfaces:")
    print("-" * 80)
    print(f"{'Name / Identifier':<35} {'IP Address':<18} {'MAC Address':<18} {'Description'}")
    print("-" * 80)
    for iface in interfaces:
        name = iface["name"] if iface["name"] else iface["id"]
        # Shorten very long Windows device GUIDs for display if needed
        display_name = (name[:32] + "...") if len(name) > 35 else name
        desc = (iface["description"][:30] + "...") if len(iface["description"]) > 33 else iface["description"]
        print(f"{display_name:<35} {iface['ip']:<18} {iface['mac']:<18} {desc}")
    print("-" * 80 + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main application entry point.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success, non-zero for error).
    """
    args = parse_args(argv)

    # Handle interface listing request immediately
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print_interfaces_table(interfaces)
        return 0

    # Load configuration from YAML and apply CLI overrides
    config: AppConfig = load_config(config_path=args.config, cli_args=args)

    # Configure logging
    setup_logging(level=config.logging.level)

    # Validate offline file if provided
    if config.capture.offline:
        offline_path = Path(config.capture.offline)
        if not offline_path.is_file():
            logger.error("Specified offline pcap file does not exist: '%s'", config.capture.offline)
            print(f"\n[ERROR] File not found: '{config.capture.offline}'")
            print("Please provide a valid .pcap path (e.g. --offline tests/samples/sample.pcap).\n")
            return 1

    logger.info("Initializing Packet Sniffer...")
    logger.info("Interface: %s", config.capture.interface or "Default")
    logger.info("BPF Filter: '%s'", config.capture.bpf_filter or "None")
    logger.info("Packet Count Limit: %s", config.capture.count or "Unlimited")

    from sniffer.analyze.stats import StatsAnalyzer
    from sniffer.analyze.detectors import PortScanDetector
    from sniffer.output.pcap_writer import PcapWriterOutput
    from sniffer.output.storage import create_storage_output

    # Initialize output plugins
    outputs: List[BaseOutput] = []
    if config.output.console.enabled:
        outputs.append(ConsoleOutput(colored=config.output.console.colored))
    if config.output.pcap.enabled:
        outputs.append(PcapWriterOutput(filepath=config.output.pcap.path))
    if config.output.storage.enabled:
        outputs.append(create_storage_output(
            storage_type=config.output.storage.type,
            file_path=config.output.storage.path,
        ))

    # Initialize analyzers
    stats = StatsAnalyzer()
    detector = PortScanDetector()

    # Handlers list: analyzers receive packets first, followed by output plugins
    handlers = [stats.handle, detector.handle]
    for out in outputs:
        handlers.append(out.handle)

    # Signal handling for clean exit on Ctrl+C / SIGTERM
    stop_requested = False

    def on_signal(sig: int, frame: object) -> None:
        nonlocal stop_requested
        if not stop_requested:
            stop_requested = True
            logger.info("Interrupt received (%s). Stopping capture...", signal.Signals(sig).name)
            if capturer.is_alive():
                capturer.stop()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    import queue
    from sniffer.decode.decoder import PacketDecoder
    from sniffer.decode.worker import PacketWorker

    # Thread-safe queue decoupling capture thread from decoding/output workers
    packet_queue: queue.Queue = queue.Queue(maxsize=10000)

    # Capturer pushes directly to queue with zero processing
    def enqueue_packet(raw_pkt: object) -> None:
        try:
            packet_queue.put(raw_pkt, timeout=0.2)
        except queue.Full:
            logger.warning("Packet queue full (capacity 10,000)! Dropping raw packet.")

    # Worker thread pulls from queue, decodes into Packet dataclass, and dispatches to handlers
    worker = PacketWorker(
        packet_queue=packet_queue,
        decoder=PacketDecoder(),
        handlers=handlers,
    )

    capturer = PacketCapturer(
        on_packet=enqueue_packet,
        interface=config.capture.interface,
        bpf_filter=config.capture.bpf_filter,
        count=config.capture.count,
        promisc=config.capture.promisc,
        offline=config.capture.offline,
    )

    try:
        worker.start()
        capturer.start()
        logger.info("Capture started. Press Ctrl+C to stop.")

        # Keep main thread alive while capturer is active and no stop signal
        while capturer.is_alive() and not stop_requested:
            time.sleep(0.1)

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt caught. Stopping...")
    finally:
        # Step 1: Stop and join the capturer thread so no new packets arrive
        capturer.stop()
        capturer.join(timeout=2.0)

        # Step 2: Signal worker to process remaining packets in the queue and terminate
        worker.stop()
        worker.join(timeout=5.0)

        # Step 3: Flush and close all output plugins
        for out in outputs:
            try:
                out.close()
            except Exception as e:
                logger.error("Error closing output plugin %s: %s", out.__class__.__name__, e)

        # Step 4: Display comprehensive statistics report
        print(stats.format_summary())

        if detector.alerts_count > 0:
            logger.warning("Total port-scan security alerts: %d", detector.alerts_count)

        logger.info(
            "Capture stopped. Packets captured: %d | Decoded: %d | Errors: %d",
            capturer.packets_captured,
            worker.packets_decoded,
            worker.decode_errors,
        )

    if capturer.error:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
