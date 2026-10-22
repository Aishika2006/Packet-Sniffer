"""Packet Audit Tool — Main entry point.

Enforces legal authorization notice, orchestrates pipeline threads,
manages output lifecycles, and handles graceful shutdowns.
"""

from __future__ import annotations

import logging
import queue
import signal
import sys
import time
from pathlib import Path
from typing import Any

from sniffer.analyze.audit_rules import build_rules
from sniffer.analyze.stats import StatsAnalyzer
from sniffer.audit.report import generate_report
from sniffer.audit.trail import AuditTrail
from sniffer.capture.capturer import PacketCapturer, list_interfaces
from sniffer.cli import build_parser
from sniffer.config import enforce_data_retention, load_config
from sniffer.decode.decoder import PacketDecoder
from sniffer.decode.worker import PacketWorker
from sniffer.output.base import OutputPlugin
from sniffer.output.console import ConsoleOutput
from sniffer.output.pcap_writer import PcapWriterOutput
from sniffer.output.storage import CSVStorageOutput, SQLiteStorageOutput
from sniffer.utils.logging import setup_logging

log = logging.getLogger("packet-audit")

LEGAL_NOTICE = """
================================================================================
                    *** LEGAL AND AUTHORIZED USE NOTICE ***
  This network traffic auditing tool is strictly designed for passive monitoring
  and security assessment on networks and systems that you OWN or have EXPLICIT,
  WRITTEN AUTHORIZATION to inspect.

  Unauthorized interception, inspection, or monitoring of network communications
  is a violation of applicable computer crime and wiretapping laws.

  ALL AUDIT ACTIVITIES MAY BE RECORDED WITH INTEGRITY HASH CHAINS.
================================================================================
"""


def _print_legal_notice() -> None:
    print(LEGAL_NOTICE, file=sys.stderr)


def _cmd_list_interfaces() -> int:
    interfaces = list_interfaces()
    print("\nAvailable Network Interfaces:")
    print("-" * 60)
    for iface in interfaces:
        print(f"  {iface['name']:<40} IP: {iface['ip']}")
    print("-" * 60)
    return 0


def _cmd_verify(trail_file: str) -> int:
    path = Path(trail_file)
    print(f"\nVerifying audit trail integrity: {path}")
    ok, errors = AuditTrail.verify(path)
    if ok:
        print(" Integrity check PASSED: Hash chain is valid and untampered.\n")
        return 0
    else:
        print(" Integrity check FAILED: Tampering or corruption detected!\n")
        for err in errors:
            print(f"  [!] {err}")
        print()
        return 1


def _cmd_report(trail_file: str, out_dir: str, fmt: str, operator: str) -> int:
    try:
        report_path = generate_report(trail_file, out_dir, fmt, operator)
        print(f"\nAudit report successfully generated:\n  -> {report_path}\n")
        return 0
    except Exception as exc:
        print(f"\nFailed to generate report: {exc}", file=sys.stderr)
        return 1


def _run_pipeline(
    cfg: dict[str, Any],
    offline_file: str | None = None,
    bpf_filter_override: str | None = None,
    report_after: bool = True,
    operator_override: str | None = None,
) -> int:
    # 1. Enforce data retention policy
    retention_days = cfg.get("privacy", {}).get("retention_days", 30)
    purged = enforce_data_retention(retention_days, ["reports", "captures"])
    if purged > 0:
        log.info("Purged %d expired file(s) per retention policy (%d days)", purged, retention_days)

    # 2. Extract configuration
    cap_cfg = cfg.get("capture", {})
    privacy_cfg = cfg.get("privacy", {})
    output_cfg = cfg.get("output", {})
    audit_trail_cfg = cfg.get("audit_trail", {})
    report_cfg = cfg.get("report", {})

    log_payload = privacy_cfg.get("log_payload", False)
    queue_maxsize = cap_cfg.get("queue_maxsize", 10000)
    interface = cap_cfg.get("interface")
    bpf_filter = bpf_filter_override if bpf_filter_override is not None else cap_cfg.get("bpf_filter", "")
    count = cap_cfg.get("count", 0)
    duration = cap_cfg.get("duration", 0)
    promisc = cap_cfg.get("promisc", True)
    offline = offline_file or cap_cfg.get("offline")
    operator = operator_override or audit_trail_cfg.get("operator", "")

    # 3. Setup audit trail
    trail_path = audit_trail_cfg.get("path", "reports/audit_trail.jsonl")
    trail = AuditTrail(trail_path)
    trail.append("meta", {
        "event": "session_start",
        "operator": operator,
        "mode": "offline" if offline else "live",
        "interface": interface,
        "filter": bpf_filter,
    })

    # 4. Instantiate pipeline components
    packet_queue: queue.Queue[Any] = queue.Queue(maxsize=queue_maxsize)
    decoder = PacketDecoder(log_payload=log_payload)
    stats = StatsAnalyzer()
    rules = build_rules(cfg.get("audit", {}).get("rules", {}))

    outputs: list[OutputPlugin] = []
    console_out: ConsoleOutput | None = None

    if output_cfg.get("console", {}).get("enabled", True):
        console_out = ConsoleOutput(colored=output_cfg.get("console", {}).get("colored", True))
        outputs.append(console_out)

    if output_cfg.get("pcap", {}).get("enabled", False):
        pcap_path = output_cfg.get("pcap", {}).get("path", "captures/audit.pcap")
        outputs.append(PcapWriterOutput(pcap_path))

    storage_cfg = output_cfg.get("storage", {})
    if storage_cfg.get("enabled", False):
        st_type = storage_cfg.get("type", "sqlite")
        st_path = storage_cfg.get("path", "captures/packets.db")
        if st_type == "csv":
            outputs.append(CSVStorageOutput(st_path))
        else:
            outputs.append(SQLiteStorageOutput(st_path, log_payload=log_payload))

    worker = PacketWorker(
        packet_queue=packet_queue,
        decoder=decoder,
        analyzers=[stats],
        rules=rules,
        outputs=outputs,
        audit_trail=trail,
        console_output=console_out,
    )

    capturer = PacketCapturer(
        packet_queue=packet_queue,
        interface=interface,
        bpf_filter=bpf_filter,
        count=count,
        promisc=promisc,
        offline=offline,
    )

    # 5. Handle shutdown signals
    stop_called = False

    def _sig_handler(signum: int, frame: Any) -> None:
        nonlocal stop_called
        if not stop_called:
            stop_called = True
            log.info("Shutdown requested. Draining pipeline...")
            capturer.stop()

    signal.signal(signal.SIGINT, _sig_handler)
    try:
        signal.signal(signal.SIGTERM, _sig_handler)
    except Exception:
        pass

    # 6. Start threads
    worker.start()
    capturer.start()

    start_time = time.time()
    try:
        while capturer.is_alive():
            time.sleep(0.5)
            if duration > 0 and (time.time() - start_time) >= duration:
                log.info("Duration limit reached (%d s)", duration)
                capturer.stop()
                break
    except KeyboardInterrupt:
        _sig_handler(signal.SIGINT, None)

    # 7. Drain and terminate
    capturer.join()
    stats.drop_count = capturer.dropped_packets

    # Send sentinel to unblock worker
    packet_queue.put(None)
    worker.join()

    # 8. Close outputs and record session end
    for out in outputs:
        try:
            out.close()
        except Exception as exc:
            log.debug("Error closing output: %s", exc)

    trail.append("meta", {
        "event": "session_end",
        "captured": capturer.captured_packets,
        "dropped": capturer.dropped_packets,
        "processed": worker.processed_count,
        "audit_events": worker.audit_event_count,
    })
    trail.close()

    # 9. Print stats
    stats.print_summary()

    # 10. Generate audit report
    if report_after:
        rep_dir = report_cfg.get("out_dir", "reports")
        rep_fmt = report_cfg.get("format", "markdown")
        try:
            rpath = generate_report(trail_path, rep_dir, rep_fmt, operator)
            print(f"\n Audit report generated: {rpath}")
        except Exception as exc:
            log.warning("Could not auto-generate report: %s", exc)

    return 0


def main() -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    # Default to capture if no subcommand provided
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "list-interfaces":
        return _cmd_list_interfaces()

    _print_legal_notice()

    # Load configuration
    cfg = load_config(args.config)
    log_level = "DEBUG" if args.verbose else cfg.get("logging", {}).get("level", "INFO")
    setup_logging(log_level)

    if args.command == "verify":
        return _cmd_verify(args.trail_file)

    if args.command == "report":
        return _cmd_report(args.trail_file, args.out_dir, args.format, args.operator)

    if args.command == "audit":
        cfg["capture"]["offline"] = args.pcap_file
        if args.filter:
            cfg["capture"]["bpf_filter"] = args.filter
        if args.trail:
            cfg["audit_trail"]["path"] = args.trail
        if args.report_dir:
            cfg["report"]["out_dir"] = args.report_dir
        if args.report_format:
            cfg["report"]["format"] = args.report_format
        if args.operator:
            cfg["audit_trail"]["operator"] = args.operator
        return _run_pipeline(cfg, offline_file=args.pcap_file, report_after=True)

    if args.command == "capture":
        if args.interface:
            cfg["capture"]["interface"] = args.interface
        if args.filter:
            cfg["capture"]["bpf_filter"] = args.filter
        if args.count:
            cfg["capture"]["count"] = args.count
        if args.duration:
            cfg["capture"]["duration"] = args.duration
        if args.offline:
            cfg["capture"]["offline"] = args.offline
        if args.pcap:
            cfg["output"]["pcap"]["enabled"] = True
            cfg["output"]["pcap"]["path"] = args.pcap
        if args.db:
            cfg["output"]["storage"]["enabled"] = True
            cfg["output"]["storage"]["type"] = "sqlite"
            cfg["output"]["storage"]["path"] = args.db
        if args.csv:
            cfg["output"]["storage"]["enabled"] = True
            cfg["output"]["storage"]["type"] = "csv"
            cfg["output"]["storage"]["path"] = args.csv
        if args.trail:
            cfg["audit_trail"]["path"] = args.trail
        if args.operator:
            cfg["audit_trail"]["operator"] = args.operator
        if args.no_console:
            cfg["output"]["console"]["enabled"] = False
        if args.log_payload:
            cfg["privacy"]["log_payload"] = True

        return _run_pipeline(cfg, offline_file=args.offline)

    return 0


if __name__ == "__main__":
    sys.exit(main())
