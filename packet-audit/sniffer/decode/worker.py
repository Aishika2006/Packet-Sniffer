"""PacketWorker — background worker consuming raw packets, decoding, and dispatching.

Pipeline flow:
queue -> PacketDecoder -> Packet -> [AuditRules, Analyzers, Outputs]
Audit findings are recorded into the tamper-evident AuditTrail.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Optional

from sniffer.analyze.audit_rules import AuditRule
from sniffer.analyze.stats import StatsAnalyzer
from sniffer.audit.events import AuditEvent
from sniffer.audit.trail import AuditTrail
from sniffer.decode.decoder import PacketDecoder
from sniffer.decode.packet import Packet
from sniffer.output.base import OutputPlugin
from sniffer.output.console import ConsoleOutput

log = logging.getLogger(__name__)


class PacketWorker(threading.Thread):
    """Processes captured raw packets from a bounded queue."""

    def __init__(
        self,
        packet_queue: queue.Queue[Any],
        decoder: PacketDecoder,
        analyzers: list[Any],
        rules: list[AuditRule],
        outputs: list[OutputPlugin],
        audit_trail: Optional[AuditTrail] = None,
        console_output: Optional[ConsoleOutput] = None,
    ) -> None:
        super().__init__(name="PacketWorkerThread")
        self.packet_queue = packet_queue
        self.decoder = decoder
        self.analyzers = analyzers
        self.rules = rules
        self.outputs = outputs
        self.audit_trail = audit_trail
        self.console_output = console_output

        self.processed_count = 0
        self.audit_event_count = 0
        self._stop_event = threading.Event()

    def run(self) -> None:
        """Worker consumption loop."""
        log.info("Worker thread started")
        while not self._stop_event.is_set():
            try:
                item = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if item is None:  # Sentinel value signaling end of capture
                self.packet_queue.task_done()
                break

            try:
                packet = self.decoder.decode(item)
                if packet is not None:
                    self._dispatch(packet)
                    self.processed_count += 1
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("Error processing packet: %s", exc)
            finally:
                self.packet_queue.task_done()

        # Drain any remaining packets after stop/sentinel
        while True:
            try:
                item = self.packet_queue.get_nowait()
                if item is None:
                    self.packet_queue.task_done()
                    break
                packet = self.decoder.decode(item)
                if packet is not None:
                    self._dispatch(packet)
                    self.processed_count += 1
                self.packet_queue.task_done()
            except queue.Empty:
                break
            except Exception:  # pylint: disable=broad-except
                self.packet_queue.task_done()

        log.info(
            "Worker thread terminated. Processed %d packets, generated %d audit events.",
            self.processed_count,
            self.audit_event_count,
        )

    def _dispatch(self, packet: Packet) -> None:
        # 1. Feed analyzers (e.g. StatsAnalyzer)
        for analyzer in self.analyzers:
            try:
                analyzer.handle(packet)
            except Exception as exc:
                log.debug("Analyzer %s error: %s", type(analyzer).__name__, exc)

        # 2. Evaluate audit rules
        for rule in self.rules:
            try:
                events = rule.analyze(packet)
                for event in events:
                    self._handle_audit_event(event)
            except Exception as exc:
                log.debug("Audit rule %s error: %s", type(rule).__name__, exc)

        # 3. Deliver to output plugins
        for output in self.outputs:
            try:
                output.handle(packet)
            except Exception as exc:
                log.debug("Output %s error: %s", type(output).__name__, exc)

    def _handle_audit_event(self, event: AuditEvent) -> None:
        self.audit_event_count += 1
        # Record into tamper-evident trail
        if self.audit_trail:
            try:
                self.audit_trail.append("event", event.to_dict())
            except Exception as exc:
                log.error("Failed to append event to audit trail: %s", exc)

        # Alert on console
        if self.console_output:
            self.console_output.print_event(event.rule, event.severity, event.message)

    def stop(self) -> None:
        """Signal worker to stop processing."""
        self._stop_event.set()
