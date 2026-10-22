"""Packet capturer — separate thread capturing raw packets via Scapy into a bounded queue.

CRITICAL DESIGN RULE:
The packet callback does ZERO decoding, parsing, formatting, or printing.
It only puts raw packets into a bounded queue.
If the queue is full, it drops the packet and increments a drop counter.
"""

from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path
from typing import Any, Optional

import scapy.all as scapy

log = logging.getLogger(__name__)


def list_interfaces() -> list[dict[str, str]]:
    """Return available network interfaces with names and IP addresses."""
    results: list[dict[str, str]] = []
    try:
        ifaces = scapy.get_if_list()
        for iface in ifaces:
            ip = ""
            try:
                ip = scapy.get_if_addr(iface)
            except Exception:
                ip = "unknown"
            results.append({"name": str(iface), "ip": str(ip)})
    except Exception as exc:
        log.warning("Could not enumerate network interfaces: %s", exc)
    return results


class PacketCapturer(threading.Thread):
    """Captures live or offline packets on a background thread into a bounded queue."""

    def __init__(
        self,
        packet_queue: queue.Queue[Any],
        interface: Optional[str] = None,
        bpf_filter: str = "",
        count: int = 0,
        promisc: bool = True,
        offline: Optional[str | Path] = None,
    ) -> None:
        super().__init__(name="PacketCapturerThread", daemon=True)
        self.packet_queue = packet_queue
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.promisc = promisc
        self.offline = str(offline) if offline else None

        self.dropped_packets = 0
        self.captured_packets = 0
        self._stop_event = threading.Event()

    def run(self) -> None:
        """Capture loop executed on background thread."""
        log.info(
            "Capturer started (mode: %s, filter: '%s', iface: %s)",
            f"offline '{self.offline}'" if self.offline else "live",
            self.bpf_filter,
            self.interface or "default",
        )

        def _packet_callback(raw_pkt: Any) -> None:
            self.captured_packets += 1
            try:
                self.packet_queue.put_nowait(raw_pkt)
            except queue.Full:
                self.dropped_packets += 1

        def _stop_filter(_: Any) -> bool:
            return self._stop_event.is_set()

        try:
            if self.offline:
                scapy.sniff(
                    offline=self.offline,
                    filter=self.bpf_filter if self.bpf_filter else None,
                    prn=_packet_callback,
                    count=self.count,
                    stop_filter=_stop_filter,
                    store=False,
                )
            else:
                scapy.sniff(
                    iface=self.interface,
                    filter=self.bpf_filter if self.bpf_filter else None,
                    prn=_packet_callback,
                    count=self.count,
                    promisc=self.promisc,
                    stop_filter=_stop_filter,
                    store=False,
                )
        except Exception as exc:
            log.error("Fatal capture error: %s", exc)
        finally:
            log.info(
                "Capturer finished. Captured: %d, Dropped: %d",
                self.captured_packets,
                self.dropped_packets,
            )

    def stop(self) -> None:
        """Signal capturer thread to stop."""
        self._stop_event.set()
