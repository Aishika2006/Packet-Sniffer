"""Packet capture thread utilizing Scapy's sniffing capabilities."""

import logging
import threading
from typing import Any, Callable, List, Optional
import scapy.all as scapy
from scapy.all import conf

logger = logging.getLogger(__name__)


def get_available_interfaces() -> List[dict[str, str]]:
    """
    Query available network interfaces across platforms.

    Returns:
        List of dictionaries with interface metadata (name, description, ip, mac).
    """
    interfaces = []
    try:
        for key, iface in conf.ifaces.items():
            name = getattr(iface, "name", str(key))
            description = getattr(iface, "description", "")
            ip = getattr(iface, "ip", "")
            mac = getattr(iface, "mac", "")
            interfaces.append({
                "id": str(key),
                "name": name,
                "description": description,
                "ip": ip or "N/A",
                "mac": mac or "N/A",
            })
    except Exception as e:
        logger.warning("Could not enumerate network interfaces: %s", e)

    return interfaces


class PacketCapturer:
    """
    Dedicated packet sniffing engine running in an isolated background thread.

    Follows the zero-work callback pattern: it only captures raw packets
    and immediately pushes them to the provided consumer callback (e.g. Queue.put),
    preventing packet drops caused by expensive decoding or I/O.
    """

    def __init__(
        self,
        on_packet: Callable[[Any], None],
        interface: Optional[str] = None,
        bpf_filter: str = "",
        count: int = 0,
        promisc: bool = True,
        offline: Optional[str] = None,
    ):
        """
        Initialize the packet capturer.

        Args:
            on_packet: Callback invoked for each raw packet (e.g. queue.put).
            interface: Name or identifier of interface to listen on.
            bpf_filter: BPF syntax filter string (e.g. 'tcp port 443').
            count: Number of packets to capture before stopping (0 = unlimited).
            promisc: Whether to put the interface in promiscuous mode.
            offline: Optional path to .pcap file for offline replay/testing.
        """
        self.on_packet = on_packet
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()
        self.count = max(0, count)
        self.promisc = promisc
        self.offline = offline

        self.packets_captured: int = 0
        self.error: Optional[Exception] = None

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _packet_callback(self, raw_packet: Any) -> None:
        """
        Minimalistic callback: strictly increments counter and pushes to consumer.
        Zero decoding or printing is performed here.
        """
        self.packets_captured += 1
        try:
            self.on_packet(raw_packet)
        except Exception as e:
            logger.error("Error in on_packet consumer callback: %s", e)

    def _stop_filter(self, _: Any) -> bool:
        """Predicate checked by Scapy on each packet to stop capture."""
        return self._stop_event.is_set()

    def _run(self) -> None:
        """Worker loop executed in the background thread."""
        logger.debug(
            "Capturer thread started. Interface=%s, Filter='%s', Count=%d, Offline=%s",
            self.interface,
            self.bpf_filter,
            self.count,
            self.offline,
        )

        try:
            if self.offline:
                import os
                if not os.path.isfile(self.offline):
                    raise FileNotFoundError(f"Offline capture file not found: '{self.offline}'")

                # Replaying from pcap file using PcapReader for high efficiency and no external tcpdump requirement
                with scapy.PcapReader(self.offline) as pcap_reader:
                    for raw_pkt in pcap_reader:
                        if self._stop_event.is_set():
                            break
                        if self.count > 0 and self.packets_captured >= self.count:
                            break
                        self._packet_callback(raw_pkt)
            else:
                # Live network capture
                # Use slice timeouts to periodically evaluate stop_event even if no packets arrive
                while not self._stop_event.is_set():
                    remaining = (self.count - self.packets_captured) if self.count > 0 else 0
                    if self.count > 0 and remaining <= 0:
                        break

                    sniff_kwargs: dict[str, Any] = {
                        "prn": self._packet_callback,
                        "store": False,
                        "timeout": 1.0,
                        "stop_filter": self._stop_filter,
                        "promisc": self.promisc,
                    }
                    if self.interface:
                        sniff_kwargs["iface"] = self.interface
                    if self.bpf_filter:
                        sniff_kwargs["filter"] = self.bpf_filter
                    if self.count > 0:
                        sniff_kwargs["count"] = remaining

                    scapy.sniff(**sniff_kwargs)

        except FileNotFoundError as e:
            self.error = e
            logger.error("File error: %s. Please specify an existing .pcap file path.", e)
        except (PermissionError, OSError) as e:
            self.error = e
            logger.error(
                "Permission denied while capturing network packets: %s\n"
                "-> On Windows: Ensure Npcap is installed with 'WinPcap API-Compatible Mode' "
                "or run your terminal as Administrator.\n"
                "-> On Linux/macOS: Run with root privileges (sudo).",
                e,
            )
        except RuntimeError as e:
            self.error = e
            logger.error(
                "Capture runtime error: %s\n"
                "-> On Windows: Please install Npcap (https://npcap.com/) for raw packet capture.",
                e,
            )
        except scapy.error.Scapy_Exception as e:
            self.error = e
            logger.error(
                "Scapy capture error (BPF filter or interface issue): %s\n"
                "-> Note: BPF filtering requires libpcap (Npcap on Windows, libpcap-dev on Linux).",
                e,
            )
        except Exception as e:
            self.error = e
            logger.error("Unexpected error during packet capture: %s", e, exc_info=True)
        finally:
            logger.debug("Capturer thread exiting. Total packets captured: %d", self.packets_captured)

    def start(self) -> None:
        """Start the background sniffing thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("PacketCapturer is already running.")
            return

        self._stop_event.clear()
        self.error = None
        self._thread = threading.Thread(target=self._run, name="PacketCapturerThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture loop to stop."""
        self._stop_event.set()

    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for the capture thread to terminate."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        """Check whether the capture thread is currently active."""
        return self._thread is not None and self._thread.is_alive()
