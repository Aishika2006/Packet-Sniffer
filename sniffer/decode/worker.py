"""Worker thread that pulls raw packets from queue, decodes them, and dispatches to handlers."""

import logging
import queue
import threading
from typing import Any, Callable, List, Optional

from sniffer.decode.decoder import PacketDecoder
from sniffer.decode.packet import Packet

logger = logging.getLogger(__name__)

# Unique sentinel indicating queue termination
STOP_SENTINEL = object()


class PacketWorker(threading.Thread):
    """
    Dedicated worker thread decoupling capture from packet decoding and downstream I/O.

    Consumes raw packets from a thread-safe Queue, transforms them into
    standalone Packet dataclasses using PacketDecoder, and dispatches each
    Packet to registered analyzer and output handlers.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        decoder: Optional[PacketDecoder] = None,
        handlers: Optional[List[Callable[[Packet], None]]] = None,
        name: str = "PacketWorkerThread",
    ) -> None:
        """
        Initialize the worker thread.

        Args:
            packet_queue: Thread-safe queue containing raw packets from capturer.
            decoder: PacketDecoder instance (defaults to a new PacketDecoder).
            handlers: Callables accepting a Packet (e.g. output.handle, analyzer.handle).
            name: Thread name for debugging and logging.
        """
        super().__init__(name=name, daemon=True)
        self.packet_queue = packet_queue
        self.decoder = decoder or PacketDecoder()
        self.handlers: List[Callable[[Packet], None]] = list(handlers or [])

        self.packets_processed: int = 0
        self.packets_decoded: int = 0
        self.decode_errors: int = 0

        self._stop_requested = threading.Event()

    def add_handler(self, handler: Callable[[Packet], None]) -> None:
        """Register a new downstream packet handler."""
        self.handlers.append(handler)

    def run(self) -> None:
        """Main worker loop: pulls packets until sentinel is encountered."""
        logger.debug("PacketWorker thread started.")

        while True:
            try:
                item = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                if self._stop_requested.is_set():
                    break
                continue

            if item is STOP_SENTINEL:
                self.packet_queue.task_done()
                logger.debug("Stop sentinel received. Draining completed.")
                break

            self.packets_processed += 1
            try:
                packet = self.decoder.decode(item)
                if packet is not None:
                    self.packets_decoded += 1
                    self._dispatch(packet)
                else:
                    self.decode_errors += 1
            except Exception as e:
                self.decode_errors += 1
                logger.error("Unexpected error in worker processing packet: %s", e, exc_info=True)
            finally:
                self.packet_queue.task_done()

        logger.debug(
            "PacketWorker exiting. Processed: %d, Decoded: %d, Errors: %d",
            self.packets_processed,
            self.packets_decoded,
            self.decode_errors,
        )

    def _dispatch(self, packet: Packet) -> None:
        """Send decoded packet to all registered handlers."""
        for handler in self.handlers:
            try:
                handler(packet)
            except Exception as e:
                logger.error("Handler %s raised an exception: %s", handler, e, exc_info=True)

    def stop(self) -> None:
        """Signal the worker to stop by pushing the stop sentinel."""
        self._stop_requested.set()
        try:
            self.packet_queue.put_nowait(STOP_SENTINEL)
        except queue.Full:
            # If queue is completely full, put with short timeout
            try:
                self.packet_queue.put(STOP_SENTINEL, timeout=1.0)
            except queue.Full:
                logger.warning("Queue full when pushing stop sentinel.")
