"""Logging configuration for the audit tool."""

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """Configure the root logger with a standardised format.

    Args:
        level: String log level: DEBUG, INFO, WARNING, ERROR.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        root.addHandler(handler)
    else:
        for h in root.handlers:
            h.setLevel(numeric_level)


# Suppress verbose Scapy import-time noise
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
