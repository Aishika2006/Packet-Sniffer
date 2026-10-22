"""Logging utilities for the packet sniffer."""

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """
    Configure the root logger with a standardized format.

    Args:
        level: Log level string (e.g. 'DEBUG', 'INFO', 'WARNING', 'ERROR').
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Reset any existing handlers to prevent duplicates
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not root_logger.handlers:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(numeric_level)
        formatter = logging.Formatter(log_format, date_format)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(numeric_level)
