"""Configuration loader, validator, and privacy/retention enforcement."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "capture": {
        "interface": None,
        "bpf_filter": "",
        "count": 0,
        "duration": 0,
        "promisc": True,
        "queue_maxsize": 10000,
        "offline": None,
    },
    "audit": {
        "rules": {
            "cleartext_protocols": {
                "enabled": True,
                "severity": "HIGH",
                "ports": [21, 23, 25, 80, 110, 143],
            },
            "deprecated_tls": {
                "enabled": True,
                "severity": "HIGH",
                "flagged_versions": ["SSL 3.0", "TLS 1.0", "TLS 1.1"],
            },
            "allowlist": {
                "enabled": False,
                "severity": "MEDIUM",
                "allowed_hosts": [],
                "allowed_ports": [],
            },
            "dns_anomaly": {
                "enabled": True,
                "severity": "MEDIUM",
                "nxdomain_rate_threshold": 10,
                "long_name_threshold": 50,
                "high_entropy_threshold": 4.0,
            },
            "port_scan": {
                "enabled": True,
                "severity": "HIGH",
                "distinct_ports_threshold": 15,
                "window_seconds": 10.0,
            },
            "volume_anomaly": {
                "enabled": True,
                "severity": "MEDIUM",
                "bytes_per_minute_threshold": 10485760,
            },
            "cleartext_credentials": {
                "enabled": True,
                "severity": "CRITICAL",
                "patterns": ["Authorization", "password", "passwd", "token", "api_key"],
            },
        }
    },
    "output": {
        "console": {"enabled": True, "colored": True},
        "pcap": {"enabled": False, "path": "captures/audit.pcap"},
        "storage": {"enabled": True, "type": "sqlite", "path": "captures/packets.db"},
    },
    "audit_trail": {
        "path": "reports/audit_trail.jsonl",
        "operator": "",
    },
    "privacy": {
        "log_payload": False,
        "redact_headers": True,
        "retention_days": 30,
    },
    "report": {
        "out_dir": "reports",
        "format": "markdown",
    },
    "logging": {
        "level": "INFO",
    },
}


def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge source into target."""
    for key, val in source.items():
        if isinstance(val, dict) and key in target and isinstance(target[key], dict):
            target[key] = _deep_merge(target[key], val)
        else:
            target[key] = val
    return target


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration file and merge with defaults."""
    import copy
    cfg = copy.deepcopy(DEFAULT_CONFIG)

    if config_path:
        path = Path(config_path)
        if path.is_file():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    user_cfg = yaml.safe_load(fh)
                    if isinstance(user_cfg, dict):
                        _deep_merge(cfg, user_cfg)
                        log.info("Loaded configuration from %s", path)
            except Exception as exc:
                log.warning("Could not read config file %s: %s (using defaults)", path, exc)
        else:
            log.warning("Config file not found: %s (using defaults)", path)

    # Privacy safety audit: warn if log_payload is enabled
    if cfg.get("privacy", {}).get("log_payload", False):
        log.warning(
            "PRIVACY ALERT: 'privacy.log_payload' is ENABLED. Raw application payloads "
            "will be captured and stored in local outputs. Sensitive data risk."
        )

    return cfg


def enforce_data_retention(retention_days: int, directories: list[str | Path]) -> int:
    """Delete files older than *retention_days* in specified directories.

    Args:
        retention_days: Number of days to retain files (0 = unlimited).
        directories: List of directories to clean up.

    Returns:
        Number of purged files.
    """
    if retention_days <= 0:
        return 0

    cutoff_seconds = time.time() - (retention_days * 86400)
    purged_count = 0

    for d in directories:
        dir_path = Path(d)
        if not dir_path.is_dir():
            continue
        for file_path in dir_path.glob("*"):
            if not file_path.is_file():
                continue
            try:
                mtime = file_path.stat().st_mtime
                if mtime < cutoff_seconds:
                    file_path.unlink()
                    purged_count += 1
                    log.info("Data retention: deleted expired file %s", file_path)
            except Exception as exc:
                log.debug("Error checking retention for %s: %s", file_path, exc)

    return purged_count
