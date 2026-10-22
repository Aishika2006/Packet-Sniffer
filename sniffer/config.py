"""Configuration handling: loads config.yaml and applies CLI overrides."""

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Any, Optional
import yaml

logger = logging.getLogger(__name__)


@dataclass
class CaptureConfig:
    """Capture runtime settings."""
    interface: Optional[str] = None
    bpf_filter: str = ""
    count: int = 0
    promisc: bool = True
    offline: Optional[str] = None


@dataclass
class ConsoleOutputConfig:
    """Console output settings."""
    enabled: bool = True
    colored: bool = True


@dataclass
class PcapOutputConfig:
    """PCAP output settings."""
    enabled: bool = False
    path: str = "captures/traffic.pcap"


@dataclass
class StorageOutputConfig:
    """Storage output settings."""
    enabled: bool = False
    type: str = "sqlite"  # 'sqlite' or 'csv'
    path: str = "captures/packets.db"


@dataclass
class OutputConfig:
    """Aggregated output configurations."""
    console: ConsoleOutputConfig = field(default_factory=ConsoleOutputConfig)
    pcap: PcapOutputConfig = field(default_factory=PcapOutputConfig)
    storage: StorageOutputConfig = field(default_factory=StorageOutputConfig)


@dataclass
class LoggingConfig:
    """Logging settings."""
    level: str = "INFO"


@dataclass
class AppConfig:
    """Root application configuration."""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(config_path: Optional[str | Path] = None, cli_args: Any = None) -> AppConfig:
    """
    Load configuration from YAML file and apply CLI overrides.

    Args:
        config_path: Path to YAML configuration file.
        cli_args: Parsed arguments from argparse (Namespace).

    Returns:
        AppConfig: Fully merged configuration object.
    """
    data: dict[str, Any] = {}

    target_path = Path(config_path) if config_path else Path("config.yaml")
    if target_path.is_file():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded
            logger.debug("Loaded configuration from %s", target_path)
        except Exception as e:
            logger.warning("Failed to parse config file %s: %s. Using defaults.", target_path, e)
    else:
        logger.debug("Config file %s not found. Using defaults.", target_path)

    raw_capture = data.get("capture", {}) or {}
    raw_output = data.get("output", {}) or {}
    raw_logging = data.get("logging", {}) or {}

    raw_console = raw_output.get("console", {}) or {}
    raw_pcap = raw_output.get("pcap", {}) or {}
    raw_storage = raw_output.get("storage", {}) or {}

    capture_cfg = CaptureConfig(
        interface=raw_capture.get("interface"),
        bpf_filter=raw_capture.get("bpf_filter", ""),
        count=int(raw_capture.get("count", 0)),
        promisc=bool(raw_capture.get("promisc", True)),
    )

    output_cfg = OutputConfig(
        console=ConsoleOutputConfig(
            enabled=bool(raw_console.get("enabled", True)),
            colored=bool(raw_console.get("colored", True)),
        ),
        pcap=PcapOutputConfig(
            enabled=bool(raw_pcap.get("enabled", False)),
            path=str(raw_pcap.get("path", "captures/traffic.pcap")),
        ),
        storage=StorageOutputConfig(
            enabled=bool(raw_storage.get("enabled", False)),
            type=str(raw_storage.get("type", "sqlite")),
            path=str(raw_storage.get("path", "captures/packets.db")),
        ),
    )

    logging_cfg = LoggingConfig(
        level=str(raw_logging.get("level", "INFO")),
    )

    config = AppConfig(
        capture=capture_cfg,
        output=output_cfg,
        logging=logging_cfg,
    )

    # Apply CLI argument overrides
    if cli_args is not None:
        if getattr(cli_args, "iface", None) is not None:
            config.capture.interface = cli_args.iface
        if getattr(cli_args, "filter", None) is not None:
            config.capture.bpf_filter = cli_args.filter
        if getattr(cli_args, "count", None) is not None:
            config.capture.count = cli_args.count
        if getattr(cli_args, "offline", None) is not None:
            config.capture.offline = cli_args.offline
        if getattr(cli_args, "out", None) is not None:
            config.output.pcap.enabled = True
            config.output.pcap.path = cli_args.out
        if getattr(cli_args, "db", None) is not None:
            config.output.storage.enabled = True
            config.output.storage.type = "sqlite"
            config.output.storage.path = cli_args.db
        if getattr(cli_args, "csv", None) is not None:
            config.output.storage.enabled = True
            config.output.storage.type = "csv"
            config.output.storage.path = cli_args.csv
        if getattr(cli_args, "verbose", False):
            config.logging.level = "DEBUG"
        if getattr(cli_args, "no_console", False):
            config.output.console.enabled = False

    return config
