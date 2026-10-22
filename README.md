# Modular Packet Sniffer

A modular, multi-threaded network packet sniffer and traffic analyzer written in Python 3.10+ using Scapy.

Designed for network diagnostics, security monitoring, and educational traffic analysis on networks you own or are authorized to inspect.

---

## Architecture (Layered Pipeline)

```
+--------------------+
| Network Interface  | (or Offline PCAP replay)
+---------+----------+
          |
          v
+---------+----------+
|   PacketCapturer   | Background thread (zero-work capture loop)
+---------+----------+
          |
          v
+---------+----------+
|    queue.Queue     | Thread-safe buffer (prevents dropped packets)
+---------+----------+
          |
          v
+---------+----------+
|    PacketWorker    | Dedicated consumer thread
+---------+----------+
          |
          v
+---------+----------+
|   PacketDecoder    | Transforms raw frames -> Packet dataclass
| (DNS, HTTP, TLS)   | (Decoupled from Scapy types)
+---------+----------+
          |
    +-----+-----+
    |           |
    v           v
+---+-----+   +-+--------------------------------------------+
| Analyzers|   | Output Plugins                               |
+---+-----+   +----------------------------------------------+
| * Stats |   | * ConsoleOutput (live formatted stream)      |
| * Ports |   | * PcapWriterOutput (saves to .pcap)          |
+---------+   | * SQLiteStorageOutput (indexed query DB)     |
              | * CSVStorageOutput (structured CSV export)   |
              +----------------------------------------------+
```

### Core Design Principles
1. **Zero-Work Sniffing Loop**: The capture thread strictly grabs raw packets and pushes them to a thread-safe queue. No decoding, terminal I/O, or disk operations occur in the capture callback, preventing packet drops during high-throughput bursts.
2. **Decoupled Dataclass Pipeline**: All downstream analyzers, detectors, and output plugins interact exclusively with the `Packet` dataclass and have zero dependency on Scapy internals.
3. **Graceful Ctrl+C Shutdown**: When interrupted, capture terminates, the worker drains all remaining queued packets, output buffers are flushed, and an aggregated traffic summary report is printed.

---

## Installation & Setup

### 1. Prerequisites

#### Windows
- Install [Npcap](https://npcap.com/) (required for live raw packet capture).
- During installation, make sure to check: **"Install Npcap in WinPcap API-Compatible Mode"**.
- *Note*: Offline replay (`--offline sample.pcap`) and running the test suite work 100% without Npcap or administrator privileges!

#### Linux
```bash
sudo apt-get update
sudo apt-get install -y python3-dev libpcap-dev
```

#### macOS
- Standard BSD packet filter (`/dev/bpf*`) is built-in. Run with `sudo` for live interfaces.

### 2. Python Environment & Dependencies

```bash
# Clone or navigate to the repository
cd packet-sniffer

# Install dependencies
pip install -r requirements.txt

# Or install as editable CLI command
pip install -e .
```

---

## Usage Examples

### 1. Discover Network Interfaces
List all available network adapters with their IP addresses, MAC addresses, and descriptions:
```bash
python -m sniffer.main --list-interfaces
```

### 2. Replay Offline PCAP (No Root / No Live Traffic Needed)
Test and analyze pre-recorded packet captures:
```bash
python -m sniffer.main --offline tests/samples/sample.pcap
```

### 3. Live Capture with BPF Filters
Capture live HTTP traffic on a specific interface:
```bash
# Windows (run terminal as Administrator if using raw sockets)
python -m sniffer.main --iface "Wi-Fi" --filter "tcp port 80" --count 50

# Linux / macOS
sudo python -m sniffer.main -i eth0 -f "tcp port 443 or udp port 53" -c 100
```

### 4. Save Captured Traffic to .pcap
Export captured frames to standard `.pcap` format for Wireshark inspection:
```bash
python -m sniffer.main --offline sample.pcap --out captures/traffic.pcap
```

### 5. Persistent Database & CSV Logging
Log decoded packets and structured metadata to SQLite or CSV:
```bash
# SQLite indexed database
python -m sniffer.main --offline sample.pcap --db captures/packets.db

# CSV export
python -m sniffer.main --offline sample.pcap --csv captures/packets.csv
```

### 6. Query SQLite Database
```bash
sqlite3 captures/packets.db "SELECT formatted_time, src_ip, dst_ip, protocol, info FROM packets LIMIT 10;"
```

---

## Configuration File (`config.yaml`)

Settings can be managed centrally via `config.yaml`. Any CLI argument will override config settings:

```yaml
capture:
  interface: null          # null uses default interface
  bpf_filter: ""          # e.g. "tcp port 80 or udp port 53"
  count: 0                 # 0 captures indefinitely until Ctrl+C
  promisc: true            # Enable promiscuous mode

output:
  console:
    enabled: true
    colored: true
  pcap:
    enabled: false
    path: "captures/traffic.pcap"
  storage:
    enabled: false
    type: "sqlite"         # Options: "sqlite", "csv"
    path: "captures/packets.db"

logging:
  level: "INFO"
```

---

## Running the Test Suite

The test suite runs against `tests/samples/sample.pcap` using `rdpcap` and requires **zero root privileges and zero live network traffic**:

```bash
pytest tests -v
```

**Test Coverage:**
- `tests/test_decoder.py`: Validates Layer 3 (IP, IPv6, ARP), Layer 4 (TCP flags, UDP, ICMP), DNS queries/answers, HTTP requests/responses, and TLS metadata.
- `tests/test_stats.py`: Tests counter aggregation across hosts, protocols, ports, and formatted summary generation.
- `tests/test_storage_outputs.py`: Validates PCAP writing/re-reading, SQLite table queries, CSV rows, PortScanDetector, and worker queue draining.

---

## Legal & Ethical Use Notice

> [!WARNING]
> **Authorized Use Only**
> This tool is developed strictly for educational purposes, authorized security auditing, and network diagnostics on systems and networks you own or have explicit written authorization to monitor.
>
> Intercepting, capturing, or analyzing network traffic without authorization may violate local, national, or international computer crime and privacy laws (e.g. 18 U.S. Code § 2511 in the United States, Computer Misuse Act in the UK, and equivalent privacy legislation globally). Always obtain appropriate permission before capturing network packets.
