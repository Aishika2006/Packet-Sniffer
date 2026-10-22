# packet-audit

A modular, passive network traffic auditing and security assessment tool in Python 3.10+ using Scapy.

> **CRITICAL LEGAL NOTICE**
> This tool is strictly designed for passive monitoring and auditing on network infrastructure and systems that you **own** or have **explicit, written authorization** to monitor. Unauthorized network interception, packet sniffing, or wiretapping is a crime under applicable laws (e.g. 18 U.S.C. § 2511, Computer Misuse Act).

---

## Architecture

```text
Network Interface / .pcap
         │
         ▼
  [PacketCapturer] (zero-work callback thread)
         │
         ▼ (bounded queue.Queue)
   [PacketWorker] (background pipeline thread)
         │
         ├─► [PacketDecoder] ──► Decoupled Packet dataclass
         │         │
         │         ├─► DNSParser (queries, answers, Shannon entropy)
         │         ├─► HTTPParser (methods, headers, redaction)
         │         └─► TLSParser (SNI, versions, record headers)
         │
         ├─► [AuditRules] (7 configurable detection rules)
         │         │
         │         └─► [AuditTrail] (SHA-256 hash-chained tamper-evident JSONL)
         │
         ├─► [StatsAnalyzer] (Top talkers, protocols, bytes)
         │
         └─► [OutputPlugins]
                   ├─► ConsoleOutput (real-time stream + alerts)
                   ├─► PcapWriterOutput (.pcap capture)
                   └─► SQLite / CSV Storage (metadata persistence)
```

---

## Key Features

1. **Passive Only**: Zero traffic injection, ARP spoofing, or packet modification.
2. **Decoupled Architecture**: All analyzers and outputs consume the standalone `Packet` dataclass and never depend on Scapy types.
3. **Bounded Zero-Work Capture**: Capture callback performs zero decoding or string formatting. Packets are dropped with counted drops if the worker queue fills up.
4. **Privacy & Integrity by Design**:
   - Metadata-only logging by default.
   - Raw payload logging requires explicit `--log-payload` flag and logs a warning.
   - `Authorization` headers, `Cookie`, and credentials are redacted to `<REDACTED>` before storage.
   - Password and credential values are **never stored**; only occurrence and endpoint are recorded.
   - Cryptographic SHA-256 hash-chained audit trail (`reports/audit_trail.jsonl`) guarantees append-only integrity with tamper verification (`verify` command).
   - Automated data retention policy cleans up captures and reports older than `retention_days`.
5. **Configurable Audit Rules**:
   - Cleartext protocols (HTTP, FTP, Telnet, SMTP, POP3, IMAP).
   - Deprecated TLS versions (SSL 3.0, TLS 1.0, TLS 1.1).
   - IP and destination port allowlisting / network boundaries.
   - DNS anomalies (NXDOMAIN flood, long queries, high Shannon entropy / DGA).
   - Port scan detection (distinct destination ports in sliding time window).
   - Volume anomalies (bytes-per-minute threshold per host).
   - Cleartext credentials scanner.
6. **Reporting**: Automatic generation of Markdown and HTML executive audit reports.

---

## Installation

```bash
# Clone repository and enter directory
cd packet-audit

# Install dependencies
pip install -r requirements.txt
```

*Note on Windows:* Live network packet capture requires [Npcap](https://npcap.com/) installed with "WinPcap API-compatible mode". Offline `.pcap` analysis works without Npcap.

---

## Usage

### 1. List Available Network Interfaces
```bash
python -m sniffer.main list-interfaces
```

### 2. Live Capture & Real-Time Audit
```bash
# Basic capture with default interface
python -m sniffer.main capture

# Capture on interface 'eth0', filter for HTTP/TLS, limit to 500 packets
python -m sniffer.main capture -i eth0 -f "tcp port 80 or tcp port 443" -c 500

# Capture with SQLite metadata storage and pcap output
python -m sniffer.main capture -i eth0 --db captures/audit.db -w captures/live.pcap
```

### 3. Audit an Existing PCAP File
```bash
python -m sniffer.main audit tests/samples/sample.pcap --operator "Auditor_01" --report-format html
```

### 4. Verify Cryptographic Integrity of Audit Trail
```bash
python -m sniffer.main verify reports/audit_trail.jsonl
```

### 5. Generate Audit Report
```bash
# Generate Markdown report
python -m sniffer.main report reports/audit_trail.jsonl -o reports --format markdown

# Generate HTML report
python -m sniffer.main report reports/audit_trail.jsonl -o reports --format html
```

---

## Running Test Suite

```bash
python -m pytest tests -v
```
