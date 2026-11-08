# HM NetSentry

HM NetSentry is a local-first network telemetry and security analysis toolkit by HM Studios. It captures passive network metadata on Windows, turns it into flows and device observations, and presents evidence-backed analysis through a CLI and a lightweight web dashboard.

It is intended for authorised monitoring of networks you own or are explicitly permitted to administer. It does not perform vulnerability scanning, active probing, exploit activity, or packet-payload retention.

## What it does

- Captures live traffic using Scapy and Npcap on a selected Windows interface.
- Aggregates packets into five-tuple flow records rather than storing every packet.
- Discovers observed devices, MAC addresses, local OUI vendors, hostnames when observable, and inferred device types.
- Classifies common protocols from packet structure and behaviour, including ARP, IP, TCP, UDP, DNS, DHCP, HTTP, TLS, SSH, SMB, mDNS, SSDP, QUIC, and ICMP.
- Stores telemetry, DNS events, alert evidence, topology snapshots, baseline profiles, attack-path observations, and reports in a local SQLite database.
- Provides basic anomaly signals: unusual observed ports, high-frequency sources, new external destinations, DNS anomalies, and baseline deviations.
- Generates topology data, attack-path observations, JSON/text/HTML reports, and a browser dashboard.
- Supports evidence-based local chat with Ollama (`qwen2.5:3b`); no cloud API key is required.

## Architecture

```text
Npcap / Scapy capture
        |
        v
Packet normalisation -> protocol classification -> flow & device aggregation
        |                                               |
        +-------------------- SQLite -------------------+
                                |
                CLI | Web dashboard | Local Ollama chat | Reports
```

The capture pipeline is independent of the language-model layer. Ollama is used only to interpret supported questions; answers are produced from locally observed SQLite evidence.

## Requirements

- Windows with Python 3.11 or newer.
- [Npcap](https://npcap.com/) installed with **WinPcap API-compatible mode** enabled.
- Administrator privileges or permission to capture on the selected interface.
- Python dependency: Scapy.
- Optional for natural-language chat: [Ollama](https://ollama.com/) with `qwen2.5:3b` pulled locally.

## Installation

```powershell
git clone https://github.com/Harismehd/hm-netsentry.git
cd hm-netsentry
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

For local chat support:

```powershell
ollama pull qwen2.5:3b
```

Copy `.env.example` to `.env` only if you need to override the local Ollama host or model. The application runs with the built-in local defaults otherwise.

## Quick start

Initialise the local database and list capture interfaces:

```powershell
python run.py init-db
python run.py interfaces
```

Capture for 30 seconds using an interface returned by `interfaces`:

```powershell
python run.py capture --interface "Ethernet" --duration 30
```

Review collected evidence:

```powershell
python run.py status
python run.py devices
python run.py flows
python run.py stats
python run.py fingerprint
python run.py topology --ascii
python run.py attack-paths
```

## Analysis and reporting

```powershell
# Learn or assess behavioural baselines from local history
python run.py baseline learn
python run.py baseline detect
python run.py baseline --device 192.168.1.10

# Generate a local report under reports/
python run.py report --format html

# Start the local dashboard
python run.py web
```

The dashboard binds to `127.0.0.1:8000` by default. It reads the same local SQLite database used by the CLI. The optional chart/topology browser libraries are loaded from a CDN; telemetry itself remains local.

## Evidence-based chat

```powershell
python run.py chat
python run.py chat "show all devices"
python run.py chat "which device has most traffic"
python run.py chat "investigate IP 192.168.1.10"
python run.py chat --interface "Ethernet" --duration 10 "analyze my network"
```

Supported questions are routed to local analysis functions and SQL-backed evidence. Type `exit` to leave interactive chat.

## Data handling and limitations

- The application deliberately avoids retaining raw packet payloads in SQLite.
- MAC addresses are only directly visible for devices observable on the same Layer-2 segment.
- Vendor and device-type values are inferences based on locally available OUI and observed behaviour; they are not identity assertions.
- Protocol labels are evidence-based classifications, not proof of application ownership.
- Alerts and attack paths are prioritisation signals, not confirmed compromise or vulnerability findings.
- Capture results depend on interface selection, operating-system privileges, Npcap, network topology, and actual traffic.

The `data/` and `reports/` directories are intentionally ignored by Git because they may contain network-specific telemetry and generated evidence.

## Development

Run the test suite without relying on live network traffic:

```powershell
python -m unittest discover -s tests -v
```

The project includes unit tests for telemetry aggregation, protocol classification, device tracking, persistence, behavioural baselines, attack-path generation, and reporting. Live capture is an integration activity and requires a suitable local Npcap environment.

## Project status

HM NetSentry is an actively developed V1 project. The current focus is reliable local telemetry, clear evidence presentation, and a maintainable foundation for future security-analysis work.

## License

This project is released under the [MIT License](LICENSE).
