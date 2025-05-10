# Network Packet Analyzer

A Python-based network packet analyzer tool that captures and analyzes network packets in real-time. This tool is designed for educational purposes to understand network traffic patterns and packet structures.

## Features

- Real-time packet capture and analysis
- Display of source and destination IP addresses
- Protocol identification (TCP, UDP, ICMP)
- Port number tracking
- Colored console output for better readability
- Automatic logging of captured packets to file
- Protocol filtering (TCP, UDP, ICMP)
- Payload display (optional)
- CSV log file output

## Requirements

- Python 3.6 or higher
- Required Python packages (install using `pip install -r requirements.txt`):
  - scapy
  - colorama
  - python-dateutil
- **Npcap** (for Windows) or **libpcap** (for Linux/Mac) must be installed to capture packets.

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. **Install Npcap (Windows):**
   - Download the latest Npcap installer from [https://nmap.org/npcap/](https://nmap.org/npcap/)
   - Run the installer and check "Install Npcap in WinPcap API-compatible Mode"
   - Restart your terminal after installation

## Usage

Run the packet analyzer with default settings:
```bash
python packet_analyzer.py
```

Specify a network interface:
```bash
python packet_analyzer.py --interface eth0
```

Filter by protocol (TCP, UDP, ICMP):
```bash
python packet_analyzer.py --protocol tcp
```

Display packet payloads:
```bash
python packet_analyzer.py --show-payload
```

Specify a custom log file:
```bash
python packet_analyzer.py --log-file mylog.csv
```

## Output

The tool provides real-time packet information including:
- Source and destination IP addresses
- Protocol type
- Source and destination ports
- Packet count
- Payload (if enabled)

All captured packets are also logged to a CSV file (default: `packet_log.csv`) for later analysis.

## Important Notes

- This tool requires administrative/root privileges to capture packets
- Use responsibly and only on networks you own or have permission to analyze
- For educational purposes only

## License

This project is licensed under the MIT License - see the LICENSE file for details. 