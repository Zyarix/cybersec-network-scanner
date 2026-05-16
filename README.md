NetRecon
Modular Network Reconnaissance Tool
A fast, multi-threaded network reconnaissance tool built in Python. Performs port scanning, ARP host discovery, banner grabbing, OS fingerprinting, and vulnerability checking — all from a clean command-line interface with rich formatted output.
Built to demonstrate core offensive security concepts, Python networking fundamentals, and concurrent performance optimisation.

Features
Port Scanning

Multi-threaded TCP connect scanning for speed
Custom port ranges (1-1000, 80,443,8080, etc.)
Adjustable thread count to tune performance vs. noise

ARP Host Discovery

Identifies all active hosts on a local network
Returns IP and MAC addresses for each discovered device
Useful for network topology mapping and pre-engagement reconnaissance

Banner Grabbing

Extracts service banners from open ports
Identifies running services and version strings without sending exploit traffic

OS Fingerprinting

Lightweight OS detection using TTL and TCP window-size heuristics
Confidence scoring on each result
Covers Windows, Linux, routers, and IoT devices

Vulnerability Checking

Matches detected banners against a known-vulnerabilities database
Flags potentially vulnerable services with CVE references
Designed to surface low-hanging fruit quickly during early-stage recon

Rich Output

Colour-coded tables via the rich library
Optional JSON and HTML report export for documentation


Installation
Prerequisites

Python 3.7+
Root/Administrator privileges for ARP scanning and OS fingerprinting

Setup
bashgit clone https://github.com/Zyarix/netrecon.git
cd netrecon
pip install -r requirements.txt
Requirements
rich>=13.0.0
scapy>=2.5.0

Usage
bash# Basic port scan
sudo python recon.py --target 192.168.1.1 --ports 1-1000

# ARP discovery on local network
sudo python recon.py --arp 192.168.1.0/24

# Full scan with banner grabbing and OS fingerprinting
sudo python recon.py --target 192.168.1.1 --ports 1-1000 --banners --os

# Export results
sudo python recon.py --target 192.168.1.1 --ports 1-1000 --output report.html

Output Example
┌─────────────────────────────────────────────┐
│           NetRecon — Scan Results           │
├──────┬──────────┬─────────┬────────────────┤
│ Port │ Status   │ Service │ Banner         │
├──────┼──────────┼─────────┼────────────────┤
│ 22   │ OPEN     │ SSH     │ OpenSSH 7.4    │
│ 80   │ OPEN     │ HTTP    │ Apache/2.4.6   │
│ 443  │ OPEN     │ HTTPS   │ nginx/1.14.0   │
│ 3306 │ OPEN     │ MySQL   │ 5.6.44 [CVE]   │
└──────┴──────────┴─────────┴────────────────┘

OS Fingerprint: Linux (confidence: 87%)
Vulnerabilities flagged: 1
  → MySQL 5.6.44 — CVE-2019-2687 (Medium)

Project Structure
netrecon/
├── recon.py              # Entry point and CLI argument handling
├── scanner.py            # Multi-threaded port scanner
├── arp.py                # ARP host discovery
├── banner.py             # Banner grabbing
├── fingerprint.py        # OS fingerprinting via TTL/window heuristics
├── vuln_check.py         # Vulnerability database and matching
├── output.py             # Rich table rendering and report export
└── requirements.txt

Notes
TopicDetailPermissionsARP scanning and OS fingerprinting require root/admin privilegesPerformanceIncrease --threads for faster scans; decrease on congested networksAccuracyOS fingerprinting accuracy varies with network conditions and target configVuln DatabaseCovers common CVEs — not a replacement for a full vulnerability scanner

Legal
This tool is intended for use on networks and systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions. The author accepts no responsibility for misuse.

License
MIT License — see LICENSE for details.

Author
Ismail Jonkunda Ceesay — github.com/Zyarix
