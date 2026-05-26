# NetRecon
### Modular Network Reconnaissance Tool

A fast, multi-threaded network reconnaissance tool built in Python. Performs port scanning, ARP host discovery, banner grabbing, OS fingerprinting, and vulnerability checking — all from a clean command-line interface with rich formatted output.

Built to demonstrate core offensive security concepts, Python networking fundamentals, and concurrent performance optimisation.

---

## Features

### Port Scanning
- Multi-threaded TCP connect scanning for speed
- Custom port ranges (`1-1000`, `80,443,8080`, etc.)
- Adjustable thread count to tune performance vs. noise

### ARP Host Discovery
- Identifies all active hosts on a local network
- Returns IP and MAC addresses with vendor lookup for each discovered device
- Supports automatic port scanning of all discovered hosts via `--scan-hosts`

### Banner Grabbing
- Extracts service banners from open ports
- Identifies running services and version strings without sending exploit traffic
- Handles HTTP, FTP, SSH, SMTP, MySQL, PostgreSQL, and more

### OS Fingerprinting
- OS detection using TTL normalisation and TCP window-size heuristics
- Accounts for network hops when normalising TTL values
- Confidence scoring on each result
- Covers Windows 10/11, Windows Server, Linux, macOS, and IoT devices

### Vulnerability Checking
- Matches detected banners against a built-in CVE database
- Flags potentially vulnerable services with CVE references and descriptions
- Covers OpenSSH, Apache, nginx, vsftpd, and more

### Rich Output
- Colour-coded tables via the `rich` library with graceful fallback for Windows
- Optional JSON and HTML report export for documentation

---

## Installation

**Prerequisites:** Python 3.7+ and root/Administrator privileges for ARP scanning and OS fingerprinting.

```
git clone https://github.com/Zyarix/netrecon.git
cd netrecon
pip install -r requirements.txt
```

**Requirements:**
```
rich>=13.0.0
scapy>=2.5.0
```

---

## Usage

Basic port scan:
```
python recon.py 192.168.1.1 --ports 1-1000
```

Port scan with banner grabbing and vulnerability check:
```
python recon.py 192.168.1.1 --ports 1-1000 --banner --vuln
```

Full scan with OS fingerprinting:
```
python recon.py 192.168.1.1 --ports 80,443,8080 --banner --os --vuln
```

ARP discovery on local network:
```
sudo python recon.py --arp 192.168.1.0/24
```

ARP discovery then port scan all discovered hosts:
```
sudo python recon.py --arp 192.168.1.0/24 --scan-hosts --banner --vuln
```

Export results:
```
python recon.py 192.168.1.1 --ports 1-1000 --banner --vuln --export-json results.json
python recon.py 192.168.1.1 --ports 1-1000 --banner --vuln --export-html results.html
```

---

## Output Example

```
+------+----------+---------+----------------+
| Port | Status   | Service | Banner         |
+------+----------+---------+----------------+
| 22   | OPEN     | SSH     | OpenSSH 7.4    |
| 80   | OPEN     | HTTP    | Apache/2.4.6   |
| 443  | OPEN     | HTTPS   | nginx/1.14.0   |
| 3306 | OPEN     | MySQL   | 5.6.44 [CVE]   |
+------+----------+---------+----------------+

OS Fingerprint: Linux (confidence score: 7)
Vulnerabilities flagged: 1
  -> MySQL 5.6.44 — CVE-2019-2687 (Medium)
```

---

## Project Structure

```
netrecon/
├── recon.py          All scanning logic, CLI, and output formatting
└── requirements.txt
```

---

## Arguments

| Argument | Description |
|----------|-------------|
| `target` | Target IP address or hostname |
| `--ports`, `-p` | Port range e.g. `1-1000` or `80,443,8080` (default: `1-1024`) |
| `--threads`, `-t` | Number of threads (default: 200) |
| `--banner`, `-b` | Grab service banners |
| `--os` | Perform OS fingerprinting (requires Scapy) |
| `--vuln` | Check banners against vulnerability database |
| `--arp` | ARP scan a network e.g. `192.168.1.0/24` |
| `--scan-hosts` | After ARP scan, port scan all discovered hosts |
| `--export-json` | Export results to a JSON file |
| `--export-html` | Export results to an HTML report |

---

## Notes

| Topic | Detail |
|-------|--------|
| Permissions | ARP scanning and OS fingerprinting require root/admin privileges |
| Performance | Increase `--threads` for faster scans; decrease on congested networks |
| Accuracy | OS fingerprinting accuracy varies with network conditions and target config |
| Windows | Rich progress indicators are disabled on Windows to avoid encoding issues |
| Vuln Database | Covers common CVEs — not a replacement for a full vulnerability scanner |

---

## Legal

This tool is intended for use on networks and systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions. The author accepts no responsibility for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Ismail Jonkunda Ceesay** — [github.com/IsmailCeesay](https://github.com/IsmailCeesay)
