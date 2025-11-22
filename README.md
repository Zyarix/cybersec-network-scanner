Network Reconnaissance Tool

A powerful, modular network reconnaissance tool that performs fast port scanning, ARP host discovery, banner grabbing, OS fingerprinting, and basic vulnerability checks. All from a clean, modern command‑line interface with rich output formatting.

This project demonstrates core cybersecurity concepts, Python networking skills, and multi‑threaded performance optimisation.

Features:

Port Scanning
. Fast multi-threaded TCP connect scanning  
. Custom port ranges (e.g., `1-1000`, `80,443,8080`)  
. Adjustable thread count for performance  

Address Resolution Protocol (ARP) Network Discovery
. Identifies active hosts on a local network  
. Returns IP + MAC addresses  
. Useful for topology mapping and reconnaissance  

Banner Grabbing
. Extracts server banners from open ports  
. Helps identify running services and versions  

OS Fingerprinting
. Lightweight OS detection using TTL and window-size heuristics  
. Provides confidence scoring  
. Works on Windows, Linux, routers, and IoT devices  

Vulnerability Checking
. Compares detected banners against a simple known-vulnerabilities list  
. Flags potentially vulnerable services  
. Includes CVE references when available  

Rich Output
. Clean, colored tables  
. Easy-to-read layout  
. Optional JSON/HTML export  

Installation
1. Install Python 3.7+
2. Install dependencies:

Requirements:
rich>=13.0.0
scapy>=2.5.0

License
This project is licensed under the MIT License. See the LICENSE file for details.

This tool is intended for use on networks and systems you own or have explicit permission to test. Unauthorised scanning or exploitation is illegal, and the author is not responsible for misuse.
