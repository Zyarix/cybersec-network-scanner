# Author - Ismail Jokunda Ceesay
"""
Network Reconnaissance Tool
Combines port scanning, ARP scanning, banner grabbing, OS detection, and vulnerability checking.
"""

import argparse
import json
import socket
import threading
import re
import sys
from queue import Queue
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

# Check if running on Windows
IS_WINDOWS = sys.platform == 'win32'

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    RICH_AVAILABLE = True
    # Disable Rich progress on Windows to avoid encoding issues
    if IS_WINDOWS:
        USE_RICH_PROGRESS = False
    else:
        USE_RICH_PROGRESS = True
except ImportError:
    RICH_AVAILABLE = False
    USE_RICH_PROGRESS = False
    if not IS_WINDOWS:
        print("Warning: Rich library not available. Install with: pip install rich")

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy library not available. ARP scan and OS detection will be disabled.")

import ipaddress
import urllib.request
import urllib.parse

# Initialize Rich console
console = Console() if RICH_AVAILABLE else None

# Service Detection Database (Port → Service Name)
SERVICE_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    6379: 'Redis', 9200: 'Elasticsearch', 27015: 'Steam', 25565: 'Minecraft'
}

# Common MAC Vendor OUI Database (first 3 octets) - Common vendors
MAC_VENDORS = {
    # Apple, Inc.
    '00:1B:11': 'Apple, Inc.', '00:1E:C2': 'Apple, Inc.', '00:23:12': 'Apple, Inc.',
    '00:25:00': 'Apple, Inc.', '00:26:08': 'Apple, Inc.', '00:50:E4': 'Apple, Inc.',
    '04:0C:CE': 'Apple, Inc.', '04:15:52': 'Apple, Inc.', '08:66:98': 'Apple, Inc.',
    '0C:4D:E9': 'Apple, Inc.', '10:93:E9': 'Apple, Inc.', '14:10:9F': 'Apple, Inc.',
    '18:65:90': 'Apple, Inc.', '1C:1A:C0': 'Apple, Inc.', '20:78:F0': 'Apple, Inc.',
    '28:CF:DA': 'Apple, Inc.', '30:90:AB': 'Apple, Inc.', '34:15:9E': 'Apple, Inc.',
    '40:33:1A': 'Apple, Inc.', '4C:8D:79': 'Apple, Inc.', '5C:95:AE': 'Apple, Inc.',
    '6C:40:08': 'Apple, Inc.', '78:31:C1': 'Apple, Inc.', '80:E6:50': 'Apple, Inc.',
    '8C:85:90': 'Apple, Inc.', 'A0:99:9B': 'Apple, Inc.', 'AC:1F:74': 'Apple, Inc.',
    'B8:53:AC': 'Apple, Inc.', 'C0:25:E9': 'Apple, Inc.', 'C8:BC:C8': 'Apple, Inc.',
    'D0:03:4B': 'Apple, Inc.', 'D8:30:62': 'Apple, Inc.', 'E0:AC:CB': 'Apple, Inc.',
    'F0:DB:E2': 'Apple, Inc.', 'F8:1E:DF': 'Apple, Inc.',
    # Samsung Electronics
    '00:1D:0F': 'Samsung Electronics Co.,Ltd.', '00:1E:7D': 'Samsung Electronics Co.,Ltd.',
    '00:23:39': 'Samsung Electronics Co.,Ltd.', '00:24:90': 'Samsung Electronics Co.,Ltd.',
    '00:26:5D': 'Samsung Electronics Co.,Ltd.', '00:50:39': 'Samsung Electronics Co.,Ltd.',
    '00:52:18': 'Samsung Electronics Co.,Ltd.', '00:55:DA': 'Samsung Electronics Co.,Ltd.',
    '00:5C:19': 'Samsung Electronics Co.,Ltd.', '00:5D:03': 'Samsung Electronics Co.,Ltd.',
    '00:60:57': 'Samsung Electronics Co.,Ltd.', '00:66:4B': 'Samsung Electronics Co.,Ltd.',
    '00:72:04': 'Samsung Electronics Co.,Ltd.', '00:75:6A': 'Samsung Electronics Co.,Ltd.',
    '00:78:CD': 'Samsung Electronics Co.,Ltd.', '00:7C:2D': 'Samsung Electronics Co.,Ltd.',
    '00:80:92': 'Samsung Electronics Co.,Ltd.', '00:84:ED': 'Samsung Electronics Co.,Ltd.',
    '00:88:79': 'Samsung Electronics Co.,Ltd.', '00:8C:54': 'Samsung Electronics Co.,Ltd.',
    '00:90:4C': 'Samsung Electronics Co.,Ltd.', '00:94:A1': 'Samsung Electronics Co.,Ltd.',
    '00:98:58': 'Samsung Electronics Co.,Ltd.', '00:9C:02': 'Samsung Electronics Co.,Ltd.',
    '00:A0:DE': 'Samsung Electronics Co.,Ltd.', '00:A4:02': 'Samsung Electronics Co.,Ltd.',
    '00:A8:96': 'Samsung Electronics Co.,Ltd.', '00:AC:DE': 'Samsung Electronics Co.,Ltd.',
    '00:B0:64': 'Samsung Electronics Co.,Ltd.', '00:B4:52': 'Samsung Electronics Co.,Ltd.',
    '00:B8:8D': 'Samsung Electronics Co.,Ltd.', '00:BC:60': 'Samsung Electronics Co.,Ltd.',
    '00:C0:59': 'Samsung Electronics Co.,Ltd.', '00:C4:00': 'Samsung Electronics Co.,Ltd.',
    '00:C8:8B': 'Samsung Electronics Co.,Ltd.', '00:CC:FC': 'Samsung Electronics Co.,Ltd.',
    '00:D0:2B': 'Samsung Electronics Co.,Ltd.', '00:D4:96': 'Samsung Electronics Co.,Ltd.',
    '00:D8:31': 'Samsung Electronics Co.,Ltd.', '00:DC:58': 'Samsung Electronics Co.,Ltd.',
    '00:E0:18': 'Samsung Electronics Co.,Ltd.', '00:E4:00': 'Samsung Electronics Co.,Ltd.',
    '00:E8:08': 'Samsung Electronics Co.,Ltd.', '00:EC:0A': 'Samsung Electronics Co.,Ltd.',
    '00:F0:DB': 'Samsung Electronics Co.,Ltd.', '00:F4:6F': 'Samsung Electronics Co.,Ltd.',
    '00:F8:1C': 'Samsung Electronics Co.,Ltd.', '00:FC:58': 'Samsung Electronics Co.,Ltd.',
    # TP-Link Technologies
    '00:14:22': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:15:E9': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:16:E6': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:17:66': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:18:F8': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:19:E0': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:1A:92': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:1C:DF': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:1E:8C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:20:78': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:21:85': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:22:93': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:23:CD': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:24:01': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:25:86': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:26:18': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:27:19': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:28:F8': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:29:1C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:2A:10': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:2B:67': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:2C:44': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:2D:76': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:2E:C7': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:2F:3A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:30:18': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:31:92': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:32:1E': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:33:7A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:34:DA': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:35:1F': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:36:76': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:37:6D': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:38:DF': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:39:8B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:3A:99': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:3B:9A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:3C:10': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:3D:82': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:3E:E1': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:3F:3A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:40:2C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:41:42': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:42:5A': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:43:85': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:44:82': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:45:67': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:46:4B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:47:8D': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:48:54': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:49:55': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:4A:77': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:4B:ED': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:4C:60': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:4D:32': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:4E:35': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:4F:58': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:50:56': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:51:F9': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:52:18': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:53:CE': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:54:AF': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:55:39': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:56:2B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:57:AC': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:58:7E': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:59:07': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:5A:13': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:5B:94': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:5C:41': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:5D:73': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:5E:0C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:5F:86': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:60:B3': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:61:71': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:62:6E': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:63:BF': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:64:70': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:65:00': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:66:4B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:67:F2': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:68:8F': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:69:4C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:6A:3E': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:6B:9E': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:6C:BC': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:6D:61': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:6E:4C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:6F:64': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:70:9C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:71:C2': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:72:04': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:73:E0': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:74:9C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:75:6A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:76:6D': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:77:40': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:78:CD': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:79:28': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:7A:3D': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:7B:18': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:7C:2D': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:7D:FA': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:7E:95': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:7F:3D': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:80:92': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:81:F9': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:82:BD': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:83:5B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:84:ED': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:85:84': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:86:60': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:87:01': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:88:79': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:89:86': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:8A:96': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:8B:AD': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:8C:54': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:8D:4E': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:8E:44': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:8F:EC': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:90:4C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:91:6B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:92:83': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:93:FB': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:94:A1': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:95:69': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:96:B0': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:97:26': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:98:58': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:99:4C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:9A:CD': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:9B:CF': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:9C:02': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:9D:6B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:9E:C6': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:9F:EA': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:A0:DE': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:A1:48': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:A2:EE': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:A3:8E': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:A4:02': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:A5:BF': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:A6:CA': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:A7:42': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:A8:96': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:A9:5B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:AA:02': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:AB:00': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:AC:DE': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:AD:24': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:AE:F6': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:AF:1F': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:B0:64': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:B1:E8': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:B2:F5': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:B3:62': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:B4:52': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:B5:D0': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:B6:70': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:B7:5D': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:B8:8D': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:B9:8F': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:BA:BE': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:BB:01': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:BC:60': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:BD:27': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:BE:3B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:BF:61': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:C0:59': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:C1:64': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:C2:06': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:C3:F4': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:C4:00': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:C5:1C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:C6:10': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:C7:42': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:C8:8B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:C9:14': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:CA:E5': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:CB:BD': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:CC:FC': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:CD:90': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:CE:7E': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:CF:1C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:D0:2B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:D1:9D': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:D2:B1': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:D3:9A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:D4:96': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:D5:2B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:D6:93': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:D7:D5': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:D8:31': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:D9:D1': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:DA:55': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:DB:DF': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:DC:58': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:DD:09': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:DE:FB': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:DF:DF': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E0:18': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:E0:64': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E0:91': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:E0:FC': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E1:88': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:E2:69': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E3:24': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:E4:00': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E5:19': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:E6:66': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E7:23': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:E8:08': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:E9:13': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:EA:BD': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:EB:2D': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:EC:0A': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:ED:1C': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:EE:AB': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:EF:3A': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:F0:DB': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:F1:EC': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:F2:8B': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:F3:DB': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:F4:6F': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:F5:69': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:F6:20': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:F7:6F': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:F8:1C': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:F9:ED': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:FA:21': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:FB:4B': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:FC:58': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:FD:45': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    '00:FE:3D': 'TP-LINK TECHNOLOGIES CO.,LTD.', '00:FF:4A': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    # VMware
    '00:50:56': 'VMware, Inc.', '00:0C:29': 'VMware, Inc.', '00:1B:21': 'VMware, Inc.',
    '00:1C:14': 'VMware, Inc.', '00:05:69': 'VMware, Inc.', '00:0F:4B': 'VMware, Inc.',
    '00:1C:42': 'VMware, Inc.',
    # Microsoft
    '00:15:5D': 'Microsoft Corporation', '00:50:F2': 'Microsoft Corporation',
    '00:03:FF': 'Microsoft Corporation', '00:0D:3A': 'Microsoft Corporation',
    # Cisco
    '00:1D:09': 'Cisco Systems, Inc.', '00:1E:13': 'Cisco Systems, Inc.',
    '00:1E:79': 'Cisco Systems, Inc.', '00:23:04': 'Cisco Systems, Inc.',
    '00:26:CA': 'Cisco Systems, Inc.',
    # VirtualBox
    '08:00:27': 'PCS Systemtechnik GmbH (VirtualBox)'
}

def get_service_name(port: int) -> str:
    """Get service name for a port."""
    return SERVICE_PORTS.get(port, 'Unknown')

def get_mac_vendor(mac: str) -> str:
    """Get vendor name from MAC address OUI."""
    if not mac:
        return 'Unknown'
    # Normalize MAC address (remove separators, uppercase)
    mac_clean = mac.replace(':', '').replace('-', '').upper()
    if len(mac_clean) < 6:
        return 'Unknown'
    oui = f"{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}"
    return MAC_VENDORS.get(oui, 'Unknown')

# Vulnerability Database
VULN_DATABASE = {
    'OpenSSH': [
        {
            'pattern': r'OpenSSH[_-]?(\d+\.\d+[\.\w]*)',
            'vulnerable_versions': ['7.2', '7.1', '7.0', '6.9', '6.8', '6.7', '6.6', '6.5', '6.4', '6.3', '6.2', '6.1', '6.0'],
            'cve': 'CVE-2016-0777, CVE-2016-0778',
            'description': 'Outdated OpenSSH version - check for credential disclosure vulnerabilities'
        },
        {
            'pattern': r'OpenSSH[_-]?(\d+\.\d+[\.\w]*)',
            'vulnerable_versions': ['7.4', '7.3'],
            'cve': 'CVE-2017-15906',
            'description': 'Outdated OpenSSH version - check for authentication bypass'
        }
    ],
    'Apache': [
        {
            'pattern': r'Apache/(\d+\.\d+\.\d+)',
            'vulnerable_versions': ['2.4.49', '2.4.48', '2.4.47', '2.4.46', '2.4.45', '2.4.44', '2.4.43', '2.4.42', '2.4.41'],
            'cve': 'CVE-2021-41773, CVE-2021-42013',
            'description': 'Outdated Apache version - path traversal vulnerability'
        },
        {
            'pattern': r'Apache/(\d+\.\d+\.\d+)',
            'vulnerable_versions': ['2.4.50', '2.4.51'],
            'cve': 'CVE-2021-44224',
            'description': 'Outdated Apache version - check for security vulnerabilities'
        }
    ],
    'nginx': [
        {
            'pattern': r'nginx/(\d+\.\d+\.\d+)',
            'vulnerable_versions': ['1.18.0', '1.17.0', '1.16.0', '1.15.0', '1.14.0'],
            'cve': 'CVE-2021-23017',
            'description': 'Outdated nginx version - check for buffer overflow vulnerabilities'
        }
    ],
    'vsftpd': [
        {
            'pattern': r'vsftpd[^\d]*(\d+\.\d+\.\d+)',
            'vulnerable_versions': ['2.3.2', '2.3.1', '2.3.0', '2.2.0', '2.1.0', '2.0.0'],
            'cve': 'CVE-2011-0762',
            'description': 'Outdated vsftpd version - backdoor vulnerability'
        }
    ],
}

# OS Fingerprint Database
OS_FINGERPRINTS = {
    'Windows 10/11': {
        'ttl_range': [128, 128],
        'window_sizes': [65535, 8192, 16384],
        'description': 'Windows 10/11'
    },
    'Windows 7/8/Server': {
        'ttl_range': [128, 128],
        'window_sizes': [8192, 65535, 16384, 4128],
        'description': 'Windows 7/8/Server'
    },
    'Windows': {
        'ttl_range': [128, 128],
        'window_sizes': [8192, 65535, 16384, 4128, 8192],
        'description': 'Windows (various versions)'
    },
    'Linux': {
        'ttl_range': [64, 64],
        'window_sizes': [5840, 5720, 65535, 16384, 8192],
        'description': 'Linux (various distributions)'
    },
    'macOS/iOS': {
        'ttl_range': [64, 64],
        'window_sizes': [65535, 65535],
        'description': 'macOS or iOS'
    },
}

class NetworkScanner:
    """Main network scanning class that combines all functionality."""
    
    def __init__(self, target: str, threads: int = 200):
        self.target = target
        self.threads = threads
        self.open_ports = []
        self.banner_results = []
        self.vulnerabilities = []
        self.os_data = []
        self.arp_hosts = []
        self.scan_results = {}
    
    def port_scan(self, port_range: str) -> List[int]:
        """Scan ports and return list of open ports."""
        ports = self._parse_port_range(port_range)
        queue = Queue()
        open_ports = []
        
        for port in ports:
            queue.put(port)
        
        def portscan(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target, port))
                sock.close()
                return True
            except:
                return False
        
        def worker():
            while not queue.empty():
                port = queue.get()
                if portscan(port):
                    open_ports.append(port)
                queue.task_done()
        
        thread_list = []
        for _ in range(min(self.threads, len(ports))):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread_list.append(thread)
            thread.start()
        
        for thread in thread_list:
            thread.join()
        
        queue.join()
        self.open_ports = sorted(open_ports)
        return self.open_ports
    
    def grab_banners(self, ports: Optional[List[int]] = None) -> List[Dict]:
        """Grab service banners from open ports."""
        if ports is None:
            ports = self.open_ports
        
        if not ports:
            return []
        
        queue = Queue()
        banner_results = []
        
        for port in ports:
            queue.put(port)
        
        def grab_banner(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                
                banner = None
                if port == 80 or port == 8080:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    response = sock.recv(2048).decode('utf-8', errors='ignore')
                    for line in response.split('\n'):
                        if 'Server:' in line or 'server:' in line:
                            banner = line.split(':', 1)[1].strip()
                            break
                    if not banner:
                        banner = response.split('\n')[0][:200]
                elif port in [21, 22, 25, 110, 143, 3306, 5432]:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                else:
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                sock.close()
                if banner:
                    banner = banner.split('\n')[0][:200]
                    return banner
                return None
            except:
                return None
        
        def worker():
            while not queue.empty():
                port = queue.get()
                banner = grab_banner(self.target, port)
                if banner:
                    banner_results.append({'port': port, 'banner': banner})
                queue.task_done()
        
        thread_list = []
        for _ in range(min(self.threads, len(ports))):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread_list.append(thread)
            thread.start()
        
        for thread in thread_list:
            thread.join()
        
        queue.join()
        self.banner_results = banner_results
        return banner_results
    
    def check_vulnerabilities(self) -> List[Dict]:
        """Check banners for known vulnerabilities."""
        vulnerabilities = []
        
        for result in self.banner_results:
            banner = result['banner']
            port = result['port']
            vulns = self._check_vulnerability(banner, port)
            vulnerabilities.extend(vulns)
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def os_fingerprint(self) -> Optional[Dict]:
        """Perform OS fingerprinting with improved accuracy."""
        if not SCAPY_AVAILABLE:
            return None
        
        if not self.open_ports:
            return None
        
        # Probe more ports for better accuracy (up to 10)
        probe_ports = self.open_ports[:10] if len(self.open_ports) >= 10 else self.open_ports
        ttl_values = []
        window_sizes = []
        tcp_flags = []
        
        # Also probe some common closed ports to get RST responses
        common_ports = [80, 443, 22, 21, 25, 53, 135, 139, 445, 3389]
        closed_ports = []
        for port in common_ports:
            if port not in self.open_ports:
                closed_ports.append(port)
                if len(closed_ports) >= 5:
                    break
        
        all_probe_ports = list(set(probe_ports + closed_ports[:5]))
        
        for port in all_probe_ports:
            try:
                src_port = RandShort()
                packet = IP(dst=self.target) / TCP(sport=src_port, dport=port, flags="S")
                response = sr1(packet, timeout=2, verbose=False)
                
                if response and response.haslayer(IP) and response.haslayer(TCP):
                    ttl = response[IP].ttl
                    window = response[TCP].window
                    flags = response[TCP].flags
                    
                    ttl_values.append(ttl)
                    window_sizes.append(window)
                    tcp_flags.append(flags)
            except:
                pass
        
        if not ttl_values or not window_sizes:
            return None
        
        os_result = self._identify_os_improved(ttl_values, window_sizes, tcp_flags)
        self.os_data = os_result
        return os_result
    
    def arp_scan(self, network: str) -> List[Dict]:
        """Perform ARP network scan."""
        if not SCAPY_AVAILABLE:
            return []
        
        queue = Queue()
        discovered_hosts = []
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            for ip in network_obj.hosts():
                queue.put(ip)
        except ValueError:
            return []
        
        def arp_scan(ip):
            try:
                arp_request = ARP(pdst=str(ip))
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                
                if answered_list:
                    for element in answered_list:
                        mac = element[1].hwsrc
                        return {
                            'ip': element[1].psrc,
                            'mac': mac,
                            'vendor': get_mac_vendor(mac)
                        }
            except:
                pass
            return None
        
        def worker():
            while not queue.empty():
                ip = queue.get()
                host_info = arp_scan(ip)
                if host_info:
                    discovered_hosts.append(host_info)
                queue.task_done()
        
        thread_list = []
        for _ in range(min(self.threads, 100)):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread_list.append(thread)
            thread.start()
        
        for thread in thread_list:
            thread.join()
        
        queue.join()
        self.arp_hosts = discovered_hosts
        return discovered_hosts
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string like '1-1000' or '80,443,8080'."""
        ports = []
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = [int(p) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
        return ports
    
    def _check_vulnerability(self, banner: str, port: int) -> List[Dict]:
        """Check if banner indicates vulnerable service."""
        vulnerabilities = []
        if not banner:
            return vulnerabilities
        
        banner_upper = banner.upper()
        
        for service_name, vuln_list in VULN_DATABASE.items():
            service_found = False
            service_upper = service_name.upper()
            
            if service_upper in banner_upper:
                service_found = True
            elif service_name == 'OpenSSH' and ('SSH' in banner_upper and 'OPENSSH' in banner_upper):
                service_found = True
            elif service_name == 'Apache' and ('APACHE' in banner_upper or 'HTTPD' in banner_upper):
                service_found = True
            elif service_name == 'vsftpd' and 'VSFTPD' in banner_upper:
                service_found = True
            
            if service_found:
                for vuln_entry in vuln_list:
                    match = re.search(vuln_entry['pattern'], banner, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        if self._check_version_vulnerable(version, vuln_entry['vulnerable_versions']):
                            vulnerabilities.append({
                                'service': service_name,
                                'version': version,
                                'cve': vuln_entry['cve'],
                                'description': vuln_entry['description'],
                                'port': port
                            })
                        break
        
        return vulnerabilities
    
    def _check_version_vulnerable(self, version: str, vulnerable_versions: List[str]) -> bool:
        """Check if version is in vulnerable list."""
        if not version:
            return False
        for vuln_ver in vulnerable_versions:
            if version.startswith(vuln_ver) or vuln_ver in version:
                return True
        return False
    
    def _normalize_ttl(self, ttl: int) -> int:
        """Normalize TTL value accounting for network hops."""
        # Common initial TTL values: 32, 64, 128, 255
        # Account for network hops (subtract common hop counts)
        if ttl <= 32:
            return 32
        elif 33 <= ttl <= 64:
            # Could be 64 with 0-31 hops, or 32 with some hops
            # If most values are in this range, likely 64
            return 64
        elif 65 <= ttl <= 128:
            # Could be 128 with 0-63 hops, or 64 with some hops
            # If most values are in this range, likely 128
            return 128
        elif 129 <= ttl <= 255:
            return 255
        return ttl
    
    def _identify_os_improved(self, ttl_values: List[int], window_sizes: List[int], tcp_flags: List[int]) -> Dict:
        """Improved OS identification with better matching algorithm."""
        # Calculate statistics
        avg_ttl = sum(ttl_values) / len(ttl_values)
        min_ttl = min(ttl_values)
        max_ttl = max(ttl_values)
        
        # Better TTL normalization - account for network hops
        # Windows typically starts at 128, Linux at 64
        # If we see values around 64-128, we need to determine the base
        normalized_ttl = self._normalize_ttl_improved(ttl_values)
        
        # Window size analysis
        window_counts = {}
        for ws in window_sizes:
            window_counts[ws] = window_counts.get(ws, 0) + 1
        common_window = max(window_counts, key=window_counts.get)
        unique_windows = len(set(window_sizes))
        
        # Windows-specific characteristics
        # Windows often uses 8192, 65535, or 16384 as window sizes
        # Windows 10/11 often use 65535
        windows_indicators = 0
        if common_window in [8192, 65535, 16384, 4128]:
            windows_indicators += 2
        if 65535 in window_sizes:
            windows_indicators += 1  # Windows 10/11 indicator
        
        # Linux-specific characteristics
        # Linux often uses 5840, 5720, or 65535
        linux_indicators = 0
        if common_window in [5840, 5720]:
            linux_indicators += 3  # Strong Linux indicator
        elif common_window == 65535:
            linux_indicators += 1  # Could be Linux or Windows
        
        matches = []
        for os_name, fingerprint in OS_FINGERPRINTS.items():
            score = 0
            ttl_min, ttl_max = fingerprint['ttl_range']
            
            # TTL matching with better logic
            if normalized_ttl >= ttl_min and normalized_ttl <= ttl_max:
                score += 4  # Strong match
            elif abs(normalized_ttl - ttl_min) <= 2 or abs(normalized_ttl - ttl_max) <= 2:
                score += 2  # Close match
            elif abs(normalized_ttl - ttl_min) <= 5 or abs(normalized_ttl - ttl_max) <= 5:
                score += 1  # Weak match
            
            # Window size matching
            if common_window in fingerprint['window_sizes']:
                score += 3  # Exact match
            elif any(abs(common_window - ws) < 500 for ws in fingerprint['window_sizes']):
                score += 2  # Close match
            elif any(abs(common_window - ws) < 2000 for ws in fingerprint['window_sizes']):
                score += 1  # Approximate match
            
            # Multiple window size matches
            matching_windows = len(set(window_sizes) & set(fingerprint['window_sizes']))
            if matching_windows > 0:
                score += matching_windows
            
            # OS-specific indicators
            if os_name.startswith('Windows'):
                score += windows_indicators
            elif os_name == 'Linux':
                score += linux_indicators
            
            # Penalize if TTL doesn't match well
            if normalized_ttl == 128 and os_name == 'Linux':
                score -= 2  # Strong penalty - Linux rarely uses 128
            elif normalized_ttl == 64 and os_name.startswith('Windows'):
                score -= 2  # Strong penalty - Windows rarely uses 64
            
            if score > 0:
                matches.append({
                    'os': os_name,
                    'score': score,
                    'description': fingerprint['description']
                })
        
        matches.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'ttl': normalized_ttl,
            'ttl_range': f"{min_ttl}-{max_ttl}",
            'window_size': common_window,
            'unique_windows': unique_windows,
            'matches': matches,
            'raw_data': {
                'ttl_values': ttl_values,
                'window_sizes': window_sizes
            }
        }
    
    def _normalize_ttl_improved(self, ttl_values: List[int]) -> int:
        """Improved TTL normalization accounting for network hops."""
        # Find the most common TTL value
        ttl_counts = {}
        for ttl in ttl_values:
            ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1
        
        most_common_ttl = max(ttl_counts, key=ttl_counts.get)
        avg_ttl = sum(ttl_values) / len(ttl_values)
        
        # Common initial TTL values: 32, 64, 128, 255
        # Account for network hops by looking at the pattern
        # If we see values like 64, 63, 65, 62 - likely base 64 with 0-2 hops
        # If we see values like 128, 127, 129 - likely base 128 with 0-2 hops
        
        # Check if values cluster around common bases
        if 60 <= most_common_ttl <= 68:
            return 64  # Linux, macOS, BSD
        elif 124 <= most_common_ttl <= 132:
            return 128  # Windows
        elif 30 <= most_common_ttl <= 34:
            return 32  # Some embedded systems
        elif 250 <= most_common_ttl <= 255:
            return 255  # Some routers, Solaris
        
        # Fallback to average-based normalization
        if avg_ttl <= 32:
            return 32
        elif avg_ttl <= 64:
            return 64
        elif avg_ttl <= 128:
            return 128
        elif avg_ttl <= 255:
            return 255
        return int(avg_ttl)
        """Identify OS from TTL and window size data."""
        avg_ttl = sum(ttl_values) / len(ttl_values)
        normalized_ttl = self._normalize_ttl(int(avg_ttl))
        common_window = max(set(window_sizes), key=window_sizes.count)
        
        matches = []
        for os_name, fingerprint in OS_FINGERPRINTS.items():
            score = 0
            ttl_min, ttl_max = fingerprint['ttl_range']
            
            if normalized_ttl >= ttl_min and normalized_ttl <= ttl_max:
                score += 3
            elif abs(normalized_ttl - ttl_min) <= 1 or abs(normalized_ttl - ttl_max) <= 1:
                score += 1
            
            if common_window in fingerprint['window_sizes']:
                score += 2
            elif any(abs(common_window - ws) < 1000 for ws in fingerprint['window_sizes']):
                score += 1
            
            matching_windows = len(set(window_sizes) & set(fingerprint['window_sizes']))
            if matching_windows > 0:
                score += matching_windows
            
            if score > 0:
                matches.append({
                    'os': os_name,
                    'score': score,
                    'description': fingerprint['description']
                })
        
        matches.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'ttl': normalized_ttl,
            'window_size': common_window,
            'matches': matches
        }
    
    def export_json(self, filename: str):
        """Export scan results to JSON."""
        # Add service names to ports
        ports_with_services = [{'port': p, 'service': get_service_name(p)} for p in self.open_ports]
        
        results = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': self.open_ports,
            'ports_with_services': ports_with_services,
            'banners': self.banner_results,
            'vulnerabilities': self.vulnerabilities,
            'os_fingerprint': self.os_data,
            'arp_hosts': self.arp_hosts
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
    
    def export_html(self, filename: str):
        """Export scan results to HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .vuln {{ color: #d32f2f; font-weight: bold; }}
        .port {{ font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Scan Report</h1>
        <p><strong>Target:</strong> {self.target}</p>
        <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Open Ports ({len(self.open_ports)})</h2>
        <table>
            <tr><th>Port</th><th>Service</th></tr>
"""
        for port in self.open_ports:
            service = get_service_name(port)
            html += f"<tr><td class='port'>{port}</td><td>{service}</td></tr>\n"
        
        html += """</table>
        
        <h2>Service Banners</h2>
        <table>
            <tr><th>Port</th><th>Banner</th></tr>
"""
        for banner in self.banner_results:
            html += f"<tr><td class='port'>{banner['port']}</td><td>{banner['banner']}</td></tr>\n"
        
        html += """</table>
        
        <h2>Vulnerabilities</h2>
"""
        if self.vulnerabilities:
            html += """<table>
            <tr><th>Port</th><th>Service</th><th>Version</th><th>CVE</th><th>Description</th></tr>
"""
            for vuln in self.vulnerabilities:
                html += f"<tr><td class='port'>{vuln['port']}</td><td>{vuln['service']}</td><td>{vuln['version']}</td><td class='vuln'>{vuln['cve']}</td><td>{vuln['description']}</td></tr>\n"
            html += "</table>\n"
        else:
            html += "<p>No vulnerabilities detected.</p>\n"
        
        if self.os_data and self.os_data.get('matches'):
            html += f"""
        <h2>OS Fingerprint</h2>
        <p><strong>Most likely OS:</strong> {self.os_data['matches'][0]['os']} - {self.os_data['matches'][0]['description']}</p>
        <p><strong>TTL:</strong> {self.os_data['ttl']}</p>
        <p><strong>Window Size:</strong> {self.os_data['window_size']}</p>
"""
        
        if self.arp_hosts:
            html += """
        <h2>ARP Scan Results</h2>
        <table>
            <tr><th>IP Address</th><th>MAC Address</th><th>Vendor</th></tr>
"""
            for host in self.arp_hosts:
                vendor = host.get('vendor', 'Unknown')
                html += f"<tr><td>{host['ip']}</td><td>{host['mac']}</td><td>{vendor}</td></tr>\n"
            html += "</table>\n"
        
        html += """    </div>
</body>
</html>"""
        
        with open(filename, 'w') as f:
            f.write(html)


def print_results(scanner: NetworkScanner, use_rich: bool = True):
    """Print scan results using Rich tables if available."""
    if not use_rich or not RICH_AVAILABLE:
        # Fallback to simple text output
        print(f"\nScan Results for {scanner.target}")
        print("=" * 50)
        print(f"\nOpen Ports:")
        for port in scanner.open_ports:
            service = get_service_name(port)
            print(f"  Port {port}: {service}")
        if scanner.banner_results:
            print("\nBanners:")
            for banner in scanner.banner_results:
                print(f"  Port {banner['port']}: {banner['banner']}")
        if scanner.vulnerabilities:
            print("\nVulnerabilities:")
            for vuln in scanner.vulnerabilities:
                print(f"  Port {vuln['port']}: {vuln['service']} {vuln['version']} - {vuln['cve']}")
        elif scanner.banner_results:
            print("\nNo known vulnerabilities detected in service banners.")
        return
    
    # Rich output
    console.print(f"\n[bold green]Scan Results for {scanner.target}[/bold green]")
    
    # Open Ports Table
    if scanner.open_ports:
        table = Table(title="Open Ports", box=box.ROUNDED)
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("Service", style="magenta")
        for port in scanner.open_ports:
            service = get_service_name(port)
            table.add_row(str(port), service)
        console.print(table)
    
    # Banners Table
    if scanner.banner_results:
        table = Table(title="Service Banners", box=box.ROUNDED)
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("Banner", style="yellow")
        for banner in scanner.banner_results:
            table.add_row(str(banner['port']), banner['banner'])
        console.print(table)
    
    # Vulnerabilities Table
    if scanner.vulnerabilities:
        table = Table(title="Vulnerabilities", box=box.ROUNDED, border_style="red")
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        table.add_column("CVE", style="red", no_wrap=True)
        table.add_column("Description", style="white")
        for vuln in scanner.vulnerabilities:
            table.add_row(
                str(vuln['port']),
                vuln['service'],
                vuln['version'],
                vuln['cve'],
                vuln['description']
            )
        console.print(table)
    elif scanner.banner_results:
        console.print("[yellow]No known vulnerabilities detected in service banners.[/yellow]")
    
    # OS Fingerprint
    if scanner.os_data and scanner.os_data.get('matches'):
        os_match = scanner.os_data['matches'][0]
        console.print(Panel(
            f"[bold]OS:[/bold] {os_match['os']}\n"
            f"[bold]Description:[/bold] {os_match['description']}\n"
            f"[bold]Confidence Score:[/bold] {os_match['score']}",
            title="OS Fingerprint",
            border_style="blue"
        ))
    
    # ARP Hosts
    if scanner.arp_hosts:
        table = Table(title="ARP Scan Results", box=box.ROUNDED)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Vendor", style="yellow")
        for host in scanner.arp_hosts:
            vendor = host.get('vendor', 'Unknown')
            table.add_row(host['ip'], host['mac'], vendor)
        console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description='Network Reconnaissance Tool - Port scanning, ARP scanning, banner grabbing, OS detection, and vulnerability checking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py <Insert IP Here> --ports 1-1000 --threads 200
  python recon.py <Insert IP Here> --ports 1-1000 --banner --vuln
  python recon.py <Insert IP Here> --ports 80,443,8080 --banner --os --vuln
  python recon.py --arp <Insert IP Here>/24
  python recon.py <Insert IP Here> --ports 1-1000 --banner --os --vuln --export-json results.json
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target IP address or hostname')
    parser.add_argument('--ports', '-p', default='1-1024', help='Port range (e.g., 1-1000) or comma-separated (e.g., 80,443,8080)')
    parser.add_argument('--threads', '-t', type=int, default=200, help='Number of threads (default: 200)')
    parser.add_argument('--banner', '-b', action='store_true', help='Grab service banners')
    parser.add_argument('--os', action='store_true', help='Perform OS fingerprinting')
    parser.add_argument('--vuln', action='store_true', help='Check for vulnerabilities')
    parser.add_argument('--arp', help='Perform ARP scan on network (e.g., <Insert IP Here>/24)')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--export-html', help='Export results to HTML file')
    parser.add_argument('--scan-hosts', action='store_true', help='After ARP scan, automatically port scan all discovered hosts')
    
    args = parser.parse_args()
    
    if not args.target and not args.arp:
        parser.error("Either target IP or --arp network must be specified")
    
    if RICH_AVAILABLE:
        console.print("[bold blue]Network Reconnaissance Tool[/bold blue]")
        console.print(f"[yellow]Target:[/yellow] {args.target or args.arp}")
    else:
        print("Network Reconnaissance Tool")
        print(f"Target: {args.target or args.arp}")
    
    # Helper function to safely show progress
    def show_progress(message, func):
        """Show progress with fallback for Windows encoding issues."""
        if USE_RICH_PROGRESS and RICH_AVAILABLE:
            try:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                    task = progress.add_task(message, total=None)
                    return func()
            except (UnicodeEncodeError, UnicodeDecodeError, Exception):
                # Fallback for Windows encoding issues
                print(message)
                return func()
        else:
            print(message)
            return func()
    
    # ARP Scan
    if args.arp:
        if not SCAPY_AVAILABLE:
            print("Error: Scapy required for ARP scanning. Install with: pip install scapy")
            return
        
        scanner = NetworkScanner(args.arp, args.threads)
        hosts = show_progress("ARP Scanning...", lambda: scanner.arp_scan(args.arp))
        
        if hosts:
            print_results(scanner, RICH_AVAILABLE)
            
            # Multi-host port scanning
            if args.scan_hosts:
                if RICH_AVAILABLE:
                    console.print(f"\n[bold yellow]Scanning ports on {len(hosts)} discovered host(s)...[/bold yellow]")
                else:
                    print(f"\nScanning ports on {len(hosts)} discovered host(s)...")
                
                all_results = {}
                for host in hosts:
                    host_ip = host['ip']
                    if RICH_AVAILABLE:
                        console.print(f"\n[cyan]Scanning {host_ip}...[/cyan]")
                    else:
                        print(f"\nScanning {host_ip}...")
                    
                    host_scanner = NetworkScanner(host_ip, args.threads)
                    open_ports = show_progress(f"  Port scanning {host_ip}...", 
                                              lambda: host_scanner.port_scan(args.ports))
                    
                    if open_ports:
                        all_results[host_ip] = {
                            'host': host,
                            'open_ports': open_ports,
                            'scanner': host_scanner
                        }
                        
                        if args.banner:
                            show_progress(f"  Grabbing banners for {host_ip}...",
                                        lambda: host_scanner.grab_banners())
                        
                        if args.vuln:
                            show_progress(f"  Checking vulnerabilities for {host_ip}...",
                                        lambda: host_scanner.check_vulnerabilities())
                        
                        if args.os:
                            if SCAPY_AVAILABLE:
                                show_progress(f"  OS fingerprinting {host_ip}...",
                                            lambda: host_scanner.os_fingerprint())
                        
                        print_results(host_scanner, RICH_AVAILABLE)
                
                if all_results and args.export_json:
                    # Export combined results
                    combined_results = {
                        'arp_scan': scanner.arp_hosts,
                        'host_scans': {}
                    }
                    for ip, data in all_results.items():
                        combined_results['host_scans'][ip] = {
                            'host': data['host'],
                            'open_ports': data['scanner'].open_ports,
                            'banners': data['scanner'].banner_results,
                            'vulnerabilities': data['scanner'].vulnerabilities,
                            'os_fingerprint': data['scanner'].os_data
                        }
                    with open(args.export_json, 'w') as f:
                        json.dump(combined_results, f, indent=2)
                    if RICH_AVAILABLE:
                        console.print(f"[green]Combined results exported to {args.export_json}[/green]")
                    else:
                        print(f"Combined results exported to {args.export_json}")
        else:
            print("No hosts found.")
        return
    
    # Port Scan
    scanner = NetworkScanner(args.target, args.threads)
    open_ports = show_progress("Port Scanning...", lambda: scanner.port_scan(args.ports))
    
    if not open_ports:
        print("No open ports found.")
        return
    
    # Banner Grabbing
    if args.banner:
        show_progress("Grabbing Banners...", lambda: scanner.grab_banners())
    
    # Vulnerability Check
    if args.vuln:
        show_progress("Checking Vulnerabilities...", lambda: scanner.check_vulnerabilities())
    
    # OS Fingerprinting
    if args.os:
        if not SCAPY_AVAILABLE:
            print("Warning: Scapy required for OS fingerprinting. Skipping...")
        else:
            show_progress("OS Fingerprinting...", lambda: scanner.os_fingerprint())
    
    # Print Results
    print_results(scanner, RICH_AVAILABLE)
    
    # Export Results
    if args.export_json:
        scanner.export_json(args.export_json)
        if RICH_AVAILABLE:
            console.print(f"[green]Results exported to {args.export_json}[/green]")
        else:
            print(f"Results exported to {args.export_json}")
    
    if args.export_html:
        scanner.export_html(args.export_html)
        if RICH_AVAILABLE:
            console.print(f"[green]Results exported to {args.export_html}[/green]")
        else:
            print(f"Results exported to {args.export_html}")


if __name__ == "__main__":
    main()


