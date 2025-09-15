# path: src/config.py

import logging
import os

# --- implementation strategy ---
# allows switching between raw and standard udp sockets via environment variable
SOCKET_MODE = os.getenv('SOCKET_MODE', 'UDP')
USE_RAW_SOCKETS = (SOCKET_MODE == 'RAW')

# sets the dns query filtering mode for the client
# 'ALL' processes all dns/mdns queries; 'STRICT_DNS' processes only port 53 queries
DNS_FILTER_MODE = os.getenv('DNS_FILTER_MODE', 'ALL')

# --- path configuration ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

# --- general settings ---
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'

# --- server settings ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8081
SERVER_BUFFER_SIZE = 4096

# --- ip pool for dns load balancing ---
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# --- time-based routing rules ---
# defines which ip sub-pool to use based on the time of day
TIME_BASED_ROUTING_RULES = {
    "morning":   {"range": range(4, 12), "hash_mod": 5, "ip_pool_start": 0},
    "afternoon": {"range": range(12, 20),"hash_mod": 5, "ip_pool_start": 5},
    "night":     {"range": range(20, 24),"hash_mod": 5, "ip_pool_start": 10},
    "late_night":{"range": range(0, 4),  "hash_mod": 5, "ip_pool_start": 10}
}

# --- client settings ---
PCAP_FILE_PATH = os.path.join(BASE_DIR, 'data', '9.pcap')
CUSTOM_HEADER_FORMAT = "utf-8"