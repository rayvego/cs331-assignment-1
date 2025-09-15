# path: src/client.py

import socket
import logging
import sys
import os
import struct
from datetime import datetime
from scapy.all import DNS, PcapReader
from tqdm import tqdm
import config

# conditionally import raw socket utilities
if config.USE_RAW_SOCKETS:
    from packet_utils import create_ipv4_header, create_udp_header

# configure basic logging
logging.basicConfig(level=config.LOG_LEVEL, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr)


class DnsClient:
    """a client that reads dns queries from a pcap, sends them to a custom server, and logs responses."""
    def __init__(self, server_host, server_port):
        self.server_addr = (server_host, server_port)
        self.sock = None
        self.results = {}
        self.ordered_headers = [] # preserve send order for final report
        self.source_ip = '127.0.0.1'
        self.source_port = 54321

    def _collect_dns_queries(self, pcap_path: str) -> list:
        """extracts all dns query packets from a given pcap file."""
        dns_queries = []
        try:
            file_size = os.path.getsize(pcap_path)
            with PcapReader(pcap_path) as pcap_reader, \
                 tqdm(total=file_size, unit='B', unit_scale=True, desc="scanning pcap") as pbar:
                for packet in pcap_reader:
                    pbar.update(pcap_reader.f.tell() - pbar.n)
                    # filter for dns queries (qr=0 means query)
                    if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qdcount > 0:
                        dns_queries.append((packet.time, bytes(packet[DNS])))
            return dns_queries
        except FileNotFoundError:
            logging.error(f"pcap file not found: '{pcap_path}'.")
            return []

    def process_and_send(self):
        """main method to initialize socket, send queries, and receive responses."""
        try:
            if config.USE_RAW_SOCKETS:
                # create a raw socket to build custom ip/udp headers
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.bind((self.source_ip, self.source_port))
            else:
                # create a standard udp socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0)
        except Exception as e:
            logging.error(f"failed to initialize client: {e}")
            return

        dns_queries = self._collect_dns_queries(config.PCAP_FILE_PATH)
        if not dns_queries:
            logging.warning("no dns queries found.")
            return

        logging.info(f"sending {len(dns_queries)} dns queries...")
        for i, (pcap_time, dns_payload) in enumerate(tqdm(dns_queries, desc="sending packets")):
            domain = DNS(dns_payload).qd.qname.decode('utf-8', errors='ignore')
            dt_object = datetime.fromtimestamp(float(pcap_time))
            
            # create custom header: HHMMSS + 2-digit query index
            custom_header_str = f"{dt_object:%H%M%S}{i:02d}"
            self.ordered_headers.append(custom_header_str)
            self.results[custom_header_str] = {"domain": domain, "resolved_ip": "NO_RESPONSE"}
            
            # construct the application payload
            app_data = custom_header_str.encode() + dns_payload
            
            if config.USE_RAW_SOCKETS:
                # create full ip/udp packet to send
                ip_header = create_ipv4_header(self.source_ip, self.server_addr[0], socket.IPPROTO_UDP, len(app_data))
                udp_header = create_udp_header(self.source_port, self.server_addr[1], app_data)
                packet_to_send = ip_header + udp_header + app_data
                self.sock.sendto(packet_to_send, self.server_addr)
            else:
                self.sock.sendto(app_data, self.server_addr)

        logging.info("listening for responses...")
        received_count = 0
        pbar = tqdm(total=len(dns_queries), desc="receiving packets")
        try:
            while received_count < len(dns_queries):
                if config.USE_RAW_SOCKETS:
                    # for raw sockets, parse ip and udp headers manually
                    response_packet, _ = self.sock.recvfrom(config.SERVER_BUFFER_SIZE)
                    if len(response_packet) < 28: continue
                    
                    ip_header_len = (response_packet[0] & 0xF) * 4
                    udph = struct.unpack('!HHHH', response_packet[ip_header_len:ip_header_len+8])
                    if udph[0] != self.server_addr[1]: continue # filter packets not from our server
                    
                    payload = response_packet[ip_header_len+8:]
                else:
                    payload, _ = self.sock.recvfrom(config.SERVER_BUFFER_SIZE)
                
                if len(payload) < 9: continue # ensure payload has header + at least 1 ip char
                
                # parse the response and update the corresponding result
                header_from_server = payload[:8].decode('utf-8', 'ignore')
                ip_from_server = payload[8:].decode('utf-8', 'ignore')
                
                if header_from_server in self.results and self.results[header_from_server]['resolved_ip'] == "NO_RESPONSE":
                    self.results[header_from_server]['resolved_ip'] = ip_from_server
                    received_count += 1
                    pbar.update(1)

        except socket.timeout:
            logging.warning(f"timeout. received {pbar.n}/{len(dns_queries)} responses.")
        finally:
            pbar.close()
            self.sock.close()
            self._print_report()
            
    def _print_report(self):
        """prints a formatted report of sent queries and their resolution status."""
        if not self.results: return
        print("\n" + "="*80 + "\n" + "CLIENT-SIDE RESOLUTION LOG".center(80) + "\n" + "="*80)
        print(f"{'Custom Header':<30} {'Domain Name':<35} {'Resolved IP Address':<20}")
        print("-"*80)
        # iterate using the ordered list to print in the same order packets were sent
        for header in self.ordered_headers:
            entry = self.results[header]
            print(f"{header:<30} {entry['domain']:<35} {entry['resolved_ip']:<20}")
        print("="*80)

if __name__ == "__main__":
    DnsClient(config.SERVER_HOST, config.SERVER_PORT).process_and_send()