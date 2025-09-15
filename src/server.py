# path: src/server.py

import socket
import logging
import sys
import struct
from scapy.all import DNS
import config

# conditionally import raw socket utilities
if config.USE_RAW_SOCKETS:
    from packet_utils import create_ipv4_header, create_udp_header

# configure basic logging
logging.basicConfig(level=config.LOG_LEVEL, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr)


class DnsServer:
    """a custom dns server that resolves ips based on time and session."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.dns_report = []

    def _get_time_period(self, hour: int) -> str:
        """determines the time period ('morning', 'afternoon', etc.) from the hour."""
        for period, rules in config.TIME_BASED_ROUTING_RULES.items():
            if hour in rules["range"]:
                return period
        return "night"

    def _resolve_ip(self, custom_header: bytes) -> tuple:
        """resolves an ip address based on the custom header's time and session id."""
        try:
            header_str = custom_header.decode(config.CUSTOM_HEADER_FORMAT)
            hour = int(header_str[0:2])
            session_id = int(header_str[6:8])
            
            # select ip pool based on time
            time_period = self._get_time_period(hour)
            rule = config.TIME_BASED_ROUTING_RULES[time_period]
            
            # select ip from pool using a hash of the session id
            hash_value = session_id % rule["hash_mod"]
            ip_index = rule["ip_pool_start"] + hash_value
            return config.IP_POOL[ip_index], header_str
            
        except (ValueError, IndexError):
            # return a default ip if the header is invalid
            return config.IP_POOL[0], "INVALID_HEADER"

    def _parse_domain_name(self, dns_packet_bytes: bytes) -> str:
        """safely extracts the domain name from a raw dns packet."""
        try:
            return DNS(dns_packet_bytes).qd.qname.decode('utf-8', errors='ignore')
        except Exception:
            return "unknown.domain"

    def _print_report(self):
        """prints a formatted report of all processed dns queries."""
        if not self.dns_report:
            logging.info("no dns queries processed.")
            return
        print("\n" + "="*80 + "\n" + "DNS RESOLUTION REPORT".center(80) + "\n" + "="*80)
        print(f"{'Custom Header':<30} {'Domain Name':<35} {'Resolved IP Address':<20}")
        print("-"*80)
        for entry in self.dns_report:
            print(f"{entry['custom_header']:<30} {entry['domain']:<35} {entry['resolved_ip']:<20}")
        print("="*80)

    def start(self):
        """initializes the socket and starts the main listening loop."""
        try:
            if config.USE_RAW_SOCKETS:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # THE FIX: allow the socket to be reused immediately after it's closed
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            self.sock.bind((self.host, self.port))
            logging.info(f"server listening on {self.host}:{self.port}")
        except Exception as e:
            logging.error(f"failed to initialize server: {e}")
            return

        try:
            while True:
                if config.USE_RAW_SOCKETS:
                    # for raw sockets, parse ip and udp headers manually
                    raw_packet, _ = self.sock.recvfrom(config.SERVER_BUFFER_SIZE)
                    if len(raw_packet) < 28: continue # ensure packet has full ip and udp headers
                    
                    udph = struct.unpack('!HHHH', raw_packet[20:28])
                    if udph[1] != self.port: continue # filter packets not destined for our port
                    
                    iph = struct.unpack('!BBHHHBBH4s4s', raw_packet[:20])
                    ip_header_len = (raw_packet[0] & 0xF) * 4
                    client_addr = (socket.inet_ntoa(iph[8]), udph[0]) # get source ip and port
                    app_data = raw_packet[ip_header_len + 8:]
                else:
                    # for standard sockets, recvfrom gives us the data and address directly
                    app_data, client_addr = self.sock.recvfrom(config.SERVER_BUFFER_SIZE)

                # extract custom header and dns data from the payload
                custom_header = app_data[:8]
                dns_data = app_data[8:]
                
                resolved_ip, header_str = self._resolve_ip(custom_header)
                domain_name = self._parse_domain_name(dns_data)
                self.dns_report.append({"custom_header": header_str, "domain": domain_name, "resolved_ip": resolved_ip})
                
                # construct the response payload
                response_data = custom_header + resolved_ip.encode()

                if config.USE_RAW_SOCKETS:
                    # create full ip/udp packet for the response
                    ip_header = create_ipv4_header(self.host, client_addr[0], socket.IPPROTO_UDP, len(response_data))
                    udp_header = create_udp_header(self.port, client_addr[1], response_data)
                    response_packet = ip_header + udp_header + response_data
                    self.sock.sendto(response_packet, client_addr)
                else:
                    # send only the application data
                    self.sock.sendto(response_data, client_addr)
                    
        except KeyboardInterrupt:
            logging.info("shutdown signal received.")
        finally:
            if self.sock: self.sock.close()
            self._print_report()

if __name__ == "__main__":
    DnsServer(config.SERVER_HOST, config.SERVER_PORT).start()