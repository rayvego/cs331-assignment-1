# path: src/packet_utils.py

import struct
import socket

def calculate_checksum(data: bytes) -> int:
    """calculates the internet checksum per rfc 791."""
    s = 0
    # pad with a zero byte if data has an odd length
    if len(data) % 2 == 1:
        data += b'\x00'
    
    # sum 16-bit words
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + (data[i+1])
    
    # fold carry bits
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    
    # return one's complement
    return ~s & 0xFFFF

def create_ipv4_header(source_ip: str, dest_ip: str, protocol: int, data_len: int) -> bytes:
    """constructs a 20-byte ipv4 header per rfc 791."""
    version = 4
    ihl = 5 # internet header length in 32-bit words
    version_ihl = (version << 4) + ihl
    
    total_len = 20 + 8 + data_len # ip header + udp header + data
    ident = 54321 # identification field
    frag_offset = 0
    ttl = 64
    
    src_addr = socket.inet_aton(source_ip)
    dest_addr = socket.inet_aton(dest_ip)
    
    # pack header fields without checksum to calculate it
    temp_header = struct.pack('!BBHHHBBH4s4s', version_ihl, 0, total_len, ident, frag_offset, ttl, protocol, 0, src_addr, dest_addr)
    checksum = calculate_checksum(temp_header)
    
    # pack the final header with the correct checksum
    return struct.pack('!BBHHHBBH4s4s', version_ihl, 0, total_len, ident, frag_offset, ttl, protocol, checksum, src_addr, dest_addr)

def create_udp_header(source_port: int, dest_port: int, data: bytes) -> bytes:
    """constructs an 8-byte udp header per rfc 768."""
    # udp checksum is optional in ipv4, so we set it to 0
    return struct.pack('!HHHH', source_port, dest_port, 8 + len(data), 0)