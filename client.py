from scapy.all import rdpcap, DNS
import datetime
import socket

# Create UDP socket for communication with server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = ('127.0.0.1', 8081)

packets = rdpcap('http_packet.pcap')
dns_packets = []
id_counter = 0

# Gather all DNS query packets
for packet in packets:
    if packet.haslayer('UDP') and (packet['UDP'].sport == 53 or packet['UDP'].dport == 53) and packet.haslayer('DNS') and packet['DNS'].qr == 0:
        dns_packets.append(packet)

print(f"Found {len(dns_packets)} DNS query packets:")
print("-" * 50)

for i, packet in enumerate(dns_packets, 1):
    print(f"DNS Query {i}:")
    print(f"Source: {packet['IP'].src}:{packet['UDP'].sport}")
    print(f"Destination: {packet['IP'].dst}:{packet['UDP'].dport}")
    if packet.haslayer('DNS') and packet['DNS'].qd:
        print(f"Query: {packet['DNS'].qd.qname.decode()}")
        print(f"Query Type: {packet['DNS'].qd.qtype}")

    # Add custom header to DNS packets
    if DNS in packet and packet[DNS].qr == 0:
        now = datetime.datetime.now()
        hh = f"{now.hour:02d}" # 2 bytes
        mm = f"{now.minute:02d}"
        ss = f"{now.second:02d}"
        id_seq = f"{id_counter:02d}"
        custom = (hh + mm + ss + id_seq).encode('utf-8')
        original_dns = bytes(packet[DNS])
        modified = custom + original_dns

        print(f"Custom Header: {custom}")
        print(f"Modified Payload Length: {len(modified)} bytes")
        print(f"Modified Payload (first 50 bytes): {modified[:50]}")

        # Send DNS packet to server
        try:
            sock.sendto(modified, server_addr)
            print(f"Sent modified DNS packet {i} to server")

            # Receive response from server
            response, addr = sock.recvfrom(1024) # 1024 bytes
            print(f"Received response from server: {response.decode()}")

        except Exception as e:
            print(f"Error sending/receiving packet {i}: {e}")

        id_counter += 1

    print("-" * 50)

print("\nAll DNS packets processed and sent to server.")
sock.close()