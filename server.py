import socket
import json
import datetime

IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

TIME_RULES = {
    "morning": {
        "time_range": "04:00-11:59",
        "hash_mod": 5,
        "ip_pool_start": 0,
        "description": "Morning traffic routed to first 5 IPs"
    },
    "afternoon": {
        "time_range": "12:00-19:59",
        "hash_mod": 5,
        "ip_pool_start": 5,
        "description": "Afternoon traffic routed to middle 5 IPs"
    },
    "night": {
        "time_range": "20:00-03:59",
        "hash_mod": 5,
        "ip_pool_start": 10,
        "description": "Night traffic routed to last 5 IPs"
    }
}

def get_time_period(hour):
    """Determine time period based on hour"""
    if 4 <= hour <= 11:
        return "morning"
    elif 12 <= hour <= 19:
        return "afternoon"
    else:
        return "night"

def parse_custom_header(custom_header):
    """Parse custom header in format HHMMSSID"""
    try:
        header_str = custom_header.decode('utf-8')
        if len(header_str) >= 8:
            hour = int(header_str[0:2])
            session_id = int(header_str[6:8])
            return hour, session_id
        return None
    except:
        return None

def resolve_ip(custom_header):
    """Apply DNS resolution rules based on custom header"""
    parsed = parse_custom_header(custom_header)
    if not parsed: # Fallback
        return IP_POOL[0], "unknown", 0, 0

    hour, session_id = parsed # Minute and second are not used
    time_period = get_time_period(hour)
    rule = TIME_RULES[time_period]

    hash_value = session_id % rule["hash_mod"]
    ip_index = rule["ip_pool_start"] + hash_value

    resolved_ip = IP_POOL[ip_index]

    return resolved_ip, time_period, hash_value, ip_index

def print_dns_report_table(dns_report, title="DNS RESOLUTION REPORT"):
    """Print DNS resolution report in table format"""
    if not dns_report:
        print("No DNS reports to display.")
        return

    print(f"\n{title}")
    print("=" * 80)
    print("Custom header value (HHMMSSID)\tDomain name\t\tResolved IP address")
    print("-" * 80)
    for entry in dns_report:
        print(f"{entry['custom_header']}\t\t\t{entry['domain']}\t\t{entry['resolved_ip']}")
    print("=" * 80)

# Store DNS resolution report
dns_report = []

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 12345))

    print("DNS Resolution Server started on port 12345")
    print("IP Pool:", IP_POOL)
    print("Time-based routing rules loaded")
    print("-" * 60)

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)

                if len(data) < 8:
                    print(f"Invalid packet received from {addr}: too short")
                    continue

                # Extract custom header
                custom_header = data[:8]
                dns_data = data[8:]

                print(f"\nReceived DNS packet from {addr}")
                print(f"Custom Header: {custom_header}")
                print(f"DNS Data Length: {len(dns_data)} bytes")

                domain_name = "unknown"
                # Example: 3www3google3com0 -> www.google.com
                try:
                    if len(dns_data) > 12:  # DNS header is 12 bytes
                        domain_bytes = dns_data[12:]  # Skip DNS header
                        domain_parts = []
                        i = 0
                        while i < len(domain_bytes) and domain_bytes[i] != 0:
                            length = domain_bytes[i]
                            if length == 0:
                                break
                            if i + length + 1 < len(domain_bytes):
                                part = domain_bytes[i+1:i+1+length].decode('utf-8', errors='ignore') # Decode domain name
                                domain_parts.append(part)
                                i += length + 1
                            else:
                                break
                        if domain_parts:
                            domain_name = '.'.join(domain_parts)
                except Exception as e:
                    print(f"Error parsing domain: {e}")

                # DNS resolution
                resolved_ip, time_period, hash_value, ip_index = resolve_ip(custom_header)

                response = f"Resolved {domain_name} -> {resolved_ip} (Time: {time_period}, Rule: {hash_value}@{ip_index})"

                # Send response
                sock.sendto(response.encode(), addr)

                # Store in report
                header_str = custom_header.decode('utf-8', errors='ignore')
                dns_report.append({
                    "custom_header": header_str,
                    "domain": domain_name,
                    "resolved_ip": resolved_ip,
                    "time_period": time_period,
                    "hash_value": hash_value,
                    "ip_index": ip_index
                })

                print(f"Resolved: {domain_name} -> {resolved_ip}")
                print(f"Time Period: {time_period}, Hash: {hash_value}, IP Index: {ip_index}")

            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

            # # Print report every 10 resolutions
            # if len(dns_report) % 10 == 0 and len(dns_report) > 0:
            #     print_dns_report_table(dns_report[-10:], f"DNS RESOLUTION REPORT (Last 10)")

    except KeyboardInterrupt:
        print("\n\nServer shutdown requested...")
        if len(dns_report) > 0:
            print_dns_report_table(dns_report, "FINAL DNS RESOLUTION REPORT")
        else:
            print("No DNS queries were processed.")
        print("Server stopped.")
        sock.close()
        exit(0)