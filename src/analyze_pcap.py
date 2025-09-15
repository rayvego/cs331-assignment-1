# path: src/analyze_pcap.py

import os
import sys
import logging
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from collections import Counter
from scapy.all import PcapReader, TCP, UDP, DNS, DNSQR
from tqdm import tqdm
import config

# basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr)

# manually register fonts to ensure they are available to matplotlib
font_paths_to_check = [
    os.path.expanduser('~/.local/share/fonts'), os.path.expanduser('~/Library/Fonts'),
    '/usr/share/fonts', '/usr/local/share/fonts'
]
for path in font_paths_to_check:
    if os.path.exists(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith(('.ttf', '.otf')):
                    try:
                        fm.fontManager.addfont(os.path.join(root, file))
                    except:
                        continue

# define plot styling
FONT_TITLE = {'family': 'Oswald', 'size': 16, 'weight': 'bold'}
FONT_LABEL = {'family': 'Droid Serif', 'size': 12}
FONT_TICKS = {'family': 'Droid Serif', 'size': 10}
COLOR_PRIMARY, COLOR_SECONDARY, COLOR_TEXT = '#B45F06', '#783F04', '#666666'

# attempt to apply custom font settings
try:
    plt.rcParams.update({
        'text.color': COLOR_TEXT, 'axes.labelcolor': COLOR_TEXT,
        'xtick.color': COLOR_TEXT, 'ytick.color': COLOR_TEXT,
        'font.family': 'serif', 'font.serif': [FONT_LABEL['family']]
    })
except Exception as e:
    logging.warning(f"could not set custom fonts, falling back to default: {e}")


def plot_protocol_distribution(protocol_counts: Counter, total_packets: int):
    """generates and saves a bar chart of packet protocol distribution."""
    labels = list(protocol_counts.keys())
    counts = list(protocol_counts.values())
    percentages = [(c / total_packets) * 100 for c in counts]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(labels, counts, color=COLOR_PRIMARY)
    
    ax.set_title('Packet Protocol Distribution', fontdict=FONT_TITLE, pad=20)
    ax.set_xlabel('Number of Packets', fontdict=FONT_LABEL)
    ax.tick_params(axis='y', labelsize=FONT_TICKS['size'])
    ax.tick_params(axis='x', labelsize=FONT_TICKS['size'])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    for bar, pct in zip(bars, percentages):
        ax.text(bar.get_width(), bar.get_y() + bar.get_height()/2,
                f' {bar.get_width():,} ({pct:.1f}%)',
                va='center', ha='left', fontdict=FONT_TICKS)

    output_path = os.path.join(config.REPORTS_DIR, 'figure1_protocol_distribution.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logging.info(f"saved protocol distribution chart to {output_path}")
    plt.close()


def plot_top_domains(domain_counts: Counter):
    """generates and saves a bar chart of the top 10 most queried dns domains."""
    top_10 = domain_counts.most_common(10)
    domains = [item[0] for item in top_10][::-1] # reverse for horizontal bar chart
    counts = [item[1] for item in top_10][::-1]

    fig, ax = plt.subplots(figsize=(10, 7))
    ax.barh(domains, counts, color=COLOR_PRIMARY)
    
    ax.set_title('Top 10 Most Queried DNS Domains', fontdict=FONT_TITLE, pad=20)
    ax.set_xlabel('Number of Queries', fontdict=FONT_LABEL)
    ax.tick_params(axis='y', labelsize=FONT_TICKS['size'])
    ax.tick_params(axis='x', labelsize=FONT_TICKS['size'])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    output_path = os.path.join(config.REPORTS_DIR, 'figure2_top_dns_domains.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logging.info(f"saved top domains chart to {output_path}")
    plt.close()


def plot_query_types(qtype_counts: Counter):
    """generates and saves a bar chart of the distribution of dns query types."""
    qtype_map = {
        1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX',
        16: 'TXT', 28: 'AAAA', 33: 'SRV'
    }
    labels = [qtype_map.get(qtype, f'Type({qtype})') for qtype in qtype_counts.keys()]
    counts = list(qtype_counts.values())
            
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(labels, counts, color=COLOR_SECONDARY)

    ax.set_title('Distribution of DNS Query Types', fontdict=FONT_TITLE, pad=20)
    ax.set_ylabel('Number of Queries', fontdict=FONT_LABEL)
    ax.tick_params(axis='x', labelsize=FONT_TICKS['size'])
    ax.tick_params(axis='y', labelsize=FONT_TICKS['size'])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()

    output_path = os.path.join(config.REPORTS_DIR, 'figure3_dns_query_types.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logging.info(f"saved query types chart to {output_path}")
    plt.close()


def analyze_pcap(pcap_path: str):
    """main analysis function to read pcap and generate all plots."""
    if not os.path.exists(pcap_path):
        logging.error(f"analysis failed: pcap file not found at '{pcap_path}'")
        return

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    protocol_counts = Counter()
    domain_counts = Counter()
    qtype_counts = Counter()
    
    try:
        file_size = os.path.getsize(pcap_path)
        with PcapReader(pcap_path) as pcap_reader, \
             tqdm(total=file_size, unit='B', unit_scale=True, desc="analyzing pcap") as pbar:
            for packet in pcap_reader:
                pbar.update(pcap_reader.f.tell() - pbar.n)
                
                # count protocols
                if packet.haslayer(TCP): protocol_counts['TCP'] += 1
                elif packet.haslayer(UDP): protocol_counts['UDP'] += 1
                else: protocol_counts['Other'] += 1

                # count dns domains and query types
                if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                    try:
                        domain = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        domain_counts[domain] += 1
                        qtype_counts[packet[DNS].qd.qtype] += 1
                    except Exception:
                        continue
            
            if pbar.n < file_size:
                pbar.update(file_size - pbar.n)
    except Exception as e:
        logging.error(f"could not process pcap file: {e}")
        return

    total_packets = sum(protocol_counts.values())
    if total_packets > 0:
        plot_protocol_distribution(protocol_counts, total_packets)
    if domain_counts:
        plot_top_domains(domain_counts)
    if qtype_counts:
        plot_query_types(qtype_counts)

    logging.info("pcap analysis complete.")

if __name__ == "__main__":
    analyze_pcap(config.PCAP_FILE_PATH)