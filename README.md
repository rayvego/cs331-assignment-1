# CS331: Computer Networks - Assignment 1

This project is a comprehensive implementation of a custom DNS resolution system, developed for the CS331 course. It features a Python-based client-server application that demonstrates advanced network programming concepts, including low-level packet manipulation with raw sockets, custom protocol design, and robust process management.

**Team Members:**
*   Devansh Lodha - 23110091
*   Mohit Kamlesh Panchal - 23110208

---

### Table of Contents
1.  [Project Overview](#project-overview)
2.  [Features](#features)
3.  [Platform Compatibility](#platform-compatibility)
4.  [Project Structure](#project-structure)
5.  [Setup and Execution](#setup-and-execution)
6.  [Project Report and Key Files](#project-report-and-key-files)
7.  [License](#license)

---

## Project Overview

The core of this assignment is a DNS resolver (Task 1) that operates in two modes: a low-level raw socket mode and a high-level standard UDP mode. The client parses DNS queries from a given PCAP file, prepends a custom 8-byte `HHMMSSID` header, and sends them to a server. The server implements a set of time-based load-balancing rules to resolve these queries to a specific IP address from a predefined pool.

The project also includes a detailed analysis of the Traceroute protocol's behavior on different operating systems (Task 2), with findings and packet captures included in the final report.

## Features

-   **Dual Socket Modes:** Runs using both raw sockets (`SOCK_RAW`) for manual IPv4/UDP header construction and standard datagram sockets (`SOCK_DGRAM`) for portability.
-   **Custom Application-Layer Protocol:** Implements the `HHMMSSID` header to correlate requests and responses over connectionless UDP.
-   **Time-Based IP Resolution:** The server dynamically selects an IP pool (morning, afternoon, night) based on the timestamp in the custom header.
-   **Strict DNS Filtering:** Includes an optional mode to process only standard DNS queries sent to port 53, filtering out mDNS and other local discovery traffic.
-   **Automated Workflow:** A robust `Makefile` handles dependency installation, environment setup, execution of all run modes, and cleanup.
-   **Detailed PCAP Analysis:** A dedicated script (`analyze_pcap.py`) generates professional plots for protocol and DNS query distribution, which are used in the final report.

## Platform Compatibility

The behavior of low-level raw sockets is highly dependent on the operating system.

-   **Linux (Recommended):** The raw socket implementation (`make run` and `make run-raw-strict`) is fully functional and tested on Ubuntu 24.04.
-   **macOS / Windows:** The raw socket implementation may fail on these platforms when communicating over the `localhost` loopback interface due to kernel security policies. This is a known OS-level constraint.
-   **All Platforms:** The standard UDP implementation (`make run-udp` and `make run-udp-strict`) is fully portable and works correctly on Linux, macOS, and Windows.

## Project Structure

```
.
├── .gitignore
├── cs331_assignment1_report_23110091_23110208.pdf  # The final project report
├── data/
│   └── 9.pcap                                      # Input packet capture file
├── docs/                                           # Assignment specification documents
│   ├── assignment_1.pdf
│   └── ...
├── LICENSE
├── Makefile                                        # Main project automation script
├── README.md                                       # This file
├── reports/                                        # Generated plots and traceroute captures
│   ├── figure*.png
│   └── *.pcapng
├── requirements.txt                                # Project dependencies
└── src/
    ├── client.py                                   # Client implementation (with filter logic)
    ├── server.py                                   # Server implementation (with routing rules)
    ├── config.py                                   # Central configuration (reads environment variables)
    ├── packet_utils.py                             # Raw packet header construction functions
    └── analyze_pcap.py                             # Script to analyze pcap and generate plots
```

## Setup and Execution

All commands should be run from the project's root directory.

### 1. Installation

This command creates a Python virtual environment (`.venv/`) and installs all dependencies from `requirements.txt`.

```bash
make install
```

### 2. Running the DNS Resolver

The application can be run in four different modes.

#### Default Mode (All DNS/mDNS Queries)
These commands process all DNS and mDNS queries found in the PCAP file.

-   **Using standard UDP sockets (portable, no sudo required):**
    ```bash
    make run-udp
    ```
-   **Using raw sockets (Linux only, requires sudo):**
    ```bash
    make run-raw
    ```

#### Strict Mode (Standard DNS on Port 53 Only)
These commands filter the PCAP file to process only standard DNS queries destined for port 53.

-   **Using standard UDP sockets (portable, no sudo required):**
    ```bash
    make run-udp-strict
    ```
-   **Using raw sockets (Linux only, requires sudo):**
    ```bash
    make run-raw-strict
    ```

### 3. Running the PCAP Analysis

This command reads `data/9.pcap`, analyzes its contents, and saves several plots to the `reports/` directory.

```bash
make analyze
```

### 4. Cleanup

To remove the virtual environment and all temporary files (`__pycache__`, `.pyc`), run:

```bash
make clean
```

## Project Report and Key Files

| File                                                              | Description                                             |
| ----------------------------------------------------------------- | ------------------------------------------------------- |
| [**Final Report (PDF)**](./cs331_assignment1_report_23110091_23110208.pdf) | The complete assignment report with all analysis and results. |
| [`Makefile`](./Makefile)                                          | The automation script for building, running, and cleaning. |
| [`src/client.py`](./src/client.py)                                | The main client script.                                 |
| [`src/server.py`](./src/server.py)                                | The main server script.                                 |
| [`src/config.py`](./src/config.py)                                | Central configuration file.                             |
| [`src/packet_utils.py`](./src/packet_utils.py)                    | Low-level IP/UDP header creation logic.                 |

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.