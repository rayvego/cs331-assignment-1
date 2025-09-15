# CS331: Computer Networks - Assignment 1

This project implements a custom DNS resolver client and server in Python. It is designed to demonstrate a deep understanding of network programming, including low-level packet manipulation and professional software architecture.

## Features

- **Dual Socket Implementation:** The application can run in two modes:
    1.  **Raw Socket Mode:** Manually crafts and parses IPv4/UDP headers from scratch, demonstrating a fundamental understanding of network layers 3 and 4.
    2.  **Standard UDP Mode:** Uses standard `SOCK_DGRAM` sockets for a robust and portable implementation.
- **Custom DNS Protocol:** The client prepends a custom 8-byte header (`HHMMSSID`) to DNS queries.
- **Time-Based Resolution:** The server uses the timestamp from the custom header to route DNS queries to different IP pools.
- **High-Performance Architecture:** Employs a three-phase "Scan-Collect-Send Burst-Receive All" model to efficiently process large PCAP files without deadlocks.
- **Professional Workflow:** Uses a `Makefile` and environment variables for clean, repeatable builds and runs.

## Platform Compatibility

The behavior of low-level raw sockets is highly dependent on the operating system's kernel networking stack.

-   **Linux (Recommended):** The raw socket implementation (`make run`) is fully functional and tested on Ubuntu 24.04. The Linux kernel provides the necessary features and predictable behavior for this type of low-level packet crafting.
-   **macOS / Windows:** The raw socket implementation will **fail** on these platforms when communicating over the `localhost` loopback interface. Their kernels have security policies that reject the `sendto()` call with an `OSError: [Errno 22] Invalid argument`. This is a documented OS-level constraint, not a bug in the code.
-   **All Platforms:** The standard UDP implementation (`make run-udp`) is fully portable and will work correctly on Linux, macOS, and Windows.

## Project Structure

```
cs331-assignment-1/
├── data/
│   └── 9.pcap          # Input packet capture file
├── src/
│   ├── client.py       # Dual-mode client implementation
│   ├── server.py       # Dual-mode server implementation
│   ├── config.py       # Central configuration (reads env var)
│   └── packet_utils.py # Raw packet header construction logic
├── Makefile            # Main project automation script
├── requirements.txt    # Project dependencies
└── README.md           # This file
```

## Data Analysis

This project includes a script to analyze the contents of the input PCAP file and generate visualizations suitable for the final report.

To run the analysis:

```bash
make analyze
```

This command will:
1. Read the `data/9.pcap` file.
2. Analyze the protocol and DNS query distributions.
3. Save three high-quality plots (`.png` files) to a new `reports/` directory.

**Note on Fonts:** The script is configured to use "Oswald" and "Droid Serif" for a professional look. If these fonts are not installed on your system, it will gracefully fall back to default fonts.

## Setup and Execution

All commands should be run from the root directory of the project.

### 1. Installation

This command will create a Python virtual environment and install all necessary dependencies.

```bash
make install
```

### 2. Running the Application

**On a Linux environment (e.g., Ubuntu VM):**
To run the advanced raw socket implementation, use `make run`. This requires sudo privileges.

```bash
make run
```

**On macOS or for a portable test:**
To run the standard UDP implementation, use `make run-udp`. This does not require sudo.

```bash
make run-udp
```

### 3. Cleanup

To remove the virtual environment and all temporary files, use this command:

```bash
make clean
```