# WireFish - Packet Sniffer

**WireFish** is a simple packet sniffer tool written in C that uses the `libpcap` library to capture and analyze network packets. This tool can parse and display information about network packets, including IP, TCP, UDP, ICMP, HTTP, HTTPS, and SSH.

It provides support for filtering packets based on IP addresses and port numbers, offering a user-friendly command-line interface to monitor and inspect network traffic.

## Features

- **Capture and analyze packets** on a specified network interface.
- Display information about **IP packets** (source/destination IP addresses, etc.).
- Analyze **TCP**, **UDP**, and **ICMP** protocol layers.
- Support for **application layer protocols** like **HTTP**, **HTTPS**, and **SSH**.
- **Packet filtering** based on IP addresses and ports.
- Written in C with **object-oriented programming (OOP)** concepts using structures and function pointers.

## Requirements

To compile and run **WireFish**, you'll need:

- **Linux** operating system.
- **libpcap** library (for packet capturing).
- **gcc** or any other C compiler.

### Installing libpcap (if not already installed)

For **Debian/Ubuntu** or other **APT-based systems**:

```bash
sudo apt-get install libpcap-dev
```

For **RedHat/CentOS/Fedora** or **YUM-based systems**:

```bash
sudo yum install libpcap-devel
```

## Installation

1. Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/wirefish.git
cd wirefish
```

2. Compile the project using `make`:

```bash
make
```

This will generate an executable file called `wirefish`.

## Usage

To start capturing packets on a network interface, run the following command:

```bash
sudo ./wirefish -i <interface>
```

Where `<interface>` is the name of the network interface you want to capture packets on (e.g., `eth0`, `wlp3s0`, `enp2s0`).

### Example:

```bash
sudo ./wirefish -i wlp3s0
```

This command starts capturing packets on the `wlp3s0` interface.

### Filtering Packets

You can apply filters to capture specific packets. The filter expressions are based on **BPF (Berkeley Packet Filter)** syntax. 

To filter for HTTP traffic (port 80), use:

```bash
sudo ./wirefish -i wlp3s0 "tcp port 80"
```

Other common filter examples:

- **Capture all traffic from a specific IP address**:

```bash
sudo ./wirefish -i wlp3s0 "host 192.168.1.1"
```

- **Capture traffic from a specific IP and port**:

```bash
sudo ./wirefish -i wlp3s0 "host 192.168.1.1 and tcp port 443"
```

If no filter is specified, all packets on the interface will be captured.

## Code Structure

### Key Files

- **`main.c`**: The entry point of the program that sets up the sniffer and starts the packet capture loop.
- **`sniffer.c`**: Contains the logic for packet capture, parsing, and filtering.
- **`sniffer.h`**: Header file with the `PacketSniffer_t` structure definition and function declarations.
- **`makefile`**: The build configuration file used to compile the project.
- **`README.md`**: This file, which provides the documentation for the project.

### OOP Concepts in C

The program uses **object-oriented programming (OOP)** principles in C through the use of structures and function pointers to simulate objects and methods. Here's how it works:

- **PacketSniffer_t structure**: Represents a packet sniffer object with data and methods associated with it.
- **Methods**: Functions are associated with the structure to allow the sniffer to initialize, start capturing, set filters, and parse protocols.

### Parsing Protocols

The program parses the following protocols:

- **IP Layer**: Captures and displays source and destination IP addresses.
- **TCP Layer**: Displays TCP header information (e.g., source/destination ports).
- **UDP Layer**: Displays UDP header information (e.g., source/destination ports).
- **ICMP Layer**: Displays ICMP packet type and code.
- **Application Layer**:
  - **HTTP**: Basic parsing of HTTP packets.
  - **HTTPS**: Displays encrypted data (decryption is not currently supported).
  - **SSH**: Displays encrypted SSH packets (decryption is not currently supported).

## Troubleshooting

### Segmentation Faults or Crashes

- Ensure the network interface is active and connected.
- Ensure you're using `sudo` to run the program, as capturing packets typically requires root privileges.

### Filter Errors

- If you encounter a filter parsing error, verify that the filter expression is correctly formatted according to the [BPF filter syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html).

### No Packets Captured

- Ensure there is network traffic on the selected interface.
- Test without any filter (e.g., `sudo ./wirefish -i wlp3s0 ""`) to check if packets are being captured.

### Contact

For any questions or feedback, please feel free to reach out via GitHub issues or contact me at:

- **Email**: Baseldawoud2003@gmail.com
