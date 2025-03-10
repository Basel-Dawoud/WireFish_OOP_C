# WireFish - A Packet Sniffer in C with OOP Structure

**WireFish** is a packet sniffer written in C that captures and analyzes network packets similar to Wireshark. The project uses Object-Oriented Programming (OOP) principles to provide a clean, modular, and extendable structure. WireFish supports filtering packets based on IP address and port, and it can handle multiple protocols like HTTP, FTP, and DNS.

---

## Features

- Captures network packets from available network devices.
- Filters packets by IP address and port number.
- Supports packet analysis for protocols like HTTP, FTP, and DNS.
- Implements OOP principles using C structs and function pointers for cleaner and more maintainable code.

---

## Key OOP Concepts in WireFish

### 1. **Encapsulation**
Encapsulation refers to the concept of bundling the data and the methods that operate on that data into a single unit (i.e., a class or struct). In WireFish, this is achieved using the `WireFish` struct and the `ProtocolHandler` struct.

- The `WireFish` struct encapsulates everything related to packet sniffing: the devices to capture packets from, the filter settings (IP address and port), and the pcap handle for packet capturing.
- The `ProtocolHandler` struct holds function pointers for handling protocol-specific tasks. This encapsulates how each protocol (HTTP, FTP, DNS) should handle its own data.

### 2. **Inheritance**
In C, inheritance is mimicked using structures. The `Payload` struct acts as the base structure, and the specific protocol structs like `HTTP`, `FTP`, and `DNS` inherit from `Payload`.

- The `Payload` structure defines shared properties and methods for handling the packet payload.
- Derived structs (`HTTP`, `FTP`, `DNS`) add their own specific methods for processing data, which makes it easy to extend the application with additional protocol handlers.

### 3. **Polymorphism**
Polymorphism allows different types of objects to respond to the same method in different ways. In WireFish, this is achieved through function pointers.

- The `Payload` structure contains a function pointer `digest_packet`, which is defined differently in each protocol handler (`HTTP`, `FTP`, `DNS`).
- When a packet is captured, the appropriate handler (based on the protocol) calls its own `digest_packet` function to process the packet.

### 4. **Abstraction**
Abstraction hides complex implementation details and provides a simple interface. In WireFish, the user interacts with simple functions like `wirefish_create`, `wirefish_start`, and `wirefish_stop` to manage packet sniffing, without needing to know how packets are captured or decoded internally.

- Functions like `wirefish_create` and `wirefish_start` abstract away the complexity of setting up and starting the packet capture process.
- Users don’t need to understand the internal details of how packets are filtered or how protocols are decoded.

---

## Code Structure

### 1. **WireFish Structure**
The `WireFish` structure holds all the details for packet sniffing, including the device names, pcap handles, filter criteria (IP and port), and error buffer.

```c
typedef struct _sniffer {
    char *devices[3];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle[3];
    struct pcap_pkthdr pkthdr;
    const char *filter_ip;
    int filter_port;
} sniffer;
```

- `devices[3]`: Holds the names of the network devices available for sniffing.
- `handle[3]`: Holds the pcap handles for capturing packets from the devices.
- `filter_ip` and `filter_port`: Used to filter the packets based on IP address and port.

### 2. **Protocol Handlers**
Each protocol (HTTP, FTP, DNS) is represented by a structure that contains specific handling logic. For example, the `HTTP` structure is derived from the `Payload` base structure.

```c
typedef struct HTTP {
    Payload payload;  // HTTP protocol data (inherits Payload)
} HTTP;
```

Each of these structures has a function to handle specific packets. For example, the `digest_http_packet` function handles HTTP packets.

```c
void digest_http_packet(const u_char *payload, int payload_length) {
    // Process the HTTP packet and extract useful information
}
```

### 3. **Sniffer Initialization**
The sniffer is initialized with the network device name and optional filter parameters (IP and port). The `sniffer_init` function sets up the pcap handles and applies the filter.

```c
void sniffer_init(sniffer *s, char *device, const char *filter_ip, int filter_port) {
    // Open the network device and apply filter if necessary
}
```

### 4. **Packet Handling**
The `packet_handler` function processes each captured packet, checks the protocol type (TCP, UDP, ICMP), and calls the appropriate function to handle the data. It then passes the packet data to the correct protocol handler (HTTP, FTP, DNS).

```c
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Process the packet based on its protocol (TCP/UDP/ICMP)
}
```

### 5. **Starting and Stopping the Sniffer**
The `sniffer_start` function begins the packet capture on all devices, and `sniffer_stop` stops the capture.

```c
void sniffer_start(sniffer *s) {
    // Start sniffing on the available devices
}

void sniffer_stop(sniffer *s) {
    // Stop sniffing on all devices
}
```

### 6. **Cleaning Up**
After sniffing, the `sniffer_cleanup` function ensures that all resources (such as memory and pcap handles) are properly released.

```c
void sniffer_cleanup(sniffer *s) {
    // Clean up memory and pcap handles
}
```

---

## How It Works

1. **Initialize Sniffer**: You provide a filter IP and an optional port to the program when running it. This configures which packets to capture.
   
2. **Start Sniffer**: Once initialized, the sniffer starts capturing packets from the network devices using pcap. The program processes each packet, printing information about the packet's protocol (IP, TCP/UDP header) and content (HTTP, FTP, DNS).
   
3. **Filter Packets**: You can filter the packets by IP address and port. If no filter is provided, it captures all packets.
   
4. **Handle Protocols**: Based on the protocol type (TCP, UDP, ICMP), the sniffer will call the corresponding function to process the payload. For example, HTTP packets are handled by the `digest_http_packet` function.

5. **Stop and Cleanup**: After sniffing, you can stop the sniffer and clean up the resources.

---

## Example Usage

```bash
sudo ./wirefish wlp3s0 80
```

This command will start sniffing on the network device `wlp3s0` and filter packets that are coming to or from port `80` (HTTP). The `sudo` is required since packet capturing usually needs root privileges.

--- 

## Conclusion

WireFish is a simple yet powerful packet sniffer that uses Object-Oriented Programming principles in C to manage network packet sniffing in a modular and extendable way. By leveraging encapsulation, inheritance, polymorphism, and abstraction, it allows for easy extension (e.g., adding more protocol handlers) and better code organization. Whether you are monitoring your network traffic or learning more about network protocols, WireFish provides a clear and efficient way to capture and analyze network packets.

## Contact

For any questions or inquiries, feel free to reach out via email:

**Email**: [baselinux2024@gmail.com]
