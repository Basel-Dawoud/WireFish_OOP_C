#include "sniffer.h"
#include <netinet/ip_icmp.h>  // For ICMP header


// Base class methods
PacketSniffer_t* packet_sniffer_create(const char *device) {
    PacketSniffer_t *sniffer = (PacketSniffer_t *)malloc(sizeof(PacketSniffer_t));
    sniffer->device = device;
    sniffer->handle = NULL;
    sniffer->filter_expr = NULL;
    
    sniffer->start_capture = packet_sniffer_start_capture;
    sniffer->set_filter = packet_sniffer_set_filter;
    sniffer->capture_packet = packet_sniffer_capture_packet;
    return sniffer;
}

void packet_sniffer_destroy(PacketSniffer_t *self) {
    if (self->handle) {
        pcap_close(self->handle);
    }
    free(self);
}

void packet_sniffer_start_capture(PacketSniffer_t *self) {
    self->handle = pcap_open_live(self->device, BUFSIZ, 1, 1000, NULL);
    if (self->handle == NULL) {
        printf("Error opening device %s\n", self->device);
        return;
    }
    printf("Started capturing on %s\n", self->device);
    if (self->filter_expr) {
        self->set_filter(self, self->filter_expr);
    }
    self->capture_packet(self);
}

/*
void packet_sniffer_set_filter(PacketSniffer_t *self, const char *filter) {
    struct bpf_program fp;
    if (pcap_compile(self->handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter\n");
        return;
    }
    if (pcap_setfilter(self->handle, &fp) == -1) {
        printf("Error setting filter\n");
        return;
    }
    printf("Filter set: %s\n", filter);
}


void packet_sniffer_set_filter(PacketSniffer_t *self, const char *filter) {
    if (self == NULL || self->handle == NULL) {
        printf("Error: PacketSniffer handle is not initialized.\n");
        return;
    }

    struct bpf_program fp;
    // Compile the filter
    if (pcap_compile(self->handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(self->handle));
        return;
    }

    // Set the compiled filter
    if (pcap_setfilter(self->handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(self->handle));
        pcap_freecode(&fp); // Free the compiled filter
        return;
    }

    // Successfully set the filter
    printf("Filter set: %s\n", filter);

    // Free the compiled filter program after using it
    pcap_freecode(&fp);
}
*/
void packet_sniffer_set_filter(PacketSniffer_t *self, const char *filter) {
    if (self == NULL || self->handle == NULL) {
        printf("Error: PacketSniffer handle is not initialized.\n");
        return;
    }

    struct bpf_program fp;
    // Compile the filter
    if (pcap_compile(self->handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(self->handle));
        printf("Invalid filter expression: %s\n", filter);  // Debugging the filter expression
        return;
    }

    // Set the compiled filter
    if (pcap_setfilter(self->handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(self->handle));
        pcap_freecode(&fp); // Free the compiled filter
        return;
    }

    // Successfully set the filter
    printf("Filter set: %s\n", filter);

    // Free the compiled filter program after using it
    pcap_freecode(&fp);
}


void packet_sniffer_capture_packet(PacketSniffer_t *self) {
    while (1) {
        self->packet = pcap_next(self->handle, &self->header);
        if (self->packet) {
            printf("Packet captured: %u bytes\n", self->header.len);
        }
    }
}

// IP Layer parsing
void packet_sniffer_parse_ip(IpLayer_t *self, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    printf("IP Protocol: %d\n", ip_header->ip_p);
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

// TCP Layer parsing
void packet_sniffer_parse_tcp(TransportLayer_t *self, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    printf("TCP Src Port: %u\n", ntohs(tcp_header->th_sport));
    printf("TCP Dst Port: %u\n", ntohs(tcp_header->th_dport));
}

// UDP Layer parsing
void packet_sniffer_parse_udp(TransportLayer_t *self, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    printf("UDP Src Port: %u\n", ntohs(udp_header->uh_sport));
    printf("UDP Dst Port: %u\n", ntohs(udp_header->uh_dport));
}

// ICMP Layer parsing
void packet_sniffer_parse_icmp(TransportLayer_t *self, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    printf("ICMP Type: %d\n", icmp_header->type);
}

// Application Layer parsing
void packet_sniffer_parse_http(ApplicationLayer_t *self, const u_char *packet) {
    // The first part of the packet is the Ethernet frame, followed by the IP and TCP headers.
    // We need to skip over these headers to reach the HTTP data.
    
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));  // Skip IP header
    u_char *http_data = (u_char *)(packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));  // Skip TCP header

    // Check for HTTP (usually text data starting with "GET", "POST", "HTTP", etc.)
    if (strncmp((char *)http_data, "GET ", 4) == 0 || 
        strncmp((char *)http_data, "POST ", 5) == 0 || 
        strncmp((char *)http_data, "HTTP/", 5) == 0) {
        printf("HTTP Packet Detected:\n");

        // Print the first 100 bytes of the HTTP request or response (for simplicity)
        printf("HTTP Data:\n");
        for (int i = 0; i < 100 && http_data[i] != '\0'; i++) {
            printf("%c", http_data[i]);
        }
        printf("\n");
    } else {
        printf("Not an HTTP packet.\n");
    }
}

void packet_sniffer_parse_https(ApplicationLayer_t *self, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));  // Skip IP header
    
    // Check if this is HTTPS traffic (default port 443 or SSL handshake)
    if (ntohs(tcp_header->th_sport) == 443 || ntohs(tcp_header->th_dport) == 443) {
        printf("HTTPS Packet Detected (Encrypted, cannot parse directly):\n");
        
        // You could detect SSL/TLS handshakes by inspecting the first few bytes.
        if (packet[14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4] == 0x16) {
            // 0x16 indicates a TLS/SSL handshake.
            printf("Detected SSL/TLS Handshake (Encrypted)\n");
        }
    } else {
        printf("Not an HTTPS packet.\n");
    }
}

void packet_sniffer_parse_ssh(ApplicationLayer_t *self, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));  // Skip IP header

    // Check if the packet is using port 22 (default SSH port)
    if (ntohs(tcp_header->th_sport) == 22 || ntohs(tcp_header->th_dport) == 22) {
        printf("SSH Packet Detected (Encrypted, cannot parse directly):\n");

        // You can check the first few bytes of the packet for the SSH handshake
        if (strncmp((char *)(packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4), "SSH-", 4) == 0) {
            printf("SSH Handshake Detected\n");
        }
    } else {
        printf("Not an SSH packet.\n");
    }
}


