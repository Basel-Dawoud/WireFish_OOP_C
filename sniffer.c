#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string.h>

// Sniffer structure definition
typedef struct _sniffer {
    char *devices[3];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle[3];
    struct pcap_pkthdr pkthdr;
    const char *filter_ip;
    int filter_port;
} sniffer;

const char* wirefish_get_filter_ip(const sniffer* s) {
    return s->filter_ip;
  }

// Protocol Structure: Base structure for all protocols (HTTP, DNS, FTP)
typedef struct Payload {    
    char *protocol;
    int portNum;

    // Function pointer for handling protocol-specific data
    void (*digest_packet)(const u_char *packet);
} Payload;

// Derived structures for HTTP, DNS, and FTP protocols
typedef struct HTTP {
    Payload payload;  // HTTP protocol data (inherits Payload)
} HTTP;

typedef struct DNS {
    Payload payload;  // DNS protocol data (inherits Payload)
} DNS;

typedef struct FTP {
    Payload payload;  // FTP protocol data (inherits Payload)
} FTP;


// Initializes the sniffer with device and filter criteria (IP/port)
void sniffer_init(sniffer *s, char *device, const char *filter_ip, int filter_port) {
    pcap_if_t *alldevsp;  // Declare as pcap_if_t *

    s->filter_ip = filter_ip ? strdup(filter_ip) : NULL;
    s->filter_port = filter_port;

    if (!device){
        if (pcap_findalldevs(&alldevsp, s->errbuf) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", s->errbuf);
            exit(1);
        }
    
        if (alldevsp == NULL || alldevsp->name == NULL) {
            fprintf(stderr, "No devices found.\n");
            exit(1);
        }
        
        if(alldevsp->name != NULL)
        {
            s->devices[0] = alldevsp->name;
        }
        
        if(alldevsp->next->name != NULL)
        {
            s->devices[1] = alldevsp->next->name;
        }
        
        if(alldevsp->next->next->name != NULL)
        {
            s->devices[2] = alldevsp->next->next->name;                
        }

        pcap_freealldevs(alldevsp);  // Free the entire list of devices
    

    } else {
        s->devices[0] = device;
        s->devices[1] = NULL;
        s->devices[2] = NULL;
    }


    // Open devices for packet capture
    for (int i = 0; i < 3; i++) {
        if (s->devices[i] != NULL) {
            s->handle[i] = pcap_open_live(s->devices[i], BUFSIZ, 1, 1000, s->errbuf);
            if (s->handle[i] == NULL) {
                printf("Error opening device %s: %s\n", s->devices[i], s->errbuf);
            }
        }
    }

    // Apply filter if filter_ip or filter_port is specified
    if (filter_ip || filter_port) {
        char filter_exp[100];
        if (filter_ip && filter_port) {
            snprintf(filter_exp, sizeof(filter_exp), "host %s and port %d", filter_ip, filter_port);
        } else if (filter_ip) {
            snprintf(filter_exp, sizeof(filter_exp), "host %s", filter_ip);
        } else if (filter_port) {
            snprintf(filter_exp, sizeof(filter_exp), "port %d", filter_port);
        }

        struct bpf_program fp;
        for (int i = 0; i < 3; i++) {
            if (s->handle[i] != NULL) {
                if (pcap_compile(s->handle[i], &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
                    printf("Error compiling filter: %s\n", pcap_geterr(s->handle[i]));
                }
                if (pcap_setfilter(s->handle[i], &fp) == -1) {
                    printf("Error setting filter: %s\n", pcap_geterr(s->handle[i]));
                }
            }
        }
    }
}

// Handles each captured packet
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Skip Ethernet header (14 bytes) and point to the IP header
    struct iphdr *ip = (struct iphdr *)(packet + 14);  // Skip Ethernet header
    int ip_header_len = ip->ihl * 4;  // IP header length

    // Ensure the packet is large enough to hold an IP header
    if (pkthdr->len < 14 + ip_header_len) {
        printf("Packet is too small to contain an IP header.\n");
        return;
    }

    printf("Packet captured:\n");
    printf("IP Header:\n");
    printf("   |-IP Version        : %d\n", (unsigned int)ip->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)ip->tos);
    printf("   |-IP Total Length   : %d Bytes (Size of Packet)\n", ntohs(ip->tot_len));
    printf("   |-Identification    : %d\n", ntohs(ip->id));
    printf("   |-TTL               : %d\n", (unsigned int)ip->ttl);
    printf("   |-Protocol          : %d\n", (unsigned int)ip->protocol);
    printf("   |-Checksum          : %d\n", ntohs(ip->check));
    printf("   |-Source IP         : %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    printf("   |-Destination IP    : %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

    // Check if the IP header is large enough to hold the protocol-specific header
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len); // Skip IP header
        printf("TCP Header:\n");
        printf("   |-Source Port      : %u\n", ntohs(tcp->source));
        printf("   |-Destination Port : %u\n", ntohs(tcp->dest));
        printf("   |-Sequence Number  : %u\n", ntohl(tcp->seq));
        printf("   |-Acknowledgment   : %u\n", ntohl(tcp->ack_seq));
        printf("   |-Header Length    : %d DWORDS or %d Bytes\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);

        // Now process the payload of the TCP packet
        const u_char *payload = packet + 14 + ip_header_len + tcp->doff * 4; // Skip IP + TCP headers
        int payload_length = pkthdr->len - (14 + ip_header_len + tcp->doff * 4); // Calculate remaining length

        if (ntohs(tcp->dest) == 80) {
            // Digest HTTP packets if the destination port is 80 (HTTP)
            digest_http_packet(payload, payload_length);
        } else if (ntohs(tcp->dest) == 21) {
            // Digest FTP packets if the destination port is 21 (FTP)
            digest_ftp_packet(payload, payload_length);
        }
    } 
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_header_len); // Skip IP header
        printf("UDP Header:\n");
        printf("   |-Source Port      : %u\n", ntohs(udp->source));
        printf("   |-Destination Port : %u\n", ntohs(udp->dest));
        printf("   |-Length           : %u\n", ntohs(udp->len));
        printf("   |-Checksum         : %u\n", ntohs(udp->check));

        // Now process the payload of the UDP packet
        const u_char *payload = packet + 14 + ip_header_len + sizeof(struct udphdr); // Skip IP + UDP headers
        int payload_length = pkthdr->len - (14 + ip_header_len + sizeof(struct udphdr)); // Calculate remaining length

        if (ntohs(udp->dest) == 53) {
            // Digest DNS packets if the destination port is 53 (DNS)
            digest_dns_packet(payload, payload_length);
        }
    } 
    else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(packet + 14 + ip_header_len); // Skip IP header
        printf("ICMP Header:\n");
        printf("   |-Type      : %d\n", icmp->type);
        printf("   |-Code      : %d\n", icmp->code);
        printf("   |-Checksum  : %d\n", icmp->checksum);
    } 
    else {
        printf("Unknown Protocol\n");
    }
}


// Starts the sniffing process
void sniffer_start(sniffer *s) {
    for (int i = 0; i < 3; i++) {
        if (s->devices[i] && s->handle[i]) {
            pcap_loop(s->handle[i], 0, packet_handler, (u_char *)s);
        }
    }
    printf("Sniffing started...\n");
}

// Stops sniffing on all devices
void sniffer_stop(sniffer *s) {
    for (int i = 0; i < 3; i++) {
        if (s->devices[i] && s->handle[i]) {
            pcap_breakloop(s->handle[i]);
        }
    }
    printf("Sniffing stopped...\n");
}

// Cleans up sniffer resources
void sniffer_cleanup(sniffer *s) {
    for (int i = 0; i < 3; i++) {
        if (s->handle[i]) {
            pcap_close(s->handle[i]);
        }
        if (s->devices[i]) {
            free(s->devices[i]);  // Free device names
        }
    }
    if (s->filter_ip) {
        free((void *)s->filter_ip);  // Free filter IP
    }
    printf("Sniffer cleaned up...\n");
}

// Digest HTTP packets (based on the payload)
void digest_http_packet(const u_char *payload, int payload_length) {
    printf("Digesting HTTP Packet (first 100 bytes):\n");
    for (int i = 0; i < 100 && i < payload_length; i++) {
        if (payload[i] == '\0') break; // Stop at null byte (end of string)
        printf("%c", payload[i]);
    }
    printf("\n");

    // Simple check for HTTP method or response code
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') {
        printf("Detected HTTP GET request\n");
    }
}

// Digest FTP packets (based on the payload)
void digest_ftp_packet(const u_char *payload, int payload_length) {
    printf("Digesting FTP Packet (first 100 bytes):\n");
    for (int i = 0; i < 100 && i < payload_length; i++) {
        if (payload[i] == '\0') break; // Stop at null byte (end of string)
        printf("%c", payload[i]);
    }
    printf("\n");

    // Look for FTP commands (like USER)
    if (payload[0] == 'U' && payload[1] == 'S' && payload[2] == 'E' && payload[3] == 'R') {
        printf("Detected FTP USER command\n");
    }
}

// Digest DNS packets (based on the payload)
void digest_dns_packet(const u_char *payload, int payload_length) {
    printf("Digesting DNS Packet (first 100 bytes):\n");
    for (int i = 0; i < 100 && i < payload_length; i++) {
        if (payload[i] == '\0') break; // Stop at null byte (end of string)
        printf("%c", payload[i]);
    }
    printf("\n");

    // Look for DNS query types (e.g., A record)
    if (payload[0] == 0x00 && payload[1] == 0x01) {
        printf("Detected DNS A record query\n");
    }
}

