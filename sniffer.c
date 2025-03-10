#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Sniffer structure definition
typedef struct _sniffer {
    char *devices[3];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle[3];
    struct pcap_pkthdr pkthdr;
    const char *filter_ip;
    int filter_port;
} sniffer;

// Global protocol handlers (singletons)
static HTTPHandler http_handler = {
    .base.digest = http_digest,
    .port = 80,
    .protocol_name = "HTTP"
};

static FTPHandler ftp_handler = {
    .base.digest = ftp_digest,
    .port = 21,
    .protocol_name = "FTP"
};

static DNSHandler dns_handler = {
    .base.digest = dns_digest,
    .port = 53,
    .protocol_name = "DNS"
};



// Function Definitions

const char* wirefish_get_filter_ip(const sniffer* s) {
    return s->filter_ip;
}

int wirefish_get_filter_port(const sniffer* s) {
    return s->filter_port;
}

void wirefish_start(sniffer *s) {
    for (int i = 0; i < 3; i++) {
        if (s->devices[i] && s->handle[i]) {
            pcap_loop(s->handle[i], 0, packet_handler, (u_char *)s);
        }
    }
    printf("Sniffing started...\n");
}

void wirefish_stop(sniffer *s) {
    for (int i = 0; i < 3; i++) {
        if (s->devices[i] && s->handle[i]) {
            pcap_breakloop(s->handle[i]);
        }
    }
    printf("Sniffing stopped...\n");
}

sniffer* wirefish_create(const char* filter_ip, const char* filter_port, int device) {
    sniffer* new_sniffer = malloc(sizeof(sniffer));
    if (new_sniffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for sniffer.\n");
        return NULL;
    }

    // Initialize fields of new_sniffer, for example:
    new_sniffer->filter_ip = strdup(filter_ip);
    new_sniffer->filter_port = atoi(filter_port);
    // Initialize any other necessary fields

    return new_sniffer;
}


void wirefish_destroy(sniffer *s) {
    for (int i = 0; i < 3; i++) {
        if (s->handle[i]) {
            pcap_close(s->handle[i]);
        }
        if (s->devices[i]) {
            free(s->devices[i]);
        }
    }
    if (s->filter_ip) {
        free((void *)s->filter_ip);
    }
    printf("Sniffer cleaned up...\n");
}

// Main packet handler function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip = (struct iphdr *)(packet + 14);  // Skip Ethernet header
    int ip_header_len = ip->ihl * 4;

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

    ProtocolHandler *handler = NULL;
    const u_char *payload = NULL;
    int payload_length = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
        int tcp_header_len = tcp->doff * 4;
        if (pkthdr->len < (14 + ip_header_len + tcp_header_len)) {
            printf("Packet is too small to contain a TCP header.\n");
            return;
        }
        payload = packet + 14 + ip_header_len + tcp_header_len;
        payload_length = pkthdr->len - (14 + ip_header_len + tcp_header_len);

        switch(ntohs(tcp->dest)) {
            case 80: handler = (ProtocolHandler*)&http_handler; break;
            case 21: handler = (ProtocolHandler*)&ftp_handler; break;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_header_len);
        if (pkthdr->len < (14 + ip_header_len + sizeof(struct udphdr))) {
            printf("Packet is too small to contain a UDP header.\n");
            return;
        }
        payload = packet + 14 + ip_header_len + sizeof(struct udphdr);
        payload_length = pkthdr->len - (14 + ip_header_len + sizeof(struct udphdr));

        if(ntohs(udp->dest) == 53) {
            handler = (ProtocolHandler*)&dns_handler;
        }
    }

    if(handler && payload_length > 0) {
        handler->digest(handler, payload, payload_length);
    }
}

void http_digest(ProtocolHandler *self, const u_char *payload, int length) {
    HTTPHandler *http = (HTTPHandler*)self;
    printf("[%s/%d] Digesting packet (%d bytes):\n", http->protocol_name, http->port, length);
    for(int i = 0; i < 100 && i < length; i++) {
        if(payload[i] == '\0') break;
        printf("%c", payload[i]);
    }
    printf("\n");
}

void ftp_digest(ProtocolHandler *self, const u_char *payload, int length) {
    FTPHandler *ftp = (FTPHandler*)self;
    printf("[%s/%d] Digesting packet (%d bytes):\n", ftp->protocol_name, ftp->port, length);
    for(int i = 0; i < 100 && i < length; i++) {
        if(payload[i] == '\0') break;
        printf("%c", payload[i]);
    }
    printf("\n");
}

void dns_digest(ProtocolHandler *self, const u_char *payload, int length) {
    DNSHandler *dns = (DNSHandler*)self;
    printf("[%s/%d] Digesting packet (%d bytes):\n", dns->protocol_name, dns->port, length);
    for(int i = 0; i < 100 && i < length; i++) {
        if(payload[i] == '\0') break;
        printf("%02x ", payload[i]);
    }
    printf("\n");
}
