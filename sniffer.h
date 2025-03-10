#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <netinet/ip.h>  // For struct iphdr
#include <netinet/tcp.h> // For struct tcphdr
#include <netinet/udp.h> // For struct udphdr

// Opaque types for encapsulation
typedef struct _sniffer sniffer;
typedef struct ProtocolHandler ProtocolHandler;

// Base Protocol Handler
typedef struct ProtocolHandler {
    void (*digest)(ProtocolHandler *self, const u_char *payload, int length);
} ProtocolHandler;

// Protocol implementations
typedef struct {
    ProtocolHandler base;
    int port;
    const char *protocol_name;
} HTTPHandler;

typedef struct {
    ProtocolHandler base;
    int port;
    const char *protocol_name;
} FTPHandler;

typedef struct {
    ProtocolHandler base;
    int port;
    const char *protocol_name;
} DNSHandler;


// Function declarations
const char* wirefish_get_filter_ip(const sniffer* s);
int wirefish_get_filter_port(const sniffer* s);
void wirefish_start(sniffer *s);
void wirefish_stop(sniffer *s);
sniffer* wirefish_create(const char* filter_ip, const char* filter_port, int device);
void wirefish_destroy(sniffer *s);
void wirefish_init(sniffer* s, const char* filter_ip, const char* filter_port, int device);

// Function declarations for protocol handlers
void http_digest(ProtocolHandler *self, const u_char *payload, int length);
void ftp_digest(ProtocolHandler *self, const u_char *payload, int length);
void dns_digest(ProtocolHandler *self, const u_char *payload, int length);

// Packet handler function declaration
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif // SNIFFER_H
