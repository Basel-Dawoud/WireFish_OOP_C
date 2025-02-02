#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

// Base class for PacketSniffer
typedef struct PacketSniffer {
    pcap_t *handle;
    const char *device;
    char *filter_expr;
    struct pcap_pkthdr header;
    const u_char *packet;

    void (*start_capture)(struct PacketSniffer *self);
    void (*set_filter)(struct PacketSniffer *self, const char *filter);
    void (*capture_packet)(struct PacketSniffer *self);
} PacketSniffer_t;

// IP Layer Handler
typedef struct IpLayer {
    struct PacketSniffer base;
    void (*parse_ip)(struct IpLayer *self, const u_char *packet);
} IpLayer_t;

// TCP/UDP/ICMP Handler
typedef struct TransportLayer {
    struct IpLayer base;
    void (*parse_tcp)(struct TransportLayer *self, const u_char *packet);
    void (*parse_udp)(struct TransportLayer *self, const u_char *packet);
    void (*parse_icmp)(struct TransportLayer *self, const u_char *packet);
} TransportLayer_t;

// Application Layer Handler
typedef struct ApplicationLayer {
    struct TransportLayer base;
    void (*parse_http)(struct ApplicationLayer *self, const u_char *packet);
    void (*parse_https)(struct ApplicationLayer *self, const u_char *packet);
    void (*parse_ssh)(struct ApplicationLayer *self, const u_char *packet);
} ApplicationLayer_t;

PacketSniffer_t* packet_sniffer_create(const char *device);
void packet_sniffer_destroy(PacketSniffer_t *self);
void packet_sniffer_start_capture(PacketSniffer_t *self);
void packet_sniffer_set_filter(PacketSniffer_t *self, const char *filter);
void packet_sniffer_capture_packet(PacketSniffer_t *self);
void packet_sniffer_parse_ip(IpLayer_t *self, const u_char *packet);
void packet_sniffer_parse_tcp(TransportLayer_t *self, const u_char *packet);
void packet_sniffer_parse_udp(TransportLayer_t *self, const u_char *packet);
void packet_sniffer_parse_icmp(TransportLayer_t *self, const u_char *packet);
void packet_sniffer_parse_http(ApplicationLayer_t *self, const u_char *packet);
void packet_sniffer_parse_https(ApplicationLayer_t *self, const u_char *packet);
void packet_sniffer_parse_ssh(ApplicationLayer_t *self, const u_char *packet);

#endif // PACKET_SNIFFER_H

