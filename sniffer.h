#ifndef WIRE_FISH_SNIFFER_H
#define WIRE_FISH_SNIFFER_H

#include <pcap.h>

// Opaque types for encapsulation
typedef struct WireFish WireFish;
typedef struct ProtocolHandler ProtocolHandler;

// Base protocol handler interface
struct ProtocolHandler {
    void (*digest)(ProtocolHandler *self, const u_char *packet, int length);
};

// Sniffer control interface
WireFish* wirefish_create(const char *filter_ip, int filter_port);
void wirefish_start(WireFish *sniffer);
void wirefish_stop(WireFish *sniffer);
void wirefish_destroy(WireFish *sniffer);

// Getters for encapsulation
const char* wirefish_get_filter_ip(const WireFish* sniffer);
int wirefish_get_filter_port(const WireFish* sniffer);

#endif
