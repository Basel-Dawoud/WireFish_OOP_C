#include "sniffer.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <network interface> [filter expression]\n", argv[0]);
        return -1;
    }
    
    char *device = argv[2];
    char *filter_expr = (argc > 2) ? argv[2] : NULL;

    // Create the sniffer object
    PacketSniffer_t *sniffer = packet_sniffer_create(device);

    // Set the filter if provided
    if (filter_expr) {
        sniffer->filter_expr = filter_expr;
    }

    // Start capturing packets
    sniffer->start_capture(sniffer);
   
    // Cleanup
    packet_sniffer_destroy(sniffer);
    return 0;
}

