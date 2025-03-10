#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <filter_ip> <filter_port> <device>\n", argv[0]);
        return 1;
    }

    // Initialize sniffer with IP, port, and device
    sniffer* sniff = wirefish_create(argv[1], argv[2], atoi(argv[3]));

    // Check if sniffer creation failed
    if (sniff == NULL) {
        fprintf(stderr, "Error: Failed to create sniffer object.\n");
        return 1;
    }

    // Output the filtering IP and Port
    printf("Filtering IP: %s Port: %d\n",
           wirefish_get_filter_ip(sniff),
           wirefish_get_filter_port(sniff));

    // Start packet capturing
    wirefish_start(sniff);

    // Clean up and destroy sniffer object
    wirefish_destroy(sniff);

    return 0;
}
