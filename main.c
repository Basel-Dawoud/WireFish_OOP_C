#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"

int main(int argc, char *argv[]) {
    // Check if there are enough arguments passed
    if (argc < 2) {
        printf("Usage: %s <filter_ip> [filter_port]\n", argv[0]);
        return 1;
    }

    // Declare a pointer to WireFish
    WireFish *sniffer = malloc(sizeof(WireFish)); // Allocate memory for WireFish

    if (sniffer == NULL) { // Always check if memory allocation is successful
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Initialize sniffer with the provided arguments
    sniffer_init(sniffer, argv[1], argv[1], (argc >= 3) ? atoi(argv[2]) : 0);
    
    // Start sniffer
    sniffer_start(sniffer);
    
    // Stop sniffer
    sniffer_stop(sniffer);
    
    // Clean up sniffer
    sniffer_cleanup(sniffer);

    // Free allocated memory
    free(sniffer);

    return 0;
}
