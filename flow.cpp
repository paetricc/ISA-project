#include "flow.h"
#include "pcap.h"

void printHost(struct hostent host) {
    struct in_addr **address;
    address = (struct in_addr **)host.h_addr_list;
    printf("Collector: hostname -> %s, IP address -> ", host.h_name);
    for(int i = 0; address[i] != nullptr; i++) {
        printf("%s", inet_ntoa(*address[i]));
    }
    printf("\n");
}

void printOptions (options options) {
    if (strcmp(options.file, "-") == 0) {
        printf("File: stdin\n");
    } else {
        printf("File: %p\n", options.file);
    }
    printHost(*options.hostent);
    printf("Port: %d\n"
           "Ac_timer: %d\n"
           "In_timer: %d\n"
           "Count: %d\n",
           options.port, options.ac_timer, options.in_timer, options.count);
}

int main(int argc, char **argv) {
//    options options = default_options;
    options options;
    parse_args(argc, argv, &options);
    printOptions(options);
    pcapInit(options);
    return 0;
}

