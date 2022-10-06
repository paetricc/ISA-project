#include "flow.h"

void printOptions (options options) {
    printf("File: %s\n"
           "Collector: %s\n"
           "Port: %d\n"
           "Ac_timer: %d\n"
           "In_timer: %d\n"
           "Count: %d\n",
           "ano", options.h_addr_list[0], options.port, options.ac_timer, options.in_timer, options.count);
}

int main(int argc, char **argv) {
    options options = default_options;

    parse_args(argc, argv, &options);
    printOptions(options);
    return 0;
}

