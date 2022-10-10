/*****************************************************************************
 * Soubor: flow.cpp
 *
 * Popis: Generátor NetFlow dat ze zachycené síťové komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#include "flow.h"
#include "packet.h"

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
    printf("Port: %ld\n"
           "Ac_timer: %ld\n"
           "In_timer: %ld\n"
           "Count: %ld\n",
           options.port, options.ac_timer, options.in_timer, options.count);
}

int main(int argc, char **argv) {
    options options;
    parse_args(argc, argv, &options);
    //printOptions(options);
    pcapInit(options);
    return 0;
}

/************** Konec souboru flow.cpp ***************/
