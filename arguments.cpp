//
// Created by bartu on 4.10.22.
//

#include <iostream>
#include "arguments.h"

void parse_args(int argc, char **argv, options *options) {
    UNUSED(default_options);
    int c = 0;
    char *hostname;

    if (argc % 2 == 0) {
        fprintf(stderr, "Bad count of arguments");
        exit(EXIT_FAILURE);
    }

    while((c = getopt(argc, argv, "f:c:a:i:m:")) != -1) {
        switch(c) {
            case 'f':
                options->file = fopen(optarg, "r");
                if(!options->file) {
                    printf("File not found.");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'c':
                hostname = option_split(optarg, &options);
                process_host_name(&options, hostname);
                break;
            case 'a':
                if(isNum(optarg)) {
                    options->ac_timer = strToInt(optarg);
                } else {
                    fprintf(stderr, "Number expected\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'i':
                if (isNum(optarg)) {
                    options->in_timer = strToInt(optarg);
                } else {
                    fprintf(stderr, "Number expected\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'm':
                if (isNum(optarg)) {
                    options->count = strToInt(optarg);
                } else {
                    fprintf(stderr, "Number expected\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                fprintf(stderr, "Bad arguments\n");
                exit(EXIT_FAILURE);
            default:
                help_print();
                exit(EXIT_FAILURE);
        }
    }
}

bool isNum(const char *str) {
    int i = 0;
    while(str[i] != '\0') {
        if(isdigit(str[i]) == 0)
            return false;
        i++;
    }
    return true;
}

void process_host_name(options **options, const char *hostname) {
    struct hostent *host = gethostbyname(hostname);

    if (!host) {
        herror("Error\n");
        exit(EXIT_FAILURE);
    }
    (*options)->hostent = host;
}

char *option_split(char *collectorPort, options **options) {
    char const *delimeter = ":";
    char *token;

    token = strtok(collectorPort, delimeter);
    char *hostname = token;
    token = strtok(nullptr, delimeter);

    if(token) {
        if(!isNum(token) || !BETWEEN(0, strToInt(token), 65535)) {
            fprintf(stderr, "Undefined port.\n");
            exit(EXIT_FAILURE);
        }
        (*options)->port = strToInt(token);
    }
    return hostname;
}

int strToInt(const char* str) {
    char *ptr = nullptr;
    return (int)strtol(str, &ptr, 10);
}

void help_print() {
    printf("NAME\n\t");
    printf("NetFlow generator of data from captured network traffic\n\n");
    printf("SYNOPSIS\n\t");
    printf("./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n\n");
    printf("DESCRIPTION\n\t");
    printf("-f <file> parsed file name or STDIN,\n\n\t"
           "-c <netflow_collector:port> IP address or hostname of the NetFlow collector. optionally also UDP port (127.0.0.1:2055, if not specified)\n\n\t"
           "-a <active_timer> - interval in seconds after which active records are exported to the collector (60 if not specified)\n\n\t"
           "-i <seconds> - interval in seconds after which inactive records are exported to the collector (10 if not specified)\n\n\t"
           "-m <count> - flow-cache size. When the max size is reached, the oldest entry in the cache is exported to the collector (1024, if not specified)\n\n");
    printf("AUTHOR\n\t");
    printf("Written by Tomas Bartu.");
}
//
// Created by bartu on 6.10.22.
//
