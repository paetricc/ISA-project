//
// @author: xbartu11
//

#ifndef ISA_PROJECT_ARGUMENTS_H
#define ISA_PROJECT_ARGUMENTS_H

#include <cstdlib>
#include <cctype>
#include <cstring>
#include <getopt.h>
#include <cstdio>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>

#define BETWEEN(first, number, last)  (((first) <= (number)) && ((number) <= (last)))

using namespace std;

typedef struct Options options;

struct Options {
    const char*    file     {"-"};
    struct hostent *hostent {};
    unsigned int   port     {2055};
    unsigned int   ac_timer {60};
    unsigned int   in_timer {10};
    unsigned int   count    {1024};
};

void parse_args(int, char **, options *);

bool isNum(const char *);

char *option_split(char *, options **);

int strToInt(const char *);

void process_host_name(options **, const char *);

void help_print();

#endif