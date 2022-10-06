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
#include <netdb.h>
#include <string>
#include <arpa/inet.h>

#define UNUSED(var) ((void)(var))

#define BETWEEN(first, number, last)  (((first) <= (number)) && ((number) <= (last)))

using namespace std;

typedef struct Options options;

static struct Options {
    FILE*          file;
    struct hostent *hostent;
    unsigned int   port;
    unsigned int   ac_timer;
    unsigned int   in_timer;
    unsigned int   count;
} default_options = {stdin, nullptr, 2055, 60, 10, 1024};

void parse_args(int, char **, options *);

bool isNum(const char *);

char *option_split(char *, options **);

int strToInt(const char *);

void process_host_name(options **, const char *);

void help_print();

#endif