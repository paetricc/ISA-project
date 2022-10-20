/*****************************************************************************
 * Soubor: arguments.cpp
 *
 * Popis: Analyzátor zadaných argumentů programu
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#include "arguments.h"

void parse_args(int argc, char **argv, options *options) {
    int c;
    char *hostname;
    FILE *file;

    // nastavení defaultní hodnoty
    process_host_name(&options, "localhost");

    /* pokud hodnota v argc je dělitelná dvěmi, tak nám to indikuje, že na vstupu programu je zadaný špatný počet
     * argumentů. Respektice např.: './flow -p file.pcap abcd' -> argc = 4 */
    if (argc % 2 == 0)
        err(EXIT_FAILURE, "Bad count of arguments");

    // kontrola zadaných argumentů programu a naplnění struktury Options vyselektovanými daty
    while ((c = getopt(argc, argv, "f:c:a:i:m:")) != -1) {
        switch (c) {
            case 'f': // -f <file>
                file = fopen(optarg, "r");
                if (!file)
                    err(ENOENT, "fopen() failed");

                if (fclose(file) == EOF)
                    err(EXIT_FAILURE, "fclose() failed\n");
                options->file= optarg;
                break;
            case 'c': // -c <netflow_collector:port>
                hostname = option_split(optarg, &options); // rozdělení zadaného parametru (x.x.x.x:port)
                process_host_name(&options, hostname);                // překlad host name na IP adresu
                break;
            case 'a': // -a <active_timer>
                if (isNum(optarg))
                    options->ac_timer = strToLong(optarg); // zjistíme z argumentu hodnotu aktivního časovače
                else
                    err(EXIT_FAILURE, "Number after -a expected\n");
                break;
            case 'i': // -i <seconds>
                if (isNum(optarg))
                    options->in_timer = strToLong(optarg); // zjistíme z argumentu hodnotu inaktivního časovače
                else
                    err(EXIT_FAILURE, "Number after -i expected\n");
                break;
            case 'm': // -m <count>
                if (isNum(optarg))
                    options->count = strToLong(optarg); // zjistíme z argumentu hodnotu velikosti cache
                else
                    err(EXIT_FAILURE, "Number after -m expected\n");
                break;
            case '?': // neznámý přepínač
                err(EXIT_FAILURE, "Bad type of arguments\n");
            default:
                exit(EXIT_FAILURE);
        }
    }
}

bool isNum(const char *str) {
    int i = 0;
    while(str[i] != '\0') {      // dokud jsem nenarazil na konec řetězce
        if(isdigit(str[i]) == 0) // pokud znak neodpovídá číslu, vrať false
            return false;
        i++;
    }
    return true;
}

char *option_split(char *collectorPort, options **options) {
    char const *delimeter = ":"; // dělič řetězce
    char *token;

    token = strtok(collectorPort, delimeter); // první řetězec před delimeterem -> hostname/IP
    char *hostname = token;
    token = strtok(nullptr, delimeter);       // řetězec nacházející se za prvním delimeterem -> port

    // kontrola zda je řetězcová reprezentace portu korektně zadaná
    if(token) {
        if(!isNum(token) || !BETWEEN(0, strToLong(token), 65535))
            err(EXIT_FAILURE, "Undefined port or port is not in correct range.\n");
        (*options)->port = strToLong(token);
    }
    return hostname;
}

long strToLong(const char* str) {
    char *ptr = nullptr;
    if(!isNum(str)) // kontrola zde řetězec lze skutečně převést na číslo
        err(EXIT_FAILURE, "Number was expected");
    return (int)strtol(str, &ptr, 10);
}

void process_host_name(options **options, const char *hostname) {
    struct hostent *host = gethostbyname(hostname); // pokud je na vstupu hostname, tak dojde k lookupu
    // pokud nebylo možné provést lookup
    if (!host) {
        herror("gethostbyname() failed");
        exit(EXIT_FAILURE);
    }
    (*options)->hostent = host;
}

/************** Konec souboru arguments.cpp ***************/