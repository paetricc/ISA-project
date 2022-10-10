/*****************************************************************************
 * Soubor: arguments.h
 *
 * Popis: Hlavičkový soubor pro analyzátor zadaných argumentů programu
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

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

/* Makro pro kontrolu zda se vstupní číslo nachází v zadaném rozsahu */
#define BETWEEN(first, number, last)  (((first) <= (number)) && ((number) <= (last)))

using namespace std;

/* Struktura uchovávající výběr z argumentů programu s přednastaveným hodnotami */
typedef struct Options options;
struct Options {
    const char*    file     {"-"};
    struct hostent *hostent {};
    unsigned long  port     {2055};
    unsigned long  ac_timer {60};
    unsigned long  in_timer {10};
    unsigned long  count    {1024};
};

/**
 * Funkce pro parsování argumentů zadaných při spouštění programu.
 * Dochazí při tom k naplňování struktury Options daty zadanými v argumentech při spuštění.
 */
void parse_args(int, char **, options *);

/**
 * Funkce pro kontrolu zda řetězec lze převést na integer.
 * Předpokládá se, že na vstupu je korektní řetězec zakončený znakem '\0'.
 * @return True/False hodnota, zda je konverze možná
 */
bool isNum(const char *);

/**
 * Funkce pro rozdělení zadaného parametru při použití přepínače -c pokud
 * byl zadan hostname nebo IP adresa společne s číslem portu. Dochazí
 * zde i ke kontrole zda číslo portu se nachází v povoleném rozsahu.
 * @return Řetězcová reprezentace zadaného hostname či IP adresy
 */
char *option_split(char *, options **);

/**
 * Funkce pro převod řetězce na integer. Dochází zde i k prvotní kontrole, zde řetězec lze skutečně převést na číslo.
 * @return Převedný řetězec na číslo
 */
long strToLong(const char *);

/**
 * Funkce pro převod host name na IP adresu. Pokud je v řetězci již korektně zadaná IP nedochazí k překladu.
 */
void process_host_name(options **, const char *);

/**
 * Funkce pro výpis nápovědy
 */
void help_print();

#endif

/************** Konec souboru arguments.h ***************/