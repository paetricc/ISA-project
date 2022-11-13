/*****************************************************************************
 * Soubor: arguments.hpp
 *
 * Popis: Hlavičkový soubor pro analyzátor zadaných argumentů programu
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#ifndef ISA_PROJECT_ARGUMENTS_HPP
#define ISA_PROJECT_ARGUMENTS_HPP

#include <cstdlib>
#include <cctype>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <cstdio>
#include <string>
#include <netdb.h>

#include <arpa/inet.h>
#include <err.h>

using namespace std;

/* Makro pro kontrolu zda se vstupní číslo nachází v zadaném rozsahu */
#define BETWEEN(first, number, last)  (((first) <= (number)) && ((number) <= (last)))

/* Struktura uchovávající výběr z argumentů programu s přednastaveným defaultními hodnotami */
struct options {
    const char*     file     {"-"};   // souborový popisovač
    struct hostent* hostent  {};      // struktura uchovavájící mimo jiné cílovou IP adresu
    unsigned long   port     {2055};  // číslo portu
    unsigned long   ac_timer {60};    // aktivní časovač
    unsigned long   in_timer {10};    // inaktivní časovač
    unsigned long   count    {1024};  // velikost cache
};

/**
 * Funkce pro parsování argumentů zadaných při spouštění programu.
 * Dochazí při tom k naplňování struktury Options daty zadanými při spuštění v argumentech.
 */
void parse_args(int, char **, options *);

/**
 * Funkce pro kontrolu zda řetězec lze převést na celé číslo.
 * Předpokládá se, že na vstupu je korektní řetězec zakončený znakem '\0'.
 * @return Booleanovská hodnota, zda je konverze možná
 */
bool isNum(const char *);

/**
 * Funkce pro rozdělení zadaného parametru (xxx.xxx.xxx.xxx:port) při použití přepínače -c pokud
 * byl zadan hostname nebo IP adresa společne s číslem portu. Dochazí
 * zde i ke kontrole zda číslo portu se nachází v povoleném rozsahu.
 * @return Řetězcová reprezentace zadaného hostname či IP adresy
 */
char *option_split(char *, options **);

/**
 * Funkce pro převod řetězce na celé číslo. Dochází zde i k prvotní kontrole, zde řetězec lze skutečně převést na číslo.
 * @return Převedný řetězec na číslo
 */
long strToLong(const char *);

/**
 * Funkce pro převod hostname na IP adresu. Pokud je v řetězci již korektně zadaná IP nedochazí k překladu.
 */
void process_host_name(options **, const char *);

#endif

/************** Konec souboru arguments.hpp ***************/