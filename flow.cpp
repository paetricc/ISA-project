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
#include "pcap.h"

int main(int argc, char **argv) {
    options options;
    parse_args(argc, argv, &options);
    pcapInit(options);
    return EXIT_SUCCESS;
}

/************** Konec souboru flow.cpp ***************/
