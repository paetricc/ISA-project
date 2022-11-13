/*****************************************************************************
 * Soubor: flow.cpp
 *
 * Popis: Generátor NetFlow dat ze zachycené síťové komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 20.10.2022
 *****************************************************************************/

#include "flow.hpp"
#include "pcap.hpp"

int main(int argc, char **argv) {
    options options;                  // struktura pro uchování argumentů programu
    parse_args(argc, argv, &options); // oddělení jednotlivých částí argumentů
    pcapInit(options);                // zpracování .pcap souboru
    return EXIT_SUCCESS;
}

/************** Konec souboru flow.cpp ***************/
