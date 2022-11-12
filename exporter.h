/*****************************************************************************
 * Soubor: exporter.h
 *
 * Popis: Hlavičkový soubor pro exportér NetFlow paketů
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 20.10.2022
 *****************************************************************************/

#ifndef ISA_PROJECT_EXPORTER_H
#define ISA_PROJECT_EXPORTER_H

#include <err.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "pcap.h"
#include "arguments.h"

/* Velikost bufferu vypočítána jako:
 * maximalní počet flowů v jednom paketu * velikost jednoho flowu + velikost hlavičky flowu + maximální velikost IPv4 hlavičky + velikost ethernetové hlavičky
 * respektive : 30 * 48 + 24 + 60 + 14 = 1538 -> zaokrouhleno na nejbližší větší mocninu dvou, tedy 2048. */
#define BUFFER 2048

/**
 * Funkce pro odeslání vytvořeného NetFlow paketu pomocí UDP na kolektor
 * @return Zda došlo k úspěšnému odeslání dat na kolektor
 */
void exporter(struct NetFlowPacket, options, unsigned char);

#endif

/************** Konec souboru exporter.h ***************/
