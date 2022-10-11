/*****************************************************************************
 * Soubor: packet.h
 *
 * Popis: Hlavičkový soubor pro zachytávání a analýza zachycené síťové
 * komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#ifndef ISA_PROJECT_PACKET_H
#define ISA_PROJECT_PACKET_H

#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <iostream>
#if defined (__FreeBSD__)
    #include "structures.h"
#else
    #include <netinet/tcp.h>
#endif

#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <map>
#include <tuple>
#include <string>
#include "arguments.h"

using namespace std;

#define SOURCE 1
#define DESTINATION 2

void pcapInit(options);

void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

unsigned long timeval_to_ms(struct timeval);

#endif //ISA_PROJECT_PACKET_H

/************** Konec souboru packet.h ***************/