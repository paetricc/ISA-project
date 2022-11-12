/*****************************************************************************
 * Soubor: packet.h
 *
 * Popis: Hlavičkový soubor pro zachytávání a analýzu zachycené síťové
 * komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 11.11.2022
 *****************************************************************************/

#ifndef ISA_PROJECT_PACKET_H
#define ISA_PROJECT_PACKET_H

#include <map>
#include <list>
#include <tuple>
#include <string>
#include <vector>
#include <algorithm>

#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD

#include <pcap.h>
#include <pcap/pcap.h>

#include "arguments.h"
#include "exporter.h"

using namespace std;

#define UNDEFINED 0                     // pokud je položka nedefinovaná (například v hlavičce či záznamu netflowu)
#define SOURCE 1                        // pokud se jedná o jakýkoliv zdroj
#define DESTINATION 2                   // pokud se jedná o jakýkoliv cíl
#define NETFLOW_VERSION 5               // verze exportovaného netflow
#define NETFLOW_MAX_EXPORTED_PACKETS 30 // maximální velikost exportovaných záznamů v jednom netflow paketu

// makro pro výpočet hodnoty ukládané do položky dstport při zpracování ICMP paketu
#define ICMP(TYPE, CODE) (((TYPE) * 256) + (CODE))

// struktura definující hlavičku netflow paketu verze 5
struct NetFlowHDR {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t  engine_type;
    uint8_t  engine_id;
    uint16_t sampling_interval;
};

// struktura definující záznam netflow paketu verze 5
struct NetFlowRCD {
    in_addr  srdaddr;
    in_addr  dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  pad1;
    uint8_t  tcp_flags;
    uint8_t  prot;
    uint8_t  tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t  src_mask;
    uint8_t  dst_mask;
    uint16_t pad2;
};

// struktura definující netflow paket verze 5 při maximalním(třiceti) počtu záznamu v něm
struct NetFlowPacket{
    NetFlowHDR netFlowHdr;
    NetFlowRCD netFlowRcd[NETFLOW_MAX_EXPORTED_PACKETS];
};

/**
 *  Funkce pro otevření vstupního souboru či standardního vstupu. Následuje čtení jednotlivých paketů a po přečtení
 *  všech záznamů následuje odeslání na kolektor zbytek již nevyexportovaných netflowů.
 */
void pcapInit(options);

/**
 * Callback funkce pcap_loop()
 */
void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

/**
 * Funkce pro výpočet času od počátku funkce systému do času v argumentu funkce.
 * Součet sekund převedených na milisekundy a mikrosekund převedených na milisekundy (při tomto převodu dochází k zaokrouhlování)
 * @return Výsledné milisekundy
 */
uint32_t getUptimeDiff(struct timeval);

/**
 * Funkce při níž dochází ke kontrole zda jednotlivé záznamy stále odpovídají jednotlivým časovačům.
 *
 * Aktivní časovač
 *   getUptimeDiff(čas aktuálně zpracovávaného paketu) - čas v položce Last záznamu >= hodnota aktivního časovače
 * Neaktivní časovač
 *   getUptimeDiff(čas aktuálně zpracovávaného paketu) - čas v položce First záznamu >= hodnota neaktivního časovače
 * Pokud je nějaká z těchto podmínek dojde přidání záznamu do fronty a až se projdou všechny záznamy, tak dojde k
 * poslání všech záznamu z fronty na export_queue_flows
 */
void checkTimers(struct pcap_pkthdr, struct options);

/**
 *
 * @param options
 */
void checkSize(struct options);

/**
 * Funkce slouží k odstranění jednotlivých záznamů v cache, které jsme přijali z funkce checkPcktsToExport() a
 * k následnému vytvoření netflow hlavičky. Těmito všemi hodnotami naplníme strukturu netflowPacket, kterou pak posíláme
 * funkci export() k dalšímu zpracování. Maximálně však třicet záznamů najednou. Pokud nějakou z podmínek splňuje více
 * záznamů, tak dochází k volání funkce export() vícekrát.
 */
void export_queue_flows(vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>>, struct options);

/**
 * Funkce podobná funkci export_rest_flows(). Přičemž zde, ale nemáme frontu záznamu k odstranění. V této funkce z cache
 * vyjmeme všechny zbývající záznamy z cache a pošleme je funkci export() k dalšímu zpracování. Maximálně však třicet
 * záznamů najednou. Pokud nějakou z podmínek splňuje více záznamů, tak dochází k volání funkce export() vícekrát.
 */
void export_rest_flows(struct options);

/**
 * Funkce vracející řetězcový zápis ip adresy získané z paketu. Slouží jako část klíče v mapě neboli cache.
 * Řetězcový zápis je výhradně k debugovacím účelům.
 * @return Řetězec ip adresy zapsaný jako xxx.xxx.xxx.xxx
 */
string p_ip(const struct ip *, int);

#endif //ISA_PROJECT_PACKET_H

/************** Konec souboru packet.h ***************/