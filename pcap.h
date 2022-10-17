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

#include <iostream>
#include <map>
#include <list>
#include <tuple>
#include <string>
#include <chrono>
#include <vector>

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
#include "udp-client.h"

using namespace std;

#define UNDEFINED 0
#define SOURCE 1
#define DESTINATION 2
#define NETFLOW_VERSION 5
#define NETFLOW_MAX_EXPORTED_PACKETS 30

#define ICMP(TYPE, CODE) (((TYPE) * 256) + (CODE))

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


struct NetFlowPacket{
    NetFlowHDR netFlowHdr;
    NetFlowRCD netFlowRcd[NETFLOW_MAX_EXPORTED_PACKETS];
};

void pcapInit(options);

uint32_t getUptimeDiff(struct timeval);

void checkPcktsToExport(struct pcap_pkthdr);

void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

unsigned long timeval_to_ms(struct timeval);

#endif //ISA_PROJECT_PACKET_H

/************** Konec souboru packet.h ***************/