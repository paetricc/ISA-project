//
// Created by bartu on 6.10.22.
//

#ifndef ISA_PROJECT_PCAP_H
#define ISA_PROJECT_PCAP_H

#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include "arguments.h"


void pcapInit(options);

void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif //ISA_PROJECT_PCAP_H
