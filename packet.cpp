/*****************************************************************************
 * Soubor: packet.cpp
 *
 * Popis: Zachytávání a analýza zachycené síťové komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#include <iostream>
#include "packet.h"

// srcIP, dstIP, sport, dport, prot
std::map<tuple<string, string, int, int, int>, tuple<struct NetFlowHDR, struct NetFlowRCD>> m;

void pcapInit(options options) {
    pcap_t *handle = nullptr;
    char errbuff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(options.file, errbuff);

    if(handle == nullptr)
        err(EXIT_FAILURE, "Couldn't open file: %s", errbuff);

    if(pcap_loop(handle, 0, handler, nullptr) == -1)
        err(EXIT_FAILURE, "pcap_loop() failed");

    pcap_close(handle);

    printf("Netflow finished\n");
}

string p_ip(const struct ip *ip_header, int type) {
    /* pomocí inet_ntoa() vypíšeme adresy ze síťového prostředí (uložená v bajtech) na dekadickou tečkovou notaci */
    if (type == SOURCE)
        return inet_ntoa(ip_header->ip_src);
    else if (type == DESTINATION)
        return inet_ntoa(ip_header->ip_dst);
    else
        err(EXIT_FAILURE, "Undefined error in p_ip()");
}

uint16_t p_port_tcp(const struct tcphdr *tcp_header, int type) {
    /* Protože číslo portu je uloženo v tzv. "network byte order", tak ho převedeme na tzv. "host byte order" */
    if (type == SOURCE)
        return ntohs(tcp_header->th_sport);
    else if (type == DESTINATION)
        return ntohs(tcp_header->th_dport);
    else
        err(EXIT_FAILURE, "Undefined error in p_ip()");
}

uint16_t p_port_udp(const struct udphdr *udp_header, int type) {
    /* Protože číslo portu je uloženo v tzv. "network byte order", tak ho převedeme na tzv. "host byte order" */
    if (type == SOURCE)
        return ntohs(udp_header->uh_sport);
    else if (type == DESTINATION)
        return ntohs(udp_header->uh_dport);
    else
        err(EXIT_FAILURE, "Undefined error in p_ip()");
}

void print_map() {
    for (const auto & it : m) {
        cout << "->" << get<0>(it.first) << " <- \n";
    }
    std::cout << '\n';
}


void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    auto *eth_header = (struct ether_header *) bytes;

    /*auto pos = m.find(make_tuple(2, "HAHA"));
    if (pos == m.end()) {
        cout << "Neni :)" << '\n';
    } else {
        cout << pos->second << '\n';
    }*/


    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        auto *ip_header = (struct ip *) (bytes + ETH_HLEN);
        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

        if(ip_header->ip_p == IPPROTO_ICMP) {
            auto *icmp_header = (struct icmphdr *) (bytes + ip_len + ETH_HLEN);

            // cout << p_ip(ip_header, SOURCE) << '\n';
            //cout << p_ip(ip_header, DESTINATION) << '\n';


            auto search = m.find(make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, 0, icmp_header->type));
            if (!(search != m.end())) {
                std::cout << "Not found\n";
                //m.insert(make_pair(make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, 0, icmp_header->type), netflow));
            } else {
                std::cout << "Founded" << '\n';
            }

        }

        if(ip_header->ip_p == IPPROTO_TCP) {
            auto *tcp_header = (struct tcphdr *) (bytes + ip_len + ETH_HLEN);
        }

        if(ip_header->ip_p == IPPROTO_UDP) {
            auto *udp_header = (struct udphdr *) (bytes + ip_len + ETH_HLEN);
        }
    }
    print_map();
}

/************** Konec souboru packet.cpp ***************/