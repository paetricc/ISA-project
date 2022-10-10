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
std::map<tuple<string, string, int, int, int>, tuple<in_addr>> m;

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

string p_port_tcp(const struct tcphdr *tcp_header) {
    /* Protože číslo portu je uloženo v tzv. "network byte order", tak ho převedeme na tzv. "host byte order" */
    printf("src port: %d\n", ntohs(tcp_header->th_sport));
    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
}

string p_port_udp(const struct udphdr *udp_header) {
    /* Protože číslo portu je uloženo v tzv. "network byte order", tak ho převedeme na tzv. "host byte order" */
    printf("src port: %d\n", ntohs(udp_header->uh_sport));
    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
}

void print_map() {
    for (const auto & it : m) {
        cout << "->" << get<0>(it.first) << " <- \n";
    }
    std::cout << '\n';
}


void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    auto *eth_header = (struct ether_header *) bytes;

    printf("ts: %ld [ms]\n", timeval_to_ms(h->ts));



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

            cout << p_ip(ip_header, SOURCE) << '\n';
            //cout << p_ip(ip_header, DESTINATION) << '\n';
            auto search = m.find(make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, 0, icmp_header->type));
            if (search != m.end()) {
                std::cout << "Founded" << '\n';
            } else {
                std::cout << "Not found\n";
                m.insert(make_pair(make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, 0, icmp_header->type), ip_header->ip_src));
            }

        }

        if(ip_header->ip_p == IPPROTO_TCP) {
            auto *tcp_header = (struct tcphdr *) (bytes + ip_len + ETH_HLEN);
            p_port_tcp(tcp_header);
        }

        if(ip_header->ip_p == IPPROTO_UDP) {
            auto *udp_header = (struct udphdr *) (bytes + ip_len + ETH_HLEN);
            p_port_udp(udp_header);
        }
    }
    print_map();
}

unsigned long timeval_to_ms(struct timeval ts) {
    return ((ts.tv_usec + 500) / 1000) + (ts.tv_sec * 1000);
}

/************** Konec souboru packet.cpp ***************/