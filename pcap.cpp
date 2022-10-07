//
// Created by bartu on 6.10.22.
//

#include "pcap.h"

#include <sys/sysinfo.h>

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

void p_time(time_t time, suseconds_t m_second) {
    char buffer[512];
    char z_buffer[6];                              /* časová zóna je ve formátu (+0100) plus '\0' => 6  */
    struct tm *recv_time = localtime(&time); /* pomocí localtime získáme strukturu, obsahující dny, roky, měsíce */
    // data ze struktury pomocí funkce strftime, uložíme do bufferů v požadovaném formátu
    strftime(buffer, sizeof(buffer), "%FT%T", recv_time);
    strftime(z_buffer, sizeof(z_buffer), "%z", recv_time);
    // vypíšeme čas z bufferů a přidáme k t tomu i milivteřiny
    printf("timestamp: %s.%ld%s\n", buffer, m_second, z_buffer);
}

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    // TODO h->ts.tv_sec
    p_time((time_t) h->ts.tv_sec, h->ts.tv_usec);

    auto *eth_header = (struct ether_header *) bytes;

    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        auto *ip_header = (struct ip *) (bytes + ETH_HLEN);

        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

        if(ip_header->ip_p == IPPROTO_ICMP) {
            auto *icmp_header = (struct icmphdr *) (bytes + ip_len + ETH_HLEN);

        }

        if(ip_header->ip_p == IPPROTO_TCP) {
            auto *tcp_header = (struct tcphdr *) (bytes + ip_len + ETH_HLEN);
        }

        if(ip_header->ip_p == IPPROTO_UDP) {
            auto *udp_header = (struct udphdr *) (bytes + ip_len + ETH_HLEN);

        }
    }
}
