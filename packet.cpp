/*****************************************************************************
 * Soubor: packet.cpp
 *
 * Popis: Zachytávání a analýza zachycené síťové komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#include "packet.h"

std::map<tuple<string, string, int, int, int>, struct NetFlowRCD> m;
struct timeval SysUptime = {0, 0};
options option = {};
uint32_t FlowCounter = 0;

void pcapInit(options options) {
    option = options;
    pcap_t *handle = nullptr;
    char errbuff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(options.file, errbuff);

    if(handle == nullptr)
        err(EXIT_FAILURE, "Couldn't open file: %s", errbuff);

    const u_char *packet;
    struct pcap_pkthdr header{};
    while((packet = pcap_next(handle, &header)) != nullptr)
        handler(nullptr, &header, packet);

//    if(pcap_loop(handle, 0, handler, nullptr) == -1)
//        err(EXIT_FAILURE, "pcap_loop() failed");

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

uint32_t getUptimeDiff(pcap_pkthdr h) {
    uint32_t sec =  h.ts.tv_sec - SysUptime.tv_sec;
    uint32_t usec = h.ts.tv_usec - SysUptime.tv_usec;
    return 1000 * sec + (usec + 500) / 1000;
}

uint32_t getPcktTimeDiff(const struct pcap_pkthdr h) {
    uint32_t tmp_sec  = h.ts.tv_sec - SysUptime.tv_sec;
    uint32_t tmp_usec = h.ts.tv_usec - SysUptime.tv_usec;
    return (tmp_sec * 1000 + (tmp_usec + 500) / 1000) / 1000;
}

void print_map() {
    for (const auto & it : m) {
        cout << "->" << get<0>(it.first) << " <- \n";
    }
    std::cout << '\n';
}

void checkPcktTimes(const struct pcap_pkthdr h){
    auto tmp_map = m;
    for (auto &iterator : m) {

        auto timeDiff = getPcktTimeDiff(h);
        // active timer export
        if (timeDiff - iterator.second.First / 1000 >= option.ac_timer) {
            //TODO export
            tmp_map.erase(iterator.first);
            cout << "export active\n";
        }
        //inactive timer export
        if (timeDiff - iterator.second.Last / 1000 >= option.in_timer) {
            //TODO export
            tmp_map.erase(iterator.first);
            cout << "export inactive\n";
        }
    }
    m = tmp_map;
}

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    auto *eth_header = (struct ether_header *) bytes;

    if (SysUptime.tv_sec == 0 && SysUptime.tv_usec == 0) {
        SysUptime.tv_sec  = h->ts.tv_sec;
        SysUptime.tv_usec = h->ts.tv_usec;
    }

    if (m.size() == option.count) {
        auto iter = m.begin();
        m.erase(iter);
    }

    checkPcktTimes(*h);
    cout << m.size() << '\n';

    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        auto *ip_header = (struct ip *) (bytes + ETH_HLEN);
        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

         /*******
         * ICMP *
         ********/
        if(ip_header->ip_p == IPPROTO_ICMP) {
            auto *icmp_header = (struct icmphdr *) (bytes + ip_len + ETH_HLEN);
            auto search = m.find(make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, ICMP(icmp_header->type, icmp_header->code), ntohs(ip_header->ip_p)));
            if (!(search != m.end())) {
                std::cout << "Not found\n";
                //struct NetFlowHDR netFlowHdr = {NETFLOW_VERSION, 1, getBootUptime(*h), static_cast<uint32_t>(h->ts.tv_sec), static_cast<uint32_t>(h->ts.tv_usec), ++FlowCounter, UNDEFINED, UNDEFINED, UNDEFINED};
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src,ip_header->ip_dst, UNDEFINED, UNDEFINED,UNDEFINED, 1, ntohs(ip_header->ip_len),
                                                getUptimeDiff(*h), getUptimeDiff(*h), UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, ip_header->ip_p, ip_header->ip_tos, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};
                m.insert(make_pair(make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, ICMP(icmp_header->type, icmp_header->code), ntohs(ip_header->ip_p)),netFlowRcd));
            } else {
                (search->second.dPkts)++;
                search->second.dOctets += ntohs(ip_header->ip_len);
                search->second.Last = getUptimeDiff(*h);
                std::cout << "Founded" << '\n';
            }

        }

         /******
         * TCP *
         ******/
        if(ip_header->ip_p == IPPROTO_TCP) {
            auto *tcp_header = (struct tcphdr *) (bytes + ip_len + ETH_HLEN);
        }

        /******
         * UDP *
         ******/
        if(ip_header->ip_p == IPPROTO_UDP) {
            auto *udp_header = (struct udphdr *) (bytes + ip_len + ETH_HLEN);
        }
    }
    print_map();
}

/************** Konec souboru packet.cpp ***************/