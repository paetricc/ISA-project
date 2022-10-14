/*****************************************************************************
 * Soubor: pcap.cpp
 *
 * Popis: Zachytávání a analýza zachycené síťové komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 7.10.2022
 *****************************************************************************/

#include "pcap.h"

std::map<tuple<string, string, int, int, int, int>, struct NetFlowRCD> m;
struct timeval SysUptime, LastUptime = {0, 0};
options option = {};
uint32_t FlowCounter = 0;

uint32_t getUptimeDiff(struct timeval ts) {
    uint32_t sec =  ts.tv_sec - SysUptime.tv_sec;
    uint32_t usec = ts.tv_usec - SysUptime.tv_usec;
    return 1000 * sec + (usec + 500) / 1000;
}

struct timeval getSysUptime() {
    const auto time = std::chrono::system_clock::now().time_since_epoch();
    const auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(time);
    return {microseconds.count() / 1000000, (microseconds.count() % 1000000) * 1000};
}

void export_rest_flows() {
    struct NetFlowPacket netFlowPacket{};
    struct NetFlowHDR netFlowHdr{};
    struct NetFlowRCD netFlowRcd{};
    struct timeval uptime{};

    while(!m.empty()) {
        unsigned char count = 0;
        uptime = getSysUptime();
        netFlowHdr = {htons(static_cast<uint16_t>(NETFLOW_VERSION)), htons(static_cast<uint16_t>(1)), htonl(getUptimeDiff(LastUptime)), htonl(static_cast<uint32_t>(uptime.tv_sec)), htonl(static_cast<uint32_t>(uptime.tv_usec)), htonl(FlowCounter++), UNDEFINED, UNDEFINED, UNDEFINED};
        for (; count < NETFLOW_MAX_EXPORTED_PACKETS && !m.empty(); count++) {
            netFlowRcd = m.begin()->second;
            netFlowPacket.netFlowHdr = netFlowHdr;
            netFlowPacket.netFlowRcd[count] = netFlowRcd;
            m.erase(m.begin());
        }
        netFlowPacket.netFlowHdr.count = htons(count);
        //exporter(netFlowPacket, option, count);
    }
}

void export_queue_flows(vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue) {
    struct NetFlowPacket netFlowPacket{};
    struct NetFlowHDR netFlowHdr{};
    struct NetFlowRCD netFlowRcd{};
    struct timeval uptime{};

    while(!queue.empty()) {
        unsigned char count = 0;
        uptime = getSysUptime();
        netFlowHdr = {htons(static_cast<uint16_t>(NETFLOW_VERSION)), htons(static_cast<uint16_t>(1)), htonl(getUptimeDiff(LastUptime)), htonl(static_cast<uint32_t>(uptime.tv_sec)), htonl(static_cast<uint32_t>(uptime.tv_usec)), htonl(FlowCounter++), UNDEFINED, UNDEFINED, UNDEFINED};
        for (; count < NETFLOW_MAX_EXPORTED_PACKETS && !queue.empty(); count++) {
            netFlowRcd = queue.begin()->second;
            netFlowPacket.netFlowHdr = netFlowHdr;
            netFlowPacket.netFlowRcd[count] = netFlowRcd;
            m.erase(queue.begin()->first);
            queue.erase(queue.begin());
        }
        netFlowPacket.netFlowHdr.count = htons(count);
        //exporter(netFlowPacket, option, count);
    }
}

void pcapInit(options options) {
    option = options;
    pcap_t *handle;
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

    export_rest_flows();

    printf("Netflow finished\n");
}

string p_ip(const struct ip *ip_header, int type) {
    /* pomocí inet_ntoa() vypíšeme adresy ze síťového prostředí (uložená v bajtech) na dekadickou tečkovou notaci */
    if (type == SOURCE)
#ifdef __FAVOR_BSD
        return inet_ntoa(ip_header->ip_source);
#else
        return inet_ntoa(ip_header->ip_src);
#endif
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

uint32_t getPcktTimeDiff(struct timeval ts) {
    uint32_t tmp_sec  = ts.tv_sec  - SysUptime.tv_sec;
    uint32_t tmp_usec = ts.tv_usec - SysUptime.tv_usec;
    return (tmp_sec * 1000 + (tmp_usec + 500) / 1000) / 1000;
}

void print_map() {
    for (const auto & it : m) {
        cout << "->" << get<0>(it.first) << " <- \n";
    }
    std::cout << '\n';
}

void checkPcktTimes(const struct pcap_pkthdr h){
    vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue;

    for (auto &iterator : m) {

        auto timeDiff = getPcktTimeDiff(h.ts);
        // active timer export
        if (timeDiff - iterator.second.First / 1000 >= option.ac_timer) {
            //TODO export
            queue.emplace_back(iterator);
            cout << "active: " << timeDiff - iterator.second.First / 1000 << ":::" << get<0>(iterator.first) << "\n";
            cout << "export active\n";
        }
        //inactive timer export
        if (timeDiff - ntohl(iterator.second.Last) / 1000 >= option.in_timer) {
            //TODO export
            queue.emplace_back(iterator);
            cout << "inactive: " << timeDiff - iterator.second.Last / 1000 << ":::" << get<0>(iterator.first) << "\n";
            cout << "export inactive\n";
        }
    }

    export_queue_flows(queue);
}


int count = 0;
void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *eth_header = (struct ether_header *) bytes;
    count++;
    cout << count << ".) packet - " << h->ts.tv_sec << " seconds and " << h->ts.tv_usec << " microseconds\n";

    if (SysUptime.tv_sec == 0 && SysUptime.tv_usec == 0) {
        SysUptime.tv_sec  = h->ts.tv_sec;
        SysUptime.tv_usec = h->ts.tv_usec;
    }

    LastUptime = h->ts;

    if (m.size() == option.count) {
        auto iter = m.begin();
        m.erase(iter);
    }

    checkPcktTimes(*h);

    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        auto *ip_header = (struct ip *) (bytes + ETH_HLEN);
        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

         /*******
         * ICMP *
         ********/
        if(ip_header->ip_p == IPPROTO_ICMP) {
            auto *icmp_header = (struct icmphdr *) (bytes + ip_len + ETH_HLEN);
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), 0, ICMP(icmp_header->type, icmp_header->code), ip_header->ip_p, UNDEFINED);
            auto search = m.find(key);
            if (!(search != m.end())) {
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src,ip_header->ip_dst, UNDEFINED, UNDEFINED,UNDEFINED,htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getPcktTimeDiff(h->ts)), htonl(getPcktTimeDiff(h->ts)), UNDEFINED, htons(static_cast<uint16_t>(ICMP(icmp_header->type, icmp_header->code))), UNDEFINED, UNDEFINED, ip_header->ip_p, ip_header->ip_tos, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};
                m.insert(make_pair(key,netFlowRcd));
            } else {
                auto dPkts = ntohl(search->second.dPkts);
                search->second.dPkts = htonl(dPkts+1);
                auto dOctets = ntohl(search->second.dOctets);
                search->second.dOctets = htonl(dOctets + ntohs(ip_header->ip_len));

                search->second.Last = htonl(getPcktTimeDiff(h->ts));
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