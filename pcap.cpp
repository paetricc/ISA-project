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

#include <algorithm>

std::map<tuple<string, string, int, int, int, int>, struct NetFlowRCD> m;
std::vector<tuple<string, string, int, int, int, int>> key_queue;
struct timeval SysUptime, LastUptime = {0, 0};
options option = {};
uint32_t FlowCounter = 0;

string p_ip(const struct ip *ip_header, int type) {
    /* pomocí inet_ntoa() vypíšeme adresy ze síťového prostředí (uložená v bajtech) na dekadickou tečkovou notaci */
    if (type == SOURCE)
        return inet_ntoa(ip_header->ip_src);
    else if (type == DESTINATION)
        return inet_ntoa(ip_header->ip_dst);
    else
        err(EXIT_FAILURE, "Undefined error in p_ip()");
}

uint32_t getUptimeDiff(struct timeval ts) {
    uint32_t sec, usec;

    sec =  ts.tv_sec - SysUptime.tv_sec;
    if (ts.tv_usec < SysUptime.tv_usec) {
        usec = 1000000 - (SysUptime.tv_usec - ts.tv_usec);
        sec--;
    } else {
        usec = ts.tv_usec - SysUptime.tv_usec;
    }
    return 1000 * sec + (usec + 500) / 1000;
}

void export_rest_flows() {
    struct NetFlowPacket netFlowPacket{};
    struct NetFlowHDR netFlowHdr{};
    struct NetFlowRCD netFlowRcd{};

    cout << "time: " << LastUptime.tv_sec << '\n';

    while(!m.empty()) {
        unsigned char count = 0;
        for (; count < NETFLOW_MAX_EXPORTED_PACKETS && !m.empty(); count++) {
            FlowCounter++;
            netFlowRcd = m.find(key_queue.front())->second;
            cout << "dOctets: " << ntohl(netFlowRcd.dOctets) << " ipsrc: " << inet_ntoa(netFlowRcd.srdaddr) << " ipdst: " << inet_ntoa(netFlowRcd.dstaddr) <<  '\n';
            netFlowPacket.netFlowRcd[count] = netFlowRcd;
            m.erase(key_queue.front());
            key_queue.erase(key_queue.begin());
        }
        netFlowHdr = {htons(static_cast<uint16_t>(NETFLOW_VERSION)), htons(static_cast<uint16_t>(1)), htonl(getUptimeDiff(LastUptime)), htonl(static_cast<uint32_t>(LastUptime.tv_sec)), htonl(static_cast<uint32_t>(LastUptime.tv_usec * 1000)), htonl(FlowCounter), UNDEFINED, UNDEFINED, UNDEFINED};
        netFlowPacket.netFlowHdr = netFlowHdr;
        netFlowPacket.netFlowHdr.count = htons(count);
        exporter(netFlowPacket, option, count);
    }
}

void export_queue_flows(vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue) {
    struct NetFlowPacket netFlowPacket{};
    struct NetFlowHDR netFlowHdr{};
    struct NetFlowRCD netFlowRcd{};

    while(!queue.empty()) {
        unsigned char count = 0;
        for (; count < NETFLOW_MAX_EXPORTED_PACKETS && !queue.empty(); count++) {
            FlowCounter++;
            netFlowRcd = queue.begin()->second;
            cout << "dOctets: " << ntohl(netFlowRcd.dOctets) << " ipsrc: " << inet_ntoa(netFlowRcd.srdaddr) << " ipdst: " << inet_ntoa(netFlowRcd.dstaddr) <<  '\n';
            netFlowPacket.netFlowRcd[count] = netFlowRcd;
            m.erase(queue.begin()->first);

            auto iter = std::find(key_queue.begin(), key_queue.end(), queue.begin()->first);
            if (iter != key_queue.end())
                key_queue.erase(iter);
            else
                err(EXIT_FAILURE, "Unexpected error in std::find()");
            queue.erase(queue.begin());
        }
        netFlowHdr = {htons(static_cast<uint16_t>(NETFLOW_VERSION)), htons(static_cast<uint16_t>(1)), htonl(getUptimeDiff(LastUptime)), htonl(static_cast<uint32_t>(LastUptime.tv_sec)), htonl(static_cast<uint32_t>(LastUptime.tv_usec * 1000)), htonl(FlowCounter++), UNDEFINED, UNDEFINED, UNDEFINED};
        netFlowPacket.netFlowHdr = netFlowHdr;
        netFlowPacket.netFlowHdr.count = htons(count);
        exporter(netFlowPacket, option, count);
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

//TODO prejmenovat
void checkPcktToExport(struct pcap_pkthdr h){
    vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue;

    if (m.size() == option.count) {
        auto iter = m.begin();
        queue.emplace_back(iter->first, iter->second);
    }

    for (auto &iterator : m) {
        // active timer export
        if (getUptimeDiff(h.ts) - ntohl(iterator.second.Last) >= option.ac_timer * 1000) {
            queue.emplace_back(iterator);
            cout << "export active\n";
        }
        //inactive timer export
        if (getUptimeDiff(h.ts) - ntohl(iterator.second.First) >= option.in_timer * 1000) {
            queue.emplace_back(iterator);
            cout << "export inactive\n";
        }
    }

    export_queue_flows(queue);
}

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *eth_header = (struct ether_header *) bytes;

    if (SysUptime.tv_sec == 0 && SysUptime.tv_usec == 0) {
        SysUptime.tv_sec  = h->ts.tv_sec;
        SysUptime.tv_usec = h->ts.tv_usec;
    }

    LastUptime = h->ts;

    checkPcktTimes(*h);

    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        auto *ip_header = (struct ip *) (bytes + ETH_HLEN);
        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

         /*******
         * ICMP *
         ********/
        if(ip_header->ip_p == IPPROTO_ICMP) {
            auto *icmp_header = (struct icmphdr *) (bytes + ip_len + ETH_HLEN);
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), UNDEFINED, ICMP(icmp_header->type, icmp_header->code), ip_header->ip_p, ip_header->ip_tos);
            auto search = m.find(key);
            if (search == m.end()) {
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src,ip_header->ip_dst, UNDEFINED, UNDEFINED,UNDEFINED,htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getUptimeDiff(h->ts)), htonl(getUptimeDiff(h->ts)), UNDEFINED, htons(static_cast<uint16_t>(ICMP(icmp_header->type, icmp_header->code))), UNDEFINED, UNDEFINED, ip_header->ip_p, ip_header->ip_tos, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};
                key_queue.emplace_back(key);
                m.insert(make_pair(key,netFlowRcd));
            } else {
                auto dPkts = ntohl(search->second.dPkts);
                search->second.dPkts = htonl(dPkts+1);

                auto dOctets = ntohl(search->second.dOctets);
                search->second.dOctets = htonl(dOctets + ntohs(ip_header->ip_len));

                search->second.Last = htonl(getUptimeDiff(h->ts));
            }
        }

        /******
        * UDP *
        ******/
        if(ip_header->ip_p == IPPROTO_UDP) {
            auto *udp_header = (struct udphdr *) (bytes + ip_len + ETH_HLEN);
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), udp_header->source, udp_header->dest, ip_header->ip_p, ip_header->ip_tos);
            auto search = m.find(key);
            if (search == m.end()) {
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src,ip_header->ip_dst, UNDEFINED, UNDEFINED,UNDEFINED,htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getUptimeDiff(h->ts)), htonl(getUptimeDiff(h->ts)), udp_header->source, udp_header->dest, UNDEFINED, UNDEFINED, ip_header->ip_p, ip_header->ip_tos, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};
                key_queue.emplace_back(key);
                m.insert(make_pair(key,netFlowRcd));
                } else {
                auto dPkts = ntohl(search->second.dPkts);
                search->second.dPkts = htonl(dPkts+1);

                auto dOctets = ntohl(search->second.dOctets);
                search->second.dOctets = htonl(dOctets + ntohs(ip_header->ip_len));

                search->second.Last = htonl(getUptimeDiff(h->ts));
            }
        }

         /******
         * TCP *
         ******/
        if(ip_header->ip_p == IPPROTO_TCP) {
            auto *tcp_header = (struct tcphdr *) (bytes + ip_len + ETH_HLEN);
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION), tcp_header->source, tcp_header->dest, ip_header->ip_p, ip_header->ip_tos);
            auto search = m.find(key);
            if (search == m.end()) {
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src,ip_header->ip_dst, UNDEFINED, UNDEFINED,UNDEFINED,htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getUptimeDiff(h->ts)), htonl(getUptimeDiff(h->ts)), tcp_header->source, tcp_header->dest, UNDEFINED, tcp_header->th_flags, ip_header->ip_p, ip_header->ip_tos, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};
                key_queue.emplace_back(key);
                m.insert(make_pair(key,netFlowRcd));
            } else {
                auto dPkts = ntohl(search->second.dPkts);
                search->second.dPkts = htonl(dPkts+1);

                auto dOctets = ntohl(search->second.dOctets);
                search->second.dOctets = htonl(dOctets + ntohs(ip_header->ip_len));

                search->second.Last = htonl(getUptimeDiff(h->ts));

                auto flags = search->second.tcp_flags;
                search->second.tcp_flags = flags | tcp_header->th_flags;

                if (tcp_header->fin == 1 || tcp_header->rst == 1) {
                    vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue;
                    queue.emplace_back(search->first, search->second);
                    export_queue_flows(queue);
                }
            }
        }
    }

    //print_map();
}

/************** Konec souboru packet.cpp ***************/