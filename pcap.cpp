/*****************************************************************************
 * Soubor: pcap.cpp
 *
 * Popis: Zachytávání a analýza zachycené síťové komunikace
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 11.11.2022
 *****************************************************************************/

#include "pcap.hpp"

map<tuple<string, string, int, int, int, int>, struct NetFlowRCD> m; // cache uchovávající jednotlivé záznamy
vector<tuple<string, string, int, int, int, int>> key_queue;         // fronta k uchování záznamů nesplňujícíh např. aktivní timer
struct timeval SysUptime, LastUptime = {0, 0};                       // struktury k uchování času přijmu úplně prvního paketu a času aktuálně zpracovávaného paketu
uint32_t FlowCounter = 0;                                            // čítač vytvořených flowů

/*****************************************************************************
*    Title: IPK-projekt2
*    Author: Tomáš Bártů
*    Date: 2022
*    Code version: 1.0.0
*    Availability: https://github.com/paetricc/IPK-project2
*    Note: Byla převzata základní funkcionalita pro funkci pcapInit()
*          z funkce main()
*
******************************************************************************/
void pcapInit(options options) {
    pcap_t *handle;
    struct bpf_program filter{};          // pro uložení filtru a následnou aplikaci na pcap_setfilter
    const char *filter_exp = "icmp or tcp or udp";
    char errbuff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(options.file, errbuff); // otevřeme soubor pro zpracování

    if (handle == nullptr) // soubor se nepodařilo otevřít
        err(EXIT_FAILURE, "Couldn't open file: %s", errbuff);

    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) // ze zadaného výrazu vytvoříme filter
        err(EXIT_FAILURE, "pcap_compile() failed");

    if (pcap_setfilter(handle, &filter) == PCAP_ERROR) // aplikujeme filtr
        err(EXIT_FAILURE, "pcap_setfilter() failed");

    pcap_freecode(&filter); // uvolnění paměti

    if (pcap_loop(handle, 0, handler, (u_char *) &options) == PCAP_ERROR) // čteme jednotlivé pakety z .pcap souboru a zpracováváme je callbackem (funkcí handler())
        err(EXIT_FAILURE, "pcap_loop() failed");   // nastala chyba při čtení

    pcap_close(handle); // uvavřeme soubor

    export_rest_flows(options); // vyexportujeme zbytek záznamů z cache
}
/******************************************************************************
*    End of citation
*******************************************************************************/

/*****************************************************************************
*    Title: IPK-projekt2
*    Author: Tomáš Bártů
*    Date: 2022
*    Code version: 1.0.0
*    Availability: https://github.com/paetricc/IPK-project2
*    Note: Byla převzata základní funkcionalita pro funkci handler()
*          z funkce handler()
*
******************************************************************************/
void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *options    = (struct options *) user;       // z uživatelského vstupu si zjistíme strukturu se zadanými vstupními argumenty
    auto *eth_header = (struct ether_header *) bytes; // z přijatých bajtů si zjistíme ethernetovou hlavičku

    // z úplně prvního paketu zjistíme referenční čas
    if (SysUptime.tv_sec == 0 && SysUptime.tv_usec == 0) {
        SysUptime.tv_sec  = h->ts.tv_sec;
        SysUptime.tv_usec = h->ts.tv_usec;
    }

    LastUptime = h->ts; // timestamp posledního zpracovávaného paketu

    checkTimers(*h, *options); // kontrola zda některé záznamy z cache již lze vyexportovat

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        auto *ip_header = (struct ip *) (bytes + ETH_HLEN);     // z přijatých bajtů si zjistíme ip hlavičku
        /* Poněvadž IP hlavička, nemá danou pevnou délku, zjistíme její velikost z IP hlavičky a to konktrétně z
         * položky ip_hl. Tato hodnota je ale uvedena v 32-bitových slovech. Vymaskujeme hodnotu 1111 a vynásobíme
         * čtyřmi (respektive bitově posuneme hodnotu o dvě doleva)*/
        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

        /*******
        * ICMP *
        ********/
        if (ip_header->ip_p == IPPROTO_ICMP) { // pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena ICMP
            auto *icmp_header = (struct icmphdr *) (bytes + ip_len + ETH_HLEN); // z přijatých bajtů si zjistíme icmp hlavičku

            // vytvoříme klíč do mapy z klíčových hodnot netflow
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION),
                                  UNDEFINED, ICMP(icmp_header->type, icmp_header->code),
                                  ip_header->ip_p, ip_header->ip_tos);

            auto search = m.find(key); // klíč se pokusíme vyhledat v mapě
            if (search == m.end()) { // klíč jsme nenašli a tak vytvoříme nový záznam v mapě
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src, ip_header->ip_dst,
                                                UNDEFINED, UNDEFINED, UNDEFINED,
                                                htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getUptimeDiff(h->ts)), htonl(getUptimeDiff(h->ts)),
                                                UNDEFINED,
                                                htons(static_cast<uint16_t>(ICMP(icmp_header->type, icmp_header->code))),
                                                UNDEFINED, UNDEFINED,
                                                ip_header->ip_p, ip_header->ip_tos,
                                                UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};

                checkSize(*options);     // kontrola plnosti NetFlow cache
                key_queue.emplace_back(key); // do fronty přijatých paketů vložíme klíč
                m.insert(make_pair(key, netFlowRcd));
            } else { // klíč je v mapě a tak pouze aktualizujeme hodnoty
                auto dPkts = ntohl(search->second.dPkts);
                search->second.dPkts = htonl(dPkts + 1); // počet paketů

                auto dOctets = ntohl(search->second.dOctets); // počet bytů
                search->second.dOctets = htonl(dOctets + ntohs(ip_header->ip_len));

                search->second.Last = htonl(getUptimeDiff(h->ts));
            }
        }

        /******
        * UDP *
        ******/
        if (ip_header->ip_p == IPPROTO_UDP) { // pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena UDP
            auto *udp_header = (struct udphdr *) (bytes + ip_len + ETH_HLEN); // z přijatých bajtů si zjistíme udp hlavičku

            // vytvoříme klíč do mapy z klíčových hodnot netflow
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION),
                                  udp_header->uh_sport, udp_header->uh_dport,
                                  ip_header->ip_p, ip_header->ip_tos);

            auto search = m.find(key); // klíč se pokusíme vyhledat v mapě
            if (search == m.end()) { // klíč jsme nenašli a tak vytvoříme nový záznam v mapě
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src, ip_header->ip_dst,
                                                UNDEFINED, UNDEFINED, UNDEFINED,
                                                htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getUptimeDiff(h->ts)), htonl(getUptimeDiff(h->ts)),
                                                udp_header->uh_sport, udp_header->uh_dport,
                                                UNDEFINED, UNDEFINED,
                                                ip_header->ip_p, ip_header->ip_tos,
                                                UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};

                checkSize(*options);     // kontrola plnosti NetFlow cache
                key_queue.emplace_back(key); // do fronty přijatých paketů vložíme klíč
                m.insert(make_pair(key, netFlowRcd));
            } else { // klíč je v mapě a tak pouze aktualizujeme hodnoty
                auto dPkts = ntohl(search->second.dPkts); // počet paketů
                search->second.dPkts = htonl(dPkts + 1);

                auto dOctets = ntohl(search->second.dOctets); // počet bytů
                search->second.dOctets = htonl(dOctets + (ntohs(ip_header->ip_len)));

                search->second.Last = htonl(getUptimeDiff(h->ts)); // položka Last
            }
        }

        /******
        * TCP *
        ******/
        if (ip_header->ip_p == IPPROTO_TCP) { // pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena TCP
            auto *tcp_header = (struct tcphdr *) (bytes + ip_len + ETH_HLEN); // z přijatých bajtů si zjistíme tcp hlavičku

            // vytvoříme klíč do mapy z klíčových hodnot netflow
            auto key = make_tuple(p_ip(ip_header, SOURCE), p_ip(ip_header, DESTINATION),
                                  tcp_header->th_sport, tcp_header->th_dport,
                                  ip_header->ip_p, ip_header->ip_tos);

            auto search = m.find(key); // klíč se pokusíme vyhledat v mapě
            if (search == m.end()) { // klíč jsme nenašli a tak vytvoříme nový záznam v mapě
                struct NetFlowRCD netFlowRcd = {ip_header->ip_src, ip_header->ip_dst,
                                                UNDEFINED, UNDEFINED, UNDEFINED,
                                                htonl(1), htonl(ntohs(ip_header->ip_len)),
                                                htonl(getUptimeDiff(h->ts)), htonl(getUptimeDiff(h->ts)),
                                                tcp_header->th_sport, tcp_header->th_dport,
                                                UNDEFINED,
                                                tcp_header->th_flags, ip_header->ip_p, ip_header->ip_tos,
                                                UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED};

                checkSize(*options);     // kontrola plnosti NetFlow cache
                key_queue.emplace_back(key); // do fronty přijatých paketů vložíme klíč
                m.insert(make_pair(key, netFlowRcd));
            } else { // klíč je v mapě a tak pouze aktualizujeme hodnoty
                auto dPkts = ntohl(search->second.dPkts); // počet paketů
                search->second.dPkts = htonl(dPkts + 1);

                auto dOctets = ntohl(search->second.dOctets); // počet bytů
                search->second.dOctets = htonl(dOctets + ntohs(ip_header->ip_len));

                search->second.Last = htonl(getUptimeDiff(h->ts)); // položka Last

                auto flags = search->second.tcp_flags; // tcp flagy
                search->second.tcp_flags = flags | tcp_header->th_flags;

                // pokud jeden z flagů má příznak FIN nebo RST tak tento záznam můžeme vyexportovat
                if (tcp_header->th_flags & TH_FIN || tcp_header->th_flags & TH_RST) {
                    vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue;
                    queue.emplace_back(search->first, search->second);
                    export_queue_flows(queue, *options);
                }
            }
        }
    }
}
/******************************************************************************
*    End of citation
*******************************************************************************/

uint32_t getUptimeDiff(struct timeval ts) {
    uint32_t sec, usec;

    sec = ts.tv_sec - SysUptime.tv_sec;
    if (ts.tv_usec < SysUptime.tv_usec) { // pokud by počet mikrosekund v referenčním času byl menší než je čas v paketu, tak by došlo k podtečení
        usec = 1000000 - (SysUptime.tv_usec - ts.tv_usec); // ošetříme tento případ
        sec--;
    } else { // nedošlo k tomuto scénáři, tak normalně odečteme časy
        usec = ts.tv_usec - SysUptime.tv_usec;
    }
    return 1000 * sec + (usec + 500) / 1000;
}

void checkTimers(struct pcap_pkthdr h, struct options options) {
    vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue;

    for (auto &iterator: m) { // iterujeme mapou a hledám záznamy, kterým vypršel alespoň jeden z časovačů
        // exportování aktivního časovače
        // SysUptime aktuálního paketu - SysUptime poslední aktualizace paketu >= aktivní časovač (v milisekundách)
        if (getUptimeDiff(h.ts) - ntohl(iterator.second.First) >= options.ac_timer * 1000)
            queue.emplace_back(iterator); // a do fronty k odstranění vložíme záznam
            // exportování nektivního časovače
            // SysUptime aktuálního paketu - SysUptime prvního výskytu paketu >= nektivní časovač (v milisekundách)
        else if (getUptimeDiff(h.ts) - ntohl(iterator.second.Last) >= options.in_timer * 1000)
            queue.emplace_back(iterator); // a do fronty k odstranění vložíme záznam
    }

    export_queue_flows(queue, options);
}

void checkSize(struct options options) {
    vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue;

    if (m.size() == options.count) {       // kontrola zde není plná cache
        auto iter = key_queue.begin();     // vezmeme si nejstarší záznam
        auto netflowRCD = m.find(iter[0]); // z něho získáme klíč
        queue.emplace_back(netflowRCD->first, netflowRCD->second); // a do fronty k odstranění vložíme záznam
    }

    export_queue_flows(queue, options);
}

void export_queue_flows(vector<pair<tuple<string, string, int, int, int, int>, NetFlowRCD>> queue, struct options options) {
    struct NetFlowPacket netFlowPacket{};
    struct NetFlowHDR    netFlowHdr{};
    struct NetFlowRCD    netFlowRcd{};
    int count; // čítač záznamů k odeslání (maximálně 30)

    while (!queue.empty()) { // dokud fronta není prázdná
        for (count = 0; count < NETFLOW_MAX_EXPORTED_PACKETS && !queue.empty(); ) {
            // vložíme záznam od paketu
            netFlowRcd = queue.begin()->second;
            netFlowPacket.netFlowRcd[count++] = netFlowRcd;

            m.erase(queue.begin()->first); // záznam vymažeme z mapy
            // ve vektoru vyhledáme klíč záznamu
            auto iter = find(key_queue.begin(), key_queue.end(), queue.begin()->first);
            if (iter != key_queue.end()) // pokud jsme ho našli
                key_queue.erase(iter);   // klíč vymažeme z vektoru
            else
                err(EXIT_FAILURE, "Unexpected error in find()");
            queue.erase(queue.begin()); // z fronty odstraníme záznam
        }
        // vytvoříme netflow hlavičku
        netFlowHdr = {htons(static_cast<uint16_t>(NETFLOW_VERSION)), htons(static_cast<uint16_t>(1)),
                      htonl(getUptimeDiff(LastUptime)), htonl(static_cast<uint32_t>(LastUptime.tv_sec)),
                      htonl(static_cast<uint32_t>(LastUptime.tv_usec * 1000)), htonl(FlowCounter), UNDEFINED,
                      UNDEFINED, UNDEFINED};
        // zkompletujeme paket
        netFlowPacket.netFlowHdr = netFlowHdr;
        netFlowPacket.netFlowHdr.count = htons(count);

        FlowCounter += count;

        exporter(netFlowPacket, options, count);
    }
}

void export_rest_flows(struct options options) {
    struct NetFlowPacket netFlowPacket{};
    struct NetFlowHDR    netFlowHdr{};
    struct NetFlowRCD    netFlowRcd{};
    int count; // čítač záznamů k odeslání (maximálně 30)

    while (!m.empty()) { // dokud je nějaký záznam v mapě

        for (count = 0; count < NETFLOW_MAX_EXPORTED_PACKETS && !m.empty(); ) {
            netFlowRcd = m.find(key_queue.front())->second; // najdeme nejstarší záznam
            netFlowPacket.netFlowRcd[count++] = netFlowRcd;
            m.erase(key_queue.front()); // vymažeme záznam z mapy
            key_queue.erase(key_queue.begin()); // klíč vymažeme z vektoru
        }
        // vytvoříme netflow hlavičku
        netFlowHdr = {htons(static_cast<uint16_t>(NETFLOW_VERSION)), htons(static_cast<uint16_t>(1)),
                      htonl(getUptimeDiff(LastUptime)), htonl(static_cast<uint32_t>(LastUptime.tv_sec)),
                      htonl(static_cast<uint32_t>(LastUptime.tv_usec * 1000)), htonl(FlowCounter), UNDEFINED, UNDEFINED,
                      UNDEFINED};
        // zkompletujeme paket
        netFlowPacket.netFlowHdr = netFlowHdr;
        netFlowPacket.netFlowHdr.count = htons(count);

//        FlowCounter += count;

        exporter(netFlowPacket, options, count);
    }
}

string p_ip(const struct ip *ip_header, int type) {
    // pomocí inet_ntoa() vrátíme adresu ze síťového prostředí (uložená v bajtech) na dekadickou tečkovou notaci
    if (type == SOURCE)
        return inet_ntoa(ip_header->ip_src);
    else if (type == DESTINATION)
        return inet_ntoa(ip_header->ip_dst);
    else
        err(EXIT_FAILURE, "Undefined error in p_ip()");
}

/************** Konec souboru packet.cpp ***************/
