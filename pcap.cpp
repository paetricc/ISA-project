//
// Created by bartu on 6.10.22.
//

#include "pcap.h"

void pcapInit(options options) {
    pcap_t *handle = nullptr;
    char errbuff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(options.file, errbuff);
}
