//
// Created by bartu on 13.10.22.
//

#ifndef ISA_PROJECT_UDP_CLIENT_H
#define ISA_PROJECT_UDP_CLIENT_H

#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>
#include "pcap.h"
#include "arguments.h"

#define BUFFER 1024                // buffer length

int exporter(struct NetFlowPacket, options, unsigned char);

#endif //ISA_PROJECT_UDP_CLIENT_H
