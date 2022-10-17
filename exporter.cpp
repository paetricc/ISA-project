/*****************************************************************************
 * Soubor: exporter.cpp
 *
 * Popis: Exportér NetFlow paketů pomocí UDP
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 17.10.2022
 *****************************************************************************/

#include "exporter.h"

int exporter(struct NetFlowPacket netFlowPacket, options options, unsigned char count) {
    int msg_size, i, sock;
    struct sockaddr_in server{};
    char buffer[BUFFER];

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;

    memcpy(&server.sin_addr, options.hostent->h_addr, options.hostent->h_length);

    server.sin_port = htons(options.port);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        perror("socket() failed ");

    printf("* Server socket created\n");

    printf("* Creating a connected UDP socket using connect()\n");

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == -1)
        perror("connect() fail ");

    msg_size = sizeof(NetFlowHDR) + count * sizeof(NetFlowRCD);

    memcpy(buffer, &netFlowPacket, msg_size);

    if ((i = send(sock, buffer, msg_size, 0)) == -1)
        perror("send() failed ");
    if (i != msg_size)
        err(EXIT_FAILURE, "send(): buffer written partially ");

    if(close(sock) == -1)
        perror("close() failed ");
    printf("* Closing the client socket ...\n");
    return EXIT_SUCCESS;
}

/************** Konec souboru exporter.h ***************/
