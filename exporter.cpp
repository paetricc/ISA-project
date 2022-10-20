/*****************************************************************************
 * Soubor: exporter.cpp
 *
 * Popis: Exportér NetFlow paketů pomocí UDP
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 20.10.2022
 *****************************************************************************/

#include "exporter.h"

void exporter(struct NetFlowPacket netFlowPacket, options options, unsigned char count) {
    int msg_size, i, sock;
    struct sockaddr_in server{};
    char buffer[BUFFER];

    memset(&server, 0, sizeof(server));  // vynuluj strukturu server
    server.sin_family = AF_INET;

    // zkopíruj cílovou adresu ze struktury options do server.sin_addr
    memcpy(&server.sin_addr, options.hostent->h_addr, options.hostent->h_length);

    server.sin_port = htons(options.port); // cílový port ze struktury options

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // vytvoř socket klienta
        perror("socket() failed ");

    /* Velikost výsledného paketu v bytech počítaná jako:
     * velikost hlavičky + počet flows * velikost jedné flow */
    msg_size = sizeof(NetFlowHDR) + count * sizeof(NetFlowRCD);

    memcpy(buffer, &netFlowPacket, msg_size); // výsledný netflow paket nakopíruj do bufferu

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == -1) // na socketu otevři spojení
        perror("connect() fail ");

    if ((i = send(sock, buffer, msg_size, 0)) == -1) // odešly msg_size bytů z bufferu na socket
        perror("send() failed ");

    if (i != msg_size) // kontrola zda data byla řádně odeslaná
        err(EXIT_FAILURE, "send() failed ");

    if(close(sock) == -1) // uzavři socket
        perror("close() failed ");
}

/************** Konec souboru exporter.h ***************/
