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
    int _socket;                  // popisovač soketu
    unsigned int msg_size;        // délka odesílané zprávy v bajtech
    ssize_t i;                    // počet odeslaných bajtů
    struct sockaddr_in address{}; // struktura popisující internetovou adresu soketu
    char buffer[BUFFER];          // pro uložení zprávy

    /* Velikost výsledného paketu v bytech počítaná jako:
     * velikost hlavičky + počet flows * velikost jedné flow */
    msg_size = sizeof(NetFlowHDR) + count * sizeof(NetFlowRCD);

    memcpy(buffer, &netFlowPacket, msg_size); // výsledný netflow paket nakopíruj do bufferu
    // zkopíruj cílovou adresu ze struktury options do server.sin_addr
    memcpy(&address.sin_addr, options.hostent->h_addr, options.hostent->h_length);
    memset(&address, 0, sizeof(address));  // vynuluj strukturu adresy

    address.sin_port = htons(options.port); // cílový port ze struktury options
    address.sin_family = AF_INET;           // rodina adres IP

    if ((_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // vytvoř socket
        perror("socket() failed ");

    if (connect(_socket, (struct sockaddr *) &address, sizeof(address)) == -1) // na socketu otevři spojení
        perror("connect() fail ");

    if ((i = send(_socket, buffer, msg_size, 0)) == -1) // odešly msg_size bajtů z bufferu na socket
        perror("send() failed ");

    if (i != msg_size) // kontrola zda data byla řádně odeslaná
        err(EXIT_FAILURE, "send() failed ");

    if(close(_socket) == -1) // uzavři socket
        perror("close() failed ");
}

/************** Konec souboru exporter.h ***************/
