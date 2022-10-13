#include "udp-client.h"

int exporter(struct NetFlowPacket netFlowPacket, options options) {
    int sock;                        // socket descriptor
    int msg_size, i;
    struct sockaddr_in server; // address structures of the server and the client
    char buffer[BUFFER];

    memset(&server, 0, sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr, options.hostent->h_addr, options.hostent->h_length);

    server.sin_port = htons(options.port);        // server port (network byte order)

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)   //create a client socket
        err(1, "socket() failed\n");

    printf("* Server socket created\n");

    printf("* Creating a connected UDP socket using connect()\n");
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == -1)
        err(1, "connect() failed");

    msg_size = sizeof(netFlowPacket);
    memcpy(buffer, &netFlowPacket, msg_size);

    //send data to the server
    i = send(sock, buffer, msg_size, 0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
        err(1, "send() failed");
    else if (i != msg_size)
        err(1, "send(): buffer written partially");

    close(sock);
    printf("* Closing the client socket ...\n");
    return 0;
}