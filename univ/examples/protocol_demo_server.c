#include "../../univ/snet_api.h"
#include "../../univ/snet_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *bind_addr = "127.0.0.1";
    uint16_t port = 39010;
    char recv_buf[256];
    uint8_t received_opcode = 0;
    const char *reply_ok = "SNET connection accepted";
    const char *reply_err = "SNET protocol error: expected ask_connection";

    if (argc >= 2)
    {
        bind_addr = argv[1];
    }
    if (argc >= 3)
    {
        long parsed = strtol(argv[2], NULL, 10);
        if (parsed <= 0 || parsed > 65535)
        {
            fprintf(stderr, "Invalid port: %s\n", argv[2]);
            return 1;
        }
        port = (uint16_t)parsed;
    }

    int sock = SNET_listenTCP((char *)bind_addr, port);
    if (sock < 0)
    {
        fprintf(stderr, "SNET_listenTCP failed: %d\n", sock);
        return 1;
    }

    int received = SNET_receivePacketTCP(sock, &received_opcode, recv_buf, sizeof(recv_buf) - 1);
    if (received < 0)
    {
        fprintf(stderr, "SNET_receivePacketTCP failed: %d\n", received);
        close(sock);
        return 1;
    }

    if (received_opcode != SNET_ask_connection)
    {
        int sent_err = SNET_sendTCP(sock, SNET_protocol_error, reply_err, strlen(reply_err));
        if (sent_err < 0)
        {
            fprintf(stderr, "SNET_sendTCP(protocol_error) failed: %d\n", sent_err);
            close(sock);
            return 1;
        }

        printf("Server sent protocol error (%d bytes)\n", sent_err);
        close(sock);
        return 0;
    }

    recv_buf[received] = '\0';
    printf("Server received (%d bytes): %s\n", received, recv_buf);

    int sent = SNET_sendTCP(sock, SNET_connection_accepted, reply_ok, strlen(reply_ok));
    if (sent < 0)
    {
        fprintf(stderr, "SNET_sendTCP failed: %d\n", sent);
        close(sock);
        return 1;
    }

    printf("Server sent ACK (%d bytes)\n", sent);
    close(sock);
    return 0;
}
