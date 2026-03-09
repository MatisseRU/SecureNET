#include "../../univ/snet_api.h"
#include "../../univ/snet_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *server_addr = "127.0.0.1";
    uint16_t port = 39010;
    const char *message = "Hello from SecureNET client";
    uint8_t request_opcode = SNET_ask_connection;
    int expected_reply_opcode = SNET_connection_accepted;
    char recv_buf[256];

    if (argc >= 2)
    {
        server_addr = argv[1];
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
    if (argc >= 4 && strcmp(argv[3], "--bad-opcode") == 0)
    {
        request_opcode = SNET_new_service;
        expected_reply_opcode = SNET_protocol_error;
    }

    int sock = SNET_connectTCP((char *)server_addr, port);
    if (sock < 0)
    {
        fprintf(stderr, "SNET_connectTCP failed: %d\n", sock);
        return 1;
    }

    int sent = SNET_sendTCP(sock, request_opcode, message, strlen(message));
    if (sent < 0)
    {
        fprintf(stderr, "SNET_sendTCP failed: %d\n", sent);
        close(sock);
        return 1;
    }

    printf("Client sent (%d bytes)\n", sent);

    int received = SNET_receiveTCP(sock, recv_buf, sizeof(recv_buf) - 1, expected_reply_opcode);
    if (received < 0)
    {
        fprintf(stderr, "SNET_receiveTCP failed: %d\n", received);
        close(sock);
        return 1;
    }

    recv_buf[received] = '\0';
    if (expected_reply_opcode == SNET_connection_accepted)
    {
        printf("Client received ACK (%d bytes): %s\n", received, recv_buf);
    }
    else
    {
        printf("Client received PROTOCOL_ERROR (%d bytes): %s\n", received, recv_buf);
    }

    close(sock);
    return 0;
}
