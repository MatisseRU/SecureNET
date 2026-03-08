#define _POSIX_C_SOURCE 200809L

#include "../univ/snet_api.h"
#include "../univ/snet_protocol.h"

#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1)
    {
        continue;
    }
}

static int run_test_send_receive_ok(void)
{
    pid_t pid;
    unsigned char payload[4] = {'P', 'I', 'N', 'G'};

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39001);
        char recv_buf[4];
        int rc;

        if (server_sock < 0)
        {
            _exit(11);
        }

        rc = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), SNET_ask_connection);
        close(server_sock);

        if (rc != 4)
        {
            _exit(12);
        }

        if (memcmp(recv_buf, payload, sizeof(payload)) != 0)
        {
            _exit(13);
        }

        _exit(0);
    }

    sleep_ms(150);

    int client_sock = SNET_connectTCP("127.0.0.1", 39001);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    int sent = SNET_sendTCP(client_sock, SNET_ask_connection, payload, sizeof(payload));
    close(client_sock);

    if (sent != 4)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }

    return 0;
}

static int run_test_receive_packet_dynamic(void)
{
    pid_t pid;
    unsigned char payload[4] = {'D', 'Y', 'N', 'A'};

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39009);
        char recv_buf[4];
        uint8_t opcode = 0;
        int rc;

        if (server_sock < 0)
        {
            _exit(91);
        }

        rc = SNET_receivePacketTCP(server_sock, &opcode, recv_buf, sizeof(recv_buf));
        close(server_sock);

        if (rc != 4)
        {
            _exit(92);
        }

        if (opcode != SNET_new_service)
        {
            _exit(93);
        }

        if (memcmp(recv_buf, payload, sizeof(payload)) != 0)
        {
            _exit(94);
        }

        _exit(0);
    }

    sleep_ms(150);

    int client_sock = SNET_connectTCP("127.0.0.1", 39009);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    int sent = SNET_sendTCP(client_sock, SNET_new_service, payload, sizeof(payload));
    close(client_sock);

    if (sent != 4)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }

    return 0;
}

static int run_test_bad_opcode(void)
{
    pid_t pid;
    unsigned char payload[4] = {'P', 'I', 'N', 'G'};

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39002);
        char recv_buf[4];
        int rc;

        if (server_sock < 0)
        {
            _exit(21);
        }

        rc = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), SNET_ask_connection);
        close(server_sock);

        if (rc != -4)
        {
            _exit(22);
        }

        _exit(0);
    }

    sleep_ms(150);

    int client_sock = SNET_connectTCP("127.0.0.1", 39002);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    int sent = SNET_sendTCP(client_sock, SNET_new_service, payload, sizeof(payload));
    close(client_sock);

    if (sent != 4)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }

    return 0;
}

static int run_test_framing_fragmented(void)
{
    pid_t pid;
    unsigned char payload[4] = {'P', 'O', 'N', 'G'};

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39003);
        char recv_buf[4];
        int rc;

        if (server_sock < 0)
        {
            _exit(31);
        }

        rc = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), SNET_ask_probation);
        close(server_sock);

        if (rc != 4)
        {
            _exit(32);
        }

        if (memcmp(recv_buf, payload, sizeof(payload)) != 0)
        {
            _exit(33);
        }

        _exit(0);
    }

    sleep_ms(150);

    int client_sock = SNET_connectTCP("127.0.0.1", 39003);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    // Build and send a valid packet in fragments to test framing robustness.
    uint16_t len_net = htons((uint16_t)sizeof(payload));
    unsigned char header[5] = {SNET_PROTOCOL_MAGIC, SNET_PROTOCOL_VERSION, SNET_ask_probation, 0, 0};
    memcpy(&header[3], &len_net, sizeof(len_net));

    if (send(client_sock, header, 2, 0) != 2)
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    if (send(client_sock, header + 2, 3, 0) != 3)
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 4;
    }

    if (send(client_sock, payload, 1, 0) != 1)
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 5;
    }

    if (send(client_sock, payload + 1, 3, 0) != 3)
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 6;
    }

    close(client_sock);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 7;
    }

    return 0;
}

static int run_test_length_overflow(void)
{
    pid_t pid;
    unsigned char payload[4] = {'L', 'O', 'N', 'G'};

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39004);
        char recv_buf[2];
        int rc;

        if (server_sock < 0)
        {
            _exit(41);
        }

        rc = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), SNET_vote_no);
        close(server_sock);

        if (rc != -5)
        {
            _exit(42);
        }

        _exit(0);
    }

    sleep_ms(150);

    int client_sock = SNET_connectTCP("127.0.0.1", 39004);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    int sent = SNET_sendTCP(client_sock, SNET_vote_no, payload, sizeof(payload));
    close(client_sock);

    if (sent != 4)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }

    return 0;
}

static int run_test_bad_magic(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39005);
        char recv_buf[8];
        int rc;

        if (server_sock < 0)
        {
            _exit(51);
        }

        rc = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), -1);
        close(server_sock);
        if (rc != SNET_IO_ERR_BAD_HEADER)
        {
            _exit(52);
        }
        _exit(0);
    }

    sleep_ms(150);
    int client_sock = SNET_connectTCP("127.0.0.1", 39005);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    unsigned char bad_header[5] = {0x00, SNET_PROTOCOL_VERSION, SNET_ask_connection, 0x00, 0x00};
    if (send(client_sock, bad_header, sizeof(bad_header), 0) != (ssize_t)sizeof(bad_header))
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }
    close(client_sock);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }
    return 0;
}

static int run_test_bad_version(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39006);
        char recv_buf[8];
        int rc;

        if (server_sock < 0)
        {
            _exit(61);
        }

        rc = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), -1);
        close(server_sock);
        if (rc != SNET_IO_ERR_BAD_HEADER)
        {
            _exit(62);
        }
        _exit(0);
    }

    sleep_ms(150);
    int client_sock = SNET_connectTCP("127.0.0.1", 39006);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    unsigned char bad_header[5] = {SNET_PROTOCOL_MAGIC, 0xFF, SNET_ask_connection, 0x00, 0x00};
    if (send(client_sock, bad_header, sizeof(bad_header), 0) != (ssize_t)sizeof(bad_header))
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }
    close(client_sock);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }
    return 0;
}

static int run_test_empty_payload(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39007);
        int rc;

        if (server_sock < 0)
        {
            _exit(71);
        }

        rc = SNET_receiveTCP(server_sock, NULL, 0, SNET_are_you_alive);
        close(server_sock);
        if (rc != 0)
        {
            _exit(72);
        }
        _exit(0);
    }

    sleep_ms(150);
    int client_sock = SNET_connectTCP("127.0.0.1", 39007);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    int sent = SNET_sendTCP(client_sock, SNET_are_you_alive, NULL, 0);
    close(client_sock);
    if (sent != 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 4;
    }
    return 0;
}

static int run_test_opcode_resync(void)
{
    pid_t pid;
    unsigned char wrong_payload[4] = {'B', 'A', 'D', '!'};
    unsigned char good_payload[4] = {'G', 'O', 'O', 'D'};

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        int server_sock = SNET_listenTCP("127.0.0.1", 39008);
        char recv_buf[4];
        int rc1;
        int rc2;

        if (server_sock < 0)
        {
            _exit(81);
        }

        // First packet has wrong opcode; receiver should discard payload and stay in sync.
        rc1 = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), SNET_ask_connection);
        if (rc1 != SNET_IO_ERR_BAD_OPCODE)
        {
            close(server_sock);
            _exit(82);
        }

        // Second packet should still be decoded correctly on same socket.
        rc2 = SNET_receiveTCP(server_sock, recv_buf, sizeof(recv_buf), SNET_ask_connection);
        close(server_sock);
        if (rc2 != 4)
        {
            _exit(83);
        }

        if (memcmp(recv_buf, good_payload, sizeof(good_payload)) != 0)
        {
            _exit(84);
        }

        _exit(0);
    }

    sleep_ms(150);
    int client_sock = SNET_connectTCP("127.0.0.1", 39008);
    if (client_sock < 0)
    {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 2;
    }

    if (SNET_sendTCP(client_sock, SNET_new_service, wrong_payload, sizeof(wrong_payload)) != 4)
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 3;
    }

    if (SNET_sendTCP(client_sock, SNET_ask_connection, good_payload, sizeof(good_payload)) != 4)
    {
        close(client_sock);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 4;
    }

    close(client_sock);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 5;
    }
    return 0;
}

int main(void)
{
    int rc1 = run_test_send_receive_ok();
    int rc2 = run_test_bad_opcode();
    int rc3 = run_test_framing_fragmented();
    int rc4 = run_test_length_overflow();
    int rc5 = run_test_bad_magic();
    int rc6 = run_test_bad_version();
    int rc7 = run_test_empty_payload();
    int rc8 = run_test_opcode_resync();
    int rc9 = run_test_receive_packet_dynamic();

    if (rc1 != 0)
    {
        fprintf(stderr, "FAIL run_test_send_receive_ok: %d\n", rc1);
        return 1;
    }

    if (rc2 != 0)
    {
        fprintf(stderr, "FAIL run_test_bad_opcode: %d\n", rc2);
        return 1;
    }

    if (rc3 != 0)
    {
        fprintf(stderr, "FAIL run_test_framing_fragmented: %d\n", rc3);
        return 1;
    }

    if (rc4 != 0)
    {
        fprintf(stderr, "FAIL run_test_length_overflow: %d\n", rc4);
        return 1;
    }

    if (rc5 != 0)
    {
        fprintf(stderr, "FAIL run_test_bad_magic: %d\n", rc5);
        return 1;
    }

    if (rc6 != 0)
    {
        fprintf(stderr, "FAIL run_test_bad_version: %d\n", rc6);
        return 1;
    }

    if (rc7 != 0)
    {
        fprintf(stderr, "FAIL run_test_empty_payload: %d\n", rc7);
        return 1;
    }

    if (rc8 != 0)
    {
        fprintf(stderr, "FAIL run_test_opcode_resync: %d\n", rc8);
        return 1;
    }

    if (rc9 != 0)
    {
        fprintf(stderr, "FAIL run_test_receive_packet_dynamic: %d\n", rc9);
        return 1;
    }

    printf("PASS test_tcp\n");
    return 0;
}
