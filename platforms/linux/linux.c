#ifndef SNET_PLATFORM_LINUX
#define SNET_PLATFORM_LINUX
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../univ/snet_api.h"
#include "../../univ/snet_protocol.h"

#if defined(SNET_ENABLE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

// DEBUG flag (0 = off, non-zero = on)
uint8_t DEBUG;

static int SNET_sendAll(int sock, const unsigned char *buff, size_t buff_len)
{
    size_t total_sent = 0;
    while (total_sent < buff_len)
    {
        ssize_t sent = send(sock, buff + total_sent, buff_len - total_sent, 0);
        if (sent < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("send");
            return -1;
        }

        if (sent == 0)
        {
            return -1;
        }

        total_sent += (size_t)sent;
    }

    return 0;
}

static int SNET_recvAll(int sock, unsigned char *buff, size_t buff_len)
{
    size_t total_received = 0;
    while (total_received < buff_len)
    {
        ssize_t received = recv(sock, buff + total_received, buff_len - total_received, 0);
        if (received < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("recv");
            return -1;
        }

        if (received == 0)
        {
            return -1;
        }

        total_received += (size_t)received;
    }

    return 0;
}

static int SNET_discardAll(int sock, size_t to_discard)
{
    unsigned char tmp[256];
    size_t remaining = to_discard;

    while (remaining > 0)
    {
        size_t chunk = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
        if (SNET_recvAll(sock, tmp, chunk) != 0)
        {
            return -1;
        }
        remaining -= chunk;
    }

    return 0;
}

// Socket crafting
int SNET_connectTCP(char *SNET_distADDR, uint16_t SNET_distPORT)
{
    int sock;
    struct sockaddr_in addr_structure;
    socklen_t addr_size;

    if (SNET_distADDR == NULL)
    {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Could not create socket");
        return -2;
    }

    if (DEBUG)
    {
        printf("Socket n° %d created\n", sock);
    }

    addr_size = sizeof(addr_structure);
    memset(&addr_structure, 0x00, addr_size);

    addr_structure.sin_family = AF_INET;
    addr_structure.sin_port = htons(SNET_distPORT);

    if (inet_pton(AF_INET, SNET_distADDR, &(addr_structure.sin_addr)) != 1)
    {
        if (DEBUG)
        {
            fprintf(stderr, "Invalid destination IPv4 address: %s\n", SNET_distADDR);
        }
        close(sock);
        return -3;
    }

    if (connect(sock, (struct sockaddr *)&addr_structure, addr_size) < 0)
    {
        perror("Failed to connect to distant SecureNET Router");
        close(sock);
        return -4;
    }

    if (DEBUG)
    {
        printf("Connected socket n° %d to distant SecureNET Router n° %s\n", sock, SNET_distADDR);
    }

    return sock;
}

int SNET_listenTCP(char *SNET_localADDR, uint16_t SNET_localPORT)
{
    int sock;
    int connected_sock;
    int reuse_addr;
    struct sockaddr_in addr_structure;
    struct sockaddr_in client_structure;
    socklen_t addr_size;

    if (SNET_localADDR == NULL)
    {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Could not create socket");
        return -2;
    }

    if (DEBUG)
    {
        printf("Socket n° %d created\n", sock);
    }

    reuse_addr = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

    addr_size = sizeof(addr_structure);
    memset(&addr_structure, 0x00, addr_size);

    addr_structure.sin_family = AF_INET;
    addr_structure.sin_port = htons(SNET_localPORT);

    if (inet_pton(AF_INET, SNET_localADDR, &(addr_structure.sin_addr)) != 1)
    {
        if (DEBUG)
        {
            fprintf(stderr, "Invalid local IPv4 address: %s\n", SNET_localADDR);
        }
        close(sock);
        return -3;
    }

    if (bind(sock, (struct sockaddr *)&addr_structure, addr_size) < 0)
    {
        perror("Failed to bind socket on local port");
        close(sock);
        return -4;
    }

    if (DEBUG)
    {
        printf("Socket n° %d binded to local port %hu\n", sock, SNET_localPORT);
    }

    if (listen(sock, 1) < 0)
    {
        perror("Failed to listen to local port");
        close(sock);
        return -5;
    }

    if (DEBUG)
    {
        printf("Socket n° %d listening...\n", sock);
    }

    addr_size = sizeof(client_structure);
    connected_sock = accept(sock, (struct sockaddr *)&client_structure, &addr_size);
    if (connected_sock < 0)
    {
        perror("Failed to accept connection");
        close(sock);
        return -6;
    }

    if (DEBUG)
    {
        char dist_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_structure.sin_addr), dist_addr, INET_ADDRSTRLEN);
        printf("Accepted client from socket n°%d with dist address n°%s on port n°%hu\n", sock, dist_addr, SNET_localPORT);
    }

    close(sock);
    return connected_sock;
}

// Socket usage
int SNET_sendTCP(int sock, uint8_t opcode, const void *buff, size_t buff_len)
{
    unsigned char header[SNET_PACKET_HEADER_SIZE];
    uint16_t payload_len_net;

    if (sock < 0)
    {
        return SNET_IO_ERR_INVALID_ARG;
    }

    if (buff_len > 0 && buff == NULL)
    {
        return SNET_IO_ERR_INVALID_ARG;
    }

    if (buff_len > UINT16_MAX)
    {
        return SNET_IO_ERR_LENGTH_OVERFLOW;
    }

    payload_len_net = htons((uint16_t)buff_len);

    header[0] = SNET_PROTOCOL_MAGIC;
    header[1] = SNET_PROTOCOL_VERSION;
    header[2] = opcode;
    memcpy(&header[3], &payload_len_net, sizeof(payload_len_net));

    if (SNET_sendAll(sock, header, sizeof(header)) != 0)
    {
        return SNET_IO_ERR_SEND;
    }

    if (buff_len > 0 && SNET_sendAll(sock, (const unsigned char *)buff, buff_len) != 0)
    {
        return SNET_IO_ERR_SEND;
    }

    return (int)buff_len;
}

int SNET_receivePacketTCP(int sock, uint8_t *out_opcode, char *buff, size_t buff_len)
{
    unsigned char header[SNET_PACKET_HEADER_SIZE];
    uint16_t payload_len_net;
    size_t payload_len;

    if (sock < 0)
    {
        return SNET_IO_ERR_INVALID_ARG;
    }

    if (SNET_recvAll(sock, header, sizeof(header)) != 0)
    {
        return SNET_IO_ERR_RECV;
    }

    if (header[0] != SNET_PROTOCOL_MAGIC || header[1] != SNET_PROTOCOL_VERSION)
    {
        return SNET_IO_ERR_BAD_HEADER;
    }

    if (out_opcode != NULL)
    {
        *out_opcode = header[2];
    }

    memcpy(&payload_len_net, &header[3], sizeof(payload_len_net));
    payload_len = (size_t)ntohs(payload_len_net);

    if (payload_len == 0)
    {
        return 0;
    }

    if (buff == NULL || payload_len > buff_len)
    {
        if (SNET_discardAll(sock, payload_len) != 0)
        {
            return SNET_IO_ERR_RECV;
        }
        return SNET_IO_ERR_LENGTH_OVERFLOW;
    }

    if (SNET_recvAll(sock, (unsigned char *)buff, payload_len) != 0)
    {
        return SNET_IO_ERR_RECV;
    }

    return (int)payload_len;
}

int SNET_receiveTCP(int sock, char *buff, size_t buff_len, int expected_opcode)
{
    unsigned char header[SNET_PACKET_HEADER_SIZE];
    uint16_t payload_len_net;
    size_t payload_len;

    if (sock < 0)
    {
        return SNET_IO_ERR_INVALID_ARG;
    }

    if (SNET_recvAll(sock, header, sizeof(header)) != 0)
    {
        return SNET_IO_ERR_RECV;
    }

    if (header[0] != SNET_PROTOCOL_MAGIC || header[1] != SNET_PROTOCOL_VERSION)
    {
        return SNET_IO_ERR_BAD_HEADER;
    }

    if (expected_opcode >= 0 && header[2] != (unsigned char)expected_opcode)
    {
        memcpy(&payload_len_net, &header[3], sizeof(payload_len_net));
        payload_len = (size_t)ntohs(payload_len_net);
        if (payload_len > 0 && SNET_discardAll(sock, payload_len) != 0)
        {
            return SNET_IO_ERR_RECV;
        }
        return SNET_IO_ERR_BAD_OPCODE;
    }

    memcpy(&payload_len_net, &header[3], sizeof(payload_len_net));
    payload_len = (size_t)ntohs(payload_len_net);

    if (payload_len == 0)
    {
        return 0;
    }

    if (buff == NULL || payload_len > buff_len)
    {
        if (SNET_discardAll(sock, payload_len) != 0)
        {
            return SNET_IO_ERR_RECV;
        }
        return SNET_IO_ERR_LENGTH_OVERFLOW;
    }

    if (SNET_recvAll(sock, (unsigned char *)buff, payload_len) != 0)
    {
        return SNET_IO_ERR_RECV;
    }

    return (int)payload_len;
}

#if defined(SNET_ENABLE_OPENSSL)
// Cryptographic part
EVP_PKEY *SNET_keygenRSA(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        fprintf(stderr, "Erreur création contexte EVP_PKEY_CTX\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        fprintf(stderr, "Erreur initialisation keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        fprintf(stderr, "Erreur définition taille clef RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        fprintf(stderr, "Erreur génération de la paire de clefs\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int SNET_encryptRSA(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    size_t outlen = 0;

    if (!ctx)
    {
        fprintf(stderr, "Erreur création contexte chiffrement\n");
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        fprintf(stderr, "Erreur initialisation chiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        fprintf(stderr, "Erreur définition padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) <= 0)
    {
        fprintf(stderr, "Erreur calcul taille ciphertext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *ciphertext = OPENSSL_malloc(outlen);
    if (!*ciphertext)
    {
        fprintf(stderr, "Erreur allocation mémoire ciphertext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, *ciphertext, &outlen, plaintext, plaintext_len) <= 0)
    {
        fprintf(stderr, "Erreur chiffrement\n");
        OPENSSL_free(*ciphertext);
        *ciphertext = NULL;
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int SNET_decryptRSA(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    size_t outlen = 0;

    if (!ctx)
    {
        fprintf(stderr, "Erreur création contexte déchiffrement\n");
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        fprintf(stderr, "Erreur initialisation déchiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        fprintf(stderr, "Erreur définition padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, ciphertext_len) <= 0)
    {
        fprintf(stderr, "Erreur calcul taille plaintext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *plaintext = OPENSSL_malloc(outlen + 1);
    if (!*plaintext)
    {
        fprintf(stderr, "Erreur allocation mémoire plaintext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, *plaintext, &outlen, ciphertext, ciphertext_len) <= 0)
    {
        fprintf(stderr, "Erreur déchiffrement\n");
        OPENSSL_free(*plaintext);
        *plaintext = NULL;
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    (*plaintext)[outlen] = '\0';
    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int save_private_key(EVP_PKEY *pkey, const char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        perror("fopen");
        return 0;
    }

    int ret = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    return ret;
}

int save_public_key(EVP_PKEY *pkey, const char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        perror("fopen");
        return 0;
    }

    int ret = PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    return ret;
}

EVP_PKEY *load_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

EVP_PKEY *load_public_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}
#else
EVP_PKEY *SNET_keygenRSA(void) { return NULL; }
int SNET_encryptRSA(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext)
{
    (void)pubkey;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    return -1;
}
int SNET_decryptRSA(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext)
{
    (void)privkey;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)plaintext;
    return -1;
}
int save_private_key(EVP_PKEY *pkey, const char *filename)
{
    (void)pkey;
    (void)filename;
    return 0;
}
int save_public_key(EVP_PKEY *pkey, const char *filename)
{
    (void)pkey;
    (void)filename;
    return 0;
}
EVP_PKEY *load_private_key(const char *filename)
{
    (void)filename;
    return NULL;
}
EVP_PKEY *load_public_key(const char *filename)
{
    (void)filename;
    return NULL;
}
#endif
