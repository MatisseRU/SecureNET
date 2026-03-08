#ifndef SNET_PLATFORM_WINDOWS
#define SNET_PLATFORM_WINDOWS
#endif

#include <stdint.h>
#include <stddef.h>

#include "../../univ/snet_api.h"
#include "../../univ/snet_protocol.h"

uint8_t DEBUG;

int SNET_connectTCP(char *SNET_distADDR, uint16_t SNET_distPORT)
{
    (void)SNET_distADDR;
    (void)SNET_distPORT;
    return SNET_IO_ERR_NOT_SUPPORTED;
}

int SNET_listenTCP(char *SNET_localADDR, uint16_t SNET_localPORT)
{
    (void)SNET_localADDR;
    (void)SNET_localPORT;
    return SNET_IO_ERR_NOT_SUPPORTED;
}

int SNET_sendTCP(int sock, uint8_t opcode, const void *buff, size_t buff_len)
{
    (void)sock;
    (void)opcode;
    (void)buff;
    (void)buff_len;
    return SNET_IO_ERR_NOT_SUPPORTED;
}

int SNET_receivePacketTCP(int sock, uint8_t *out_opcode, char *buff, size_t buff_len)
{
    (void)sock;
    (void)out_opcode;
    (void)buff;
    (void)buff_len;
    return SNET_IO_ERR_NOT_SUPPORTED;
}

int SNET_receiveTCP(int sock, char *buff, size_t buff_len, int expected_opcode)
{
    (void)sock;
    (void)buff;
    (void)buff_len;
    (void)expected_opcode;
    return SNET_IO_ERR_NOT_SUPPORTED;
}

EVP_PKEY *SNET_keygenRSA(void) { return NULL; }
int SNET_encryptRSA(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext)
{
    (void)pubkey;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    return SNET_IO_ERR_NOT_SUPPORTED;
}
int SNET_decryptRSA(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext)
{
    (void)privkey;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)plaintext;
    return SNET_IO_ERR_NOT_SUPPORTED;
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
