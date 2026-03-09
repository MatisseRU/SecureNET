#ifndef SNET_API_H
#define SNET_API_H

#include <stddef.h>
#include <stdint.h>

typedef struct evp_pkey_st EVP_PKEY;

extern uint8_t DEBUG;

int SNET_connectTCP(char *SNET_distADDR, uint16_t SNET_distPORT);
int SNET_listenTCP(char *SNET_localADDR, uint16_t SNET_localPORT);
int SNET_sendTCP(int sock, uint8_t opcode, const void *buff, size_t buff_len);
int SNET_receivePacketTCP(int sock, uint8_t *out_opcode, char *buff, size_t buff_len);
int SNET_receiveTCP(int sock, char *buff, size_t buff_len, int expected_opcode);

EVP_PKEY *SNET_keygenRSA(void);
int SNET_encryptRSA(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext);
int SNET_decryptRSA(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext);
int save_private_key(EVP_PKEY *pkey, const char *filename);
int save_public_key(EVP_PKEY *pkey, const char *filename);
EVP_PKEY *load_private_key(const char *filename);
EVP_PKEY *load_public_key(const char *filename);

#endif
