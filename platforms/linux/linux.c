#ifndef PLATEFORM_LINUX
    #define PLATEFORM_LINUX
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// DBG FLAG
u_int8_t DEBUG;

// Socket crafting
int SNET_connectTCP(char *SNET_distADDR, uint16_t SNET_distPORT)
{
    int sock;
    struct sockaddr_in addr_structure;
    socklen_t addr_size;


    sock = socket(AF_INET, SOCK_STREAM, 0);
    if( sock < 0 )
    {
        perror("Could not create socket");
        close(sock);
        return -1;
    }
    if( DEBUG )
    {
        printf("Socket n° %d created\n", sock);
    }


    addr_size = sizeof(addr_structure);
    memset(&addr_structure, 0x00, addr_size);

    addr_structure.sin_family = AF_INET;
    addr_structure.sin_port = htons(SNET_distPORT);

    inet_pton(AF_INET, SNET_distADDR, &(addr_structure.sin_addr));

    if( connect(sock, (struct sockaddr*)&addr_structure, addr_size) < 0 )
    {
        perror("Failed to connect to distant SecureNET Router");
        close(sock);
        return -2;
    }
    if( DEBUG )
    {
        printf("Connected socket n° %d to distant SecureNET Router n° %s\n", sock, SNET_distADDR);
    }

    return sock;
}
int SNET_listenTCP(char *SNET_localADDR,uint16_t SNET_localPORT)
{
    int sock;
    struct sockaddr_in addr_structure;
    struct sockaddr_in client_structure;
    socklen_t addr_size;


    sock = socket(AF_INET, SOCK_STREAM, 0);
    if( sock < 0 )
    {
        perror("Could not create socket");
        close(sock);
        exit(-1);
    }
    if( DEBUG )
    {
        printf("Socket n° %d created\n", sock);
    }


    addr_size = sizeof(addr_structure);
    memset(&addr_structure, 0x00, addr_size);

    addr_structure.sin_family = AF_INET;
    addr_structure.sin_port = htons(SNET_localPORT);

    inet_pton(AF_INET, SNET_localADDR, &(addr_structure.sin_addr));

    if( bind(sock, (struct sockaddr *)&addr_structure, addr_size) < 0 )
    {
        perror("Failed to bind socket on local port");
        close(sock);
        exit(-2);
    }
    if( DEBUG )
    {
        printf("Socket n° %d binded to local port %hu\n", sock, SNET_localPORT);
    }

    
    if( listen(sock, 1) < 0 )
    {
        perror("Failed to listen to local port");
        close(sock);
        exit(-3);
    }
    if( DEBUG )
    {
        printf("Socket n° %d listening...\n", sock);
    }

    int connected_sock = accept(sock, (struct sockaddr*)&client_structure, &addr_size);
    if( connected_sock < 0 )
    {
        perror("Failed to accept connection");
        close(sock);
        exit(-4);
    }
    if( DEBUG )
    {
        char dist_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_structure.sin_addr), dist_addr, INET_ADDRSTRLEN);
        printf("Accepted client from socket n°%d with dist address n°%s on port n°%hu\n", sock, dist_addr, SNET_localPORT);
    }

    return connected_sock;
}

// Socket usage
int SNET_receiveTCP(int sock, char *buff, size_t buff_len, int expected_opcode)
{
    // TO DO

    return 0;
}
int SNET_sendTCP(int sock, const void *buff, size_t buff_len)
{
    // TO DO

    return 0;
}


// Cryptographic part

EVP_PKEY *SNET_keygenRSA(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if( !ctx )
    {
        fprintf(stderr, "Erreur création contexte EVP_PKEY_CTX\n");
        return NULL;
    }

    if( EVP_PKEY_keygen_init(ctx) <= 0 )
    {
        fprintf(stderr, "Erreur initialisation keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if( EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 )
    {
        fprintf(stderr, "Erreur définition taille clef RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if( EVP_PKEY_keygen(ctx, &pkey) <= 0 )
    {
        fprintf(stderr, "Erreur génération de la paire de clefs\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
size_t SNET_encryptRSA(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if( !ctx )
    {
        fprintf(stderr, "Erreur création contexte chiffrement\n");
        return -1;
    }

    if( EVP_PKEY_encrypt_init(ctx) <= 0 )
    {
        fprintf(stderr, "Erreur initialisation chiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Optionnel: utiliser OAEP padding (recommandé)
    if( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 )
    {
        fprintf(stderr, "Erreur définition padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t outlen = 0;
    // Obtenir la taille nécessaire pour la sortie
    if( EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) <= 0 )
    {
        fprintf(stderr, "Erreur calcul taille ciphertext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *ciphertext = OPENSSL_malloc(outlen);
    if( !*ciphertext )
    {
        fprintf(stderr, "Erreur allocation mémoire ciphertext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if( EVP_PKEY_encrypt(ctx, *ciphertext, &outlen, plaintext, plaintext_len) <= 0 )
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
    if( !ctx )
    {
        fprintf(stderr, "Erreur création contexte déchiffrement\n");
        return -1;
    }

    if( EVP_PKEY_decrypt_init(ctx) <= 0 )
    {
        fprintf(stderr, "Erreur initialisation déchiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 )
    {
        fprintf(stderr, "Erreur définition padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t outlen = 0;
    if( EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, ciphertext_len) <= 0 )
    {
        fprintf(stderr, "Erreur calcul taille plaintext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *plaintext = OPENSSL_malloc(outlen + 1);
    if( !*plaintext )
    {
        fprintf(stderr, "Erreur allocation mémoire plaintext\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if( EVP_PKEY_decrypt(ctx, *plaintext, &outlen, ciphertext, ciphertext_len) <= 0 )
    {
        fprintf(stderr, "Erreur déchiffrement\n");
        OPENSSL_free(*plaintext);
        *plaintext = NULL;
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    (*plaintext)[outlen] = '\0'; // NUL-terminer

    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}
int save_private_key(EVP_PKEY *pkey, const char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if( !fp )
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
    if( !fp )
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
    if( !fp )
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
    if( !fp )
    {
        perror("fopen");
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

