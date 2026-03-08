#include "../../univ/snet_api.h"
#include <stdio.h>
#include <string.h>
#if defined(SNET_ENABLE_OPENSSL)
#include <openssl/evp.h>
#endif

// USAGE EXAMPLE OF OPENSSL IN THE PROJECT
int main(void)
{
#if !defined(SNET_ENABLE_OPENSSL)
    fprintf(stderr, "OpenSSL is disabled. Rebuild with USE_OPENSSL=1 to run this example.\n");
    return 1;
#else
    int rc = 1;
    EVP_PKEY *pkey = SNET_keygenRSA();
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY *privkey = NULL;
    unsigned char *encrypted = NULL;
    unsigned char *decrypted = NULL;

    if (!pkey) {
        fprintf(stderr, "Error generating key pair (OpenSSL disabled or unavailable)\n");
        goto cleanup;
    }

    if (!save_private_key(pkey, "private.pem") || !save_public_key(pkey, "public.pem")) {
        fprintf(stderr, "Error saving keys\n");
        goto cleanup;
    }

    pubkey = load_public_key("public.pem");
    if (!pubkey) {
        fprintf(stderr, "Error while loading public key\n");
        goto cleanup;
    }

    const char *message = "Bonjour, OpenSSL EVP RSA!";
    int encrypted_len = SNET_encryptRSA(pubkey, (const unsigned char *)message, strlen(message), &encrypted);
    if (encrypted_len < 0) {
        fprintf(stderr, "Failed to encrypt packet\n");
        goto cleanup;
    }

    privkey = load_private_key("private.pem");
    if (!privkey) {
        fprintf(stderr, "Error while loading private key\n");
        goto cleanup;
    }

    int decrypted_len = SNET_decryptRSA(privkey, encrypted, (size_t)encrypted_len, &decrypted);
    if (decrypted_len < 0) {
        fprintf(stderr, "Failed to decrypt packet\n");
        goto cleanup;
    }

    printf("Decrypted packet: %s\n", decrypted);
    rc = 0;

cleanup:
    if (encrypted != NULL)
    {
        OPENSSL_free(encrypted);
    }
    if (decrypted != NULL)
    {
        OPENSSL_free(decrypted);
    }
    if (pubkey != NULL)
    {
        EVP_PKEY_free(pubkey);
    }
    if (privkey != NULL)
    {
        EVP_PKEY_free(privkey);
    }
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    return rc;
#endif
}
