#include "../platforms/linux/linux.c"


//USAGE EXAMPLE OF OPENSSL IN THE PROJECT
int main(void)
{
    EVP_PKEY *pkey = SN_keygenRSA();
    if (!pkey) {
        fprintf(stderr, "Error generating key pair\n");
        return 1;
    }

    // Sauvegarder les clés
    if (!save_private_key(pkey, "private.pem") || !save_public_key(pkey, "public.pem")) {
        fprintf(stderr, "Error saving the private key\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    if (DEBUG)
    {
        printf("RSA key pair generated and saved\n");
    }
    

    // Charger clé publique pour chiffrement
    EVP_PKEY *pubkey = load_public_key("public.pem");
    if (!pubkey) {
        fprintf(stderr, "Error while loading public key\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    const char *message = "Bonjour, OpenSSL EVP RSA!";
    unsigned char *encrypted = NULL;
    int encrypted_len = SN_encryptRSA(pubkey, (const unsigned char *)message, strlen(message), &encrypted);
    if (encrypted_len < 0) {
        fprintf(stderr, "Failed to encrypt packet\n");
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        return 1;
    }
    printf("Packet crypted: (%d bytes)\n", encrypted_len);

    // Charger clé privée pour déchiffrement
    EVP_PKEY *privkey = load_private_key("private.pem");
    if (!privkey) {
        fprintf(stderr, "Error while loading private key\n");
        OPENSSL_free(encrypted);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        return 1;
    }

    unsigned char *decrypted = NULL;
    int decrypted_len = SN_decryptRSA(privkey, encrypted, encrypted_len, &decrypted);
    if (decrypted_len < 0) {
        fprintf(stderr, "Failed to decrypt packet\n");
        OPENSSL_free(encrypted);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("Decrypted packet: %s\n", decrypted);

    // Libération
    OPENSSL_free(encrypted);
    OPENSSL_free(decrypted);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pkey);

    EVP_cleanup();
}