#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "encrypt.h"
#include "key.h"

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <identity_private.pem> <username> <certificate.bin>\n", argv[0]);
        return 1;
    }

    const char *private_key_file = argv[1];
    const char *username = argv[2];
    const char *certificate_file = argv[3];

    EVP_PKEY *ca_private = load_private_key("keys/ca_private.pem");
    EVP_PKEY *identity_private = load_private_key(private_key_file);

    if (ca_private == NULL || identity_private == NULL) {
        fprintf(stderr, "Failed to load keys\n");
        return 1;
    }

    Certificate certificate;
    memset(&certificate, 0, sizeof(certificate));

    /*
     * Store username in fixed-size field.
     */
    strncpy(
        (char *)certificate.username,
        username,
        USERNAME_SIZE - 1
    );

    /*
     * Extract identity public key.
     */
    size_t public_key_len = ED25519_PUBLIC_KEY_SIZE;

    if (EVP_PKEY_get_raw_public_key(
            identity_private,
            certificate.identity_public_key,
            &public_key_len
        ) <= 0) {

        fprintf(stderr, "Failed to extract identity public key\n");

        EVP_PKEY_free(ca_private);
        EVP_PKEY_free(identity_private);
        return 1;
    }

    if (public_key_len != ED25519_PUBLIC_KEY_SIZE) {
        fprintf(stderr, "Unexpected public key size\n");

        EVP_PKEY_free(ca_private);
        EVP_PKEY_free(identity_private);
        return 1;
    }

    /*
     * CA signs:
     *
     *     username || identity_public_key
     */
    if (create_certificate(
            &certificate,
            ca_private
        ) != 0) {

        fprintf(stderr, "Failed to create certificate\n");

        EVP_PKEY_free(ca_private);
        EVP_PKEY_free(identity_private);
        return 1;
    }

    /*
     * Save raw Certificate structure.
     */
    FILE *file = fopen(certificate_file, "wb");

    if (file == NULL) {
        perror("Failed to open certificate file");

        EVP_PKEY_free(ca_private);
        EVP_PKEY_free(identity_private);
        return 1;
    }

    if (fwrite(
            &certificate,
            sizeof(Certificate),
            1,
            file
        ) != 1) {

        fprintf(stderr, "Failed to write certificate\n");
        fclose(file);

        EVP_PKEY_free(ca_private);
        EVP_PKEY_free(identity_private);
        return 1;
    }

    fclose(file);

    printf("Certificate created: %s\n", certificate_file);

    EVP_PKEY_free(ca_private);
    EVP_PKEY_free(identity_private);

    return 0;
}