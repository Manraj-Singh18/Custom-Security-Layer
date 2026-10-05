#ifndef ENCRYPT_H
#define ENCRYPT_H

#define KEY_LEN   32
#define NONCE_LEN 12
#define TAG_LEN   16

#define USERNAME_SIZE 32
#define ED25519_PUBLIC_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE 64

typedef struct {
    unsigned char username[USERNAME_SIZE];
    unsigned char identity_public_key[ED25519_PUBLIC_KEY_SIZE];
    unsigned char ca_signature[ED25519_SIGNATURE_SIZE];
} Certificate;


int derive_key(unsigned char* encryption_key, unsigned char* mac_key, unsigned char* skey,enum TLSWriter writer);
void make_nonce(unsigned char *nonce,const unsigned char *iv,uint64_t seq);
int encrypt_message(const unsigned char *plaintext,
    int plaintext_len,
    unsigned char* public_write_key,
    const unsigned char *write_key,
    uint64_t seq,
    unsigned char *ciphertext,
    unsigned char *tag);
int decrypt_message(
    const unsigned char *ciphertext,
    int ciphertext_len,

    const unsigned char *write_key,
    unsigned char *public_write_key,

    uint64_t seq,

    const unsigned char *tag,

    unsigned char *plaintext
);

int sign_data(
    EVP_PKEY *private_key,
    const unsigned char *data,
    size_t data_len,
    unsigned char *signature,
    size_t *signature_len
);

int verify_signature(
    EVP_PKEY *public_key,
    const unsigned char *data,
    size_t data_len,
    const unsigned char *signature,
    size_t signature_len
);

int create_certificate(
    Certificate *certificate,
    EVP_PKEY *ca_private_key
);

int verify_certificate(
    const Certificate *certificate,
    EVP_PKEY *ca_public_key
);
#endif