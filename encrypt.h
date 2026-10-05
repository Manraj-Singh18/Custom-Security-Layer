#ifndef ENCRYPT_H
#define ENCRYPT_H

#define KEY_LEN   32
#define NONCE_LEN 12
#define TAG_LEN   16



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

#endif