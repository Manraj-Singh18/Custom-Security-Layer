#ifndef KEY_H
#define KEY_H
int secret_key(
    int *sockfd,
    unsigned char* secret,
    size_t* secret_key_len,
    unsigned char* public_key,
    unsigned char* peer_public_key,
    EVP_PKEY *identity_private,
    Certificate *certificate,
    EVP_PKEY *ca_public
);
int handshake(
    int* sockfd,
    unsigned char* encryption_key,
    unsigned char* mac_key,
    unsigned char* write_public_key,
    int role,
    EVP_PKEY *identity_private,
    Certificate *certificate,
    EVP_PKEY *ca_public
);  
EVP_PKEY *load_private_key(const char *filename);
EVP_PKEY *load_public_key(const char *filename);
int load_certificate(const char *filename, Certificate *certificate);

#endif     