#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>   
#include <openssl/pem.h>
#include "com.h"
#include "encrypt.h"
#include "key.h"
// #define TEST_TAMPER 1
int secret_key(
    int *sockfd,
    unsigned char* secret,
    size_t* secret_key_len,
    unsigned char* public_key,
    unsigned char* peer_public_key,
    EVP_PKEY *identity_private,
    Certificate *certificate,
    EVP_PKEY *ca_public
){


    EVP_PKEY* keypair =
        EVP_PKEY_Q_keygen(NULL, NULL, "X25519");

    if(keypair == NULL){
        fprintf(stderr, "Failed to create keypair\n");
        return 1;
    }

    size_t public_key_len = 32;

    if(EVP_PKEY_get_raw_public_key(
            keypair,
            public_key,
            &public_key_len) <= 0){

        fprintf(stderr, "Failed to extract public key\n");
        EVP_PKEY_free(keypair);
        return 1;
    }



    unsigned char signature[ED25519_SIGNATURE_SIZE];
    size_t signature_len = ED25519_SIGNATURE_SIZE;

    if(sign_data(
            identity_private,
            public_key,
            public_key_len,
            signature,
            &signature_len) != 0){

        fprintf(stderr, "Failed to sign X25519 public key\n");

        EVP_PKEY_free(keypair);
        return 1;
    }




    unsigned char send_buffer[
        USERNAME_SIZE +
        ED25519_PUBLIC_KEY_SIZE +
        ED25519_SIGNATURE_SIZE +
        32 +
        ED25519_SIGNATURE_SIZE
    ];

    size_t offset = 0;

    memcpy(
        send_buffer + offset,
        certificate->username,
        USERNAME_SIZE
    );

    offset += USERNAME_SIZE;

    memcpy(
        send_buffer + offset,
        certificate->identity_public_key,
        ED25519_PUBLIC_KEY_SIZE
    );

    offset += ED25519_PUBLIC_KEY_SIZE;

    memcpy(
        send_buffer + offset,
        certificate->ca_signature,
        ED25519_SIGNATURE_SIZE
    );

    offset += ED25519_SIGNATURE_SIZE;

    memcpy(
        send_buffer + offset,
        public_key,
        32
    );

    offset += 32;

    memcpy(
        send_buffer + offset,
        signature,
        ED25519_SIGNATURE_SIZE
    );

    offset += ED25519_SIGNATURE_SIZE;


    sendall(
        send_buffer,
        offset,
        *sockfd
    );


    char workbuf[BUFFER_SIZE];

    int bytes_in_buffer = 0;
    int size = 0;

    unsigned char peer_message[BUFFER_SIZE];

    receive_message(
        sockfd,
        workbuf,
        &bytes_in_buffer,
        peer_message,
        &size
    );

    if(size != 224){
        fprintf(
            stderr,
            "Invalid peer handshake message size: %d\n",
            size
        );

        EVP_PKEY_free(keypair);
        return 1;
    }



    Certificate peer_certificate;

    offset = 0;

    memcpy(
        peer_certificate.username,
        peer_message + offset,
        USERNAME_SIZE
    );

    offset += USERNAME_SIZE;

    memcpy(
        peer_certificate.identity_public_key,
        peer_message + offset,
        ED25519_PUBLIC_KEY_SIZE
    );

    offset += ED25519_PUBLIC_KEY_SIZE;

    memcpy(
        peer_certificate.ca_signature,
        peer_message + offset,
        ED25519_SIGNATURE_SIZE
    );

    offset += ED25519_SIGNATURE_SIZE;



    memcpy(
        peer_public_key,
        peer_message + offset,
        32
    );

    offset += 32;

    unsigned char peer_signature[ED25519_SIGNATURE_SIZE];

    memcpy(
        peer_signature,
        peer_message + offset,
        ED25519_SIGNATURE_SIZE
    );


    if(verify_certificate(
            &peer_certificate,
            ca_public) != 0){

        fprintf(
            stderr,
            "Peer certificate verification failed\n"
        );

        EVP_PKEY_free(keypair);
        return 1;
    }

    printf(
        "Peer certificate verified: %s\n",
        peer_certificate.username
    );


    EVP_PKEY *peer_identity_key =
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519,
            NULL,
            peer_certificate.identity_public_key,
            ED25519_PUBLIC_KEY_SIZE
        );

    if(peer_identity_key == NULL){
        fprintf(
            stderr,
            "Failed to create peer identity public key\n"
        );

        EVP_PKEY_free(keypair);
        return 1;
    }

    if(verify_signature(
            peer_identity_key,
            peer_public_key,
            32,
            peer_signature,
            ED25519_SIGNATURE_SIZE
        ) != 0){

        fprintf(
            stderr,
            "Peer X25519 signature verification failed\n"
        );

        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);
        return 1;
    }

    printf(
        "Peer X25519 public key authenticated\n"
    );


    
    EVP_PKEY *peer_key =
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            NULL,
            peer_public_key,
            32
        );

    if(peer_key == NULL){
        fprintf(
            stderr,
            "Failed to create peer public key\n"
        );

        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);
        return 1;
    }


    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new(keypair, NULL);

    if(ctx == NULL){
        fprintf(
            stderr,
            "Failed to create context\n"
        );

        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);
        return 1;
    }

    if(EVP_PKEY_derive_init(ctx) <= 0){
        fprintf(stderr, "derive_init failed\n");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);

        return 1;
    }

    if(EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0){
        fprintf(stderr, "derive_set_peer failed\n");

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);

        return 1;
    }

    size_t secret_len = 0;

    if(EVP_PKEY_derive(
            ctx,
            NULL,
            &secret_len) <= 0){

        fprintf(
            stderr,
            "Failed to determine secret length\n"
        );

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);

        return 1;
    }

    if(EVP_PKEY_derive(
            ctx,
            secret,
            &secret_len) <= 0){

        fprintf(
            stderr,
            "Failed to derive shared secret\n"
        );

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(peer_identity_key);
        EVP_PKEY_free(keypair);

        return 1;
    }

    *secret_key_len = secret_len;


    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(peer_identity_key);
    EVP_PKEY_free(keypair);

    return 0;
}

int handshake(
    int* sockfd,
    unsigned char* encryption_key,
    unsigned char* mac_key,
    unsigned char* write_public_key,
    int role,
    EVP_PKEY *identity_private,
    Certificate *certificate,
    EVP_PKEY *ca_public
){
    unsigned char secret[32];
    size_t secret_len;

    // Exchange keys + Level 8 identity authentication
    unsigned char public_key[33];       // One extra byte for \0 at the end
    unsigned char peer_public_key[33];  // One extra byte for \0 at the end

    if(secret_key(
        sockfd,
        secret,
        &secret_len,
        public_key,
        peer_public_key,
        identity_private,
        certificate,
        ca_public
    ) != 0){
        fprintf(stderr, "Key exchange / identity verification failed\n");
        return 1;
    }

    // Derive encryption and MAC keys
    derive_key(
        encryption_key,
        mac_key,
        secret,
        CLIENT
    );


    unsigned char transcript[64];

    switch(role){

        case CLIENT:

            memcpy(
                transcript,
                public_key,
                32
            );

            memcpy(
                transcript + 32,
                peer_public_key,
                32
            );

            memcpy(
                write_public_key,
                public_key,
                32
            );

            break;


        case SERVER:

            memcpy(
                transcript,
                peer_public_key,
                32
            );

            memcpy(
                transcript + 32,
                public_key,
                32
            );

            memcpy(
                write_public_key,
                peer_public_key,
                32
            );

            break;


        default:

            fprintf(stderr, "Invalid role\n");
            return 1;
    }

    size_t transcript_len = 64;



    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len;

    if(HMAC(
        EVP_sha256(),
        mac_key,
        32,
        transcript,
        transcript_len,
        mac,
        &mac_len
    ) == NULL){

        fprintf(stderr, "HMAC failed\n");
        return 1;
    }



    unsigned char peer_mac[EVP_MAX_MD_SIZE];

    char workbuf[BUFFER_SIZE];

    int bytes_in_buffer = 0;
    int size = 0;


    if(role == SERVER){



        receive_message(
            sockfd,
            workbuf,
            &bytes_in_buffer,
            peer_mac,
            &size
        );


        sendall(
            (unsigned char*)mac,
            mac_len,
            *sockfd
        );

    }
    else{



        sendall(
            (unsigned char*)mac,
            mac_len,
            *sockfd
        );


        receive_message(
            sockfd,
            workbuf,
            &bytes_in_buffer,
            peer_mac,
            &size
        );
    }


    if(size != 32){
        fprintf(
            stderr,
            "Invalid Finished MAC length: %d\n",
            size
        );

        return 1;
    }

    if(CRYPTO_memcmp(
        mac,
        peer_mac,
        32
    ) == 0){

        printf("Handshake successful!\n");
        return 0;
    }

    else{

        printf("Handshake unsuccessful!\n");
        return 1;
    }
}

EVP_PKEY *load_private_key(const char *filename)
{
    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("Failed to open private key");
        return NULL;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(
        file,
        NULL,
        NULL,
        NULL
    );

    fclose(file);

    if (key == NULL) {
        fprintf(stderr, "Failed to load private key: %s\n", filename);
        return NULL;
    }

    return key;
}


EVP_PKEY *load_public_key(const char *filename)
{
    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("Failed to open public key");
        return NULL;
    }

    EVP_PKEY *key = PEM_read_PUBKEY(
        file,
        NULL,
        NULL,
        NULL
    );

    fclose(file);

    if (key == NULL) {
        fprintf(stderr, "Failed to load public key: %s\n", filename);
        return NULL;
    }

    return key;
}

int load_certificate(const char *filename, Certificate *certificate)
{
    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("Failed to open certificate");
        return 1;
    }

    if (fread(certificate, sizeof(Certificate), 1, file) != 1) {
        fprintf(stderr, "Failed to read certificate\n");
        fclose(file);
        return 1;
    }

    fclose(file);

    return 0;
}

