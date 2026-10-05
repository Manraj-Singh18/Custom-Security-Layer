#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>   
#include "com.h"
#include "encrypt.h"
#include "key.h"
// #define TEST_TAMPER 1
int secret_key(int *sockfd,unsigned char* secret,size_t* secret_key_len,unsigned char* public_key,unsigned char* peer_public_key){
    EVP_PKEY* keypair = EVP_PKEY_Q_keygen(NULL,NULL,"X25519");
    if(keypair==NULL){
        fprintf(stderr,"Failed to create keypair");
        return 1;
    }
    size_t public_key_len= 32;
    if(EVP_PKEY_get_raw_public_key(keypair,public_key,&public_key_len)<=0){
        fprintf(stderr,"Failed to extract public key");
    }
    sendall(public_key,public_key_len,*sockfd);
    char workbuf[BUFFER_SIZE];
    int bytes_in_buffer=0;
    int size =0;
    receive_message(sockfd,workbuf,&bytes_in_buffer,peer_public_key,&size);
    #ifdef TEST_TAMPER
    printf("TEST: Tampering with peer public key\n");
    peer_public_key[0] ^= 0x01;
    #endif

    EVP_PKEY *peer_key =
    EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        32
    );
    if (peer_key == NULL) {
    fprintf(stderr, "Failed to create peer public key\n");
    return 1;
}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (ctx == NULL) {
    fprintf(stderr, "Failed to create context\n");
    return 1;
}
    if (EVP_PKEY_derive_init(ctx) <= 0) {
    fprintf(stderr, "derive_init failed\n");
    return 1;
}
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
    fprintf(stderr, "derive_set_peer failed\n");
    return 1;
}
    size_t secret_len = 0;
if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
    fprintf(stderr, "Failed to determine secret length\n");
    return 1;
}
if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
    fprintf(stderr, "Failed to derive shared secret\n");
    return 1;
}
*secret_key_len = secret_len;
EVP_PKEY_CTX_free(ctx);
EVP_PKEY_free(peer_key);
EVP_PKEY_free(keypair);
return 0;

}

int handshake(int* sockfd,unsigned char* encryption_key,unsigned char* mac_key,unsigned char* write_public_key,int role){
    unsigned char secret[32];
    size_t secret_len;
    //Exchange-keys
    unsigned char public_key[33]; // One extra byte for \0 at the end;
    unsigned char peer_public_key[33]; // One extra byte for \0 at the end;

    secret_key(sockfd,secret,&secret_len,public_key,peer_public_key);
    // Derive encryption and mac key
    derive_key(encryption_key,mac_key,secret,CLIENT);
    unsigned char transcript[64];
    switch(role){
        case CLIENT:
            memcpy(transcript,public_key,32);
            memcpy(transcript+32,peer_public_key,32);
            memcpy(write_public_key, public_key, 32);
            break;
        case SERVER:
            memcpy(transcript,peer_public_key,32);
            memcpy(transcript+32, public_key,32);
            memcpy(write_public_key, peer_public_key, 32);   
            break;
    }
    size_t transcript_len = 64;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len;
    if (HMAC(EVP_sha256(),mac_key,32,transcript,transcript_len,mac,&mac_len) == NULL) {
    fprintf(stderr, "HMAC failed\n");
    return 1;
}
unsigned char peer_mac[EVP_MAX_MD_SIZE];
char workbuf[BUFFER_SIZE];
int bytes_in_buffer=0;
int size = 0;
if(role==SERVER){
    receive_message(sockfd,workbuf,&bytes_in_buffer,peer_mac,&size);
    sendall((unsigned char*)mac,mac_len,*sockfd);

}
else{

    sendall((unsigned char*)mac,mac_len,*sockfd);
    receive_message(sockfd,workbuf,&bytes_in_buffer,peer_mac,&size);

}
if(CRYPTO_memcmp(mac,peer_mac,32)==0){
    printf("Handshake successful!\n");
    return 0;
}
else{
    printf("Handshake unsuccessful!\n");
    return 1;
}
}