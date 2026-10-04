#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include "func.h"

// #define TEST_TAMPER 1

int accept_connection(int* fd, int* sockfd, struct sockaddr_in* client_addr){
    socklen_t client_addr_len = sizeof(*client_addr);
    *fd = accept(*sockfd, (struct sockaddr*)client_addr, &client_addr_len    );
    if(*fd<0){
        perror("Connection not established!");
        close(*sockfd);
        return(-1);
    }
    return 1;
}

int sendall(unsigned char* message,int len,int sockfd){
    if (len > 255) {
    fprintf(stderr, "Message too long\n");
    return -1;
    }
    char frame[FRAME_SIZE];
    frame[0]= (unsigned char)len;
    memcpy(frame+1,message,len);
    int sent =0;
    while(sent<len+1){
        ssize_t bytes_sent = send(sockfd, frame+sent, len+1-sent, 0);
        if (bytes_sent < 0) {
            perror("Send failed");
            break;
        }
        sent+=bytes_sent;
    }
    return(0);
}

int receive_message(int *fd,char* workbuf,int* bytes_in_buffer,unsigned char*print_buf){
    
    ssize_t n;
    n = recv(*fd,workbuf + *bytes_in_buffer,BUFFER_SIZE - *bytes_in_buffer,0);
    int frame_len = (unsigned char)workbuf[0]+1;
    if (n > 0) {
        *bytes_in_buffer += n;
        if (frame_len - 1 == 4 &&
        memcmp(workbuf + 1, "exit", 4) == 0) {
        printf("User left!\n");
        close(*fd);
        exit(0);
    }
    }
    else if (n == 0) {
        printf("Client closed connection\n");
        return 0;
    }
    else {
        perror("recv failed!");
        return -1;
    }
    while(*bytes_in_buffer<frame_len){
        n = recv(*fd, workbuf+*bytes_in_buffer,(BUFFER_SIZE-*bytes_in_buffer),0);
    if(n>0){
        *bytes_in_buffer+=n;
    }
    else if(n==0){
        printf("Client closed connection\n");
        return(0);
    }
    else{
        perror("recv failed!");
        return(-1);
    }
}

memcpy(print_buf,workbuf+1,frame_len-1);
print_buf[frame_len - 1] = '\0';
size_t remaining = *bytes_in_buffer-frame_len;
memmove(
    workbuf,
    workbuf + frame_len,
    remaining
);
*bytes_in_buffer= remaining;
return(1);
}

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
    receive_message(sockfd,workbuf,&bytes_in_buffer,peer_public_key);
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

int derive_key(unsigned char* encryption_key, unsigned char* mac_key, unsigned char* skey,enum TLSWriter writer){
    unsigned char prk[32];  
    EVP_KDF* kdf = EVP_KDF_fetch(NULL,"HKDF",NULL);
    EVP_KDF_CTX* extract_ctx = EVP_KDF_CTX_new(kdf);
    const char* info;
    const char* mac_info; 
    //Check who writes
    switch(writer){
        case CLIENT:
            info = "CSL Client-to-Server Encryption-Key";
            mac_info = "CSL Client-to-Server MAC-Key";
            break;
        case SERVER:
            info = "CSL Server-to-Client Encryption-Key";
            mac_info = "CSL Server-to-Client MAC-Key";
            break;

    }
    // extract encryption key
    OSSL_PARAM extract_params[]={
        OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        "SHA256",
        0
    ),

    OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY,
    skey,
    32
    ),  
    OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_MODE,
    "EXTRACT_ONLY",
    0
    ),

    OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(extract_ctx,prk,sizeof(prk),extract_params) <= 0) {
    fprintf(stderr, "HKDF-Extract failed\n");
    return 1;
}

    EVP_KDF_CTX_free(extract_ctx);
// expand encryption key
    EVP_KDF_CTX* expand_ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM expand_params[]={
        OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        "SHA256",
        0
    ),

    OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY,
    prk,
    sizeof(prk)
    ),
    OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        (void *)info,
        strlen(info)
    ),

    OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_MODE,
    "EXPAND_ONLY",
    0
    ),

    OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(expand_ctx, encryption_key, 32, expand_params) <= 0) {
    fprintf(stderr, "HKDF-Expand failed\n");
    EVP_KDF_CTX_free(expand_ctx);
    EVP_KDF_free(kdf);
    return 1;
}
    EVP_KDF_CTX_free(expand_ctx);
// expand mac key
EVP_KDF_CTX* mac_ctx = EVP_KDF_CTX_new(kdf);

    OSSL_PARAM mac_params[]={
        OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        "SHA256",
        0
    ),

    OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY,
    prk,
    sizeof(prk)
    ),
    OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        (void *)mac_info,
        strlen(mac_info)
    ),

    OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_MODE,
    "EXPAND_ONLY",
    0
    ),

    OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(mac_ctx, mac_key, 32, mac_params) <= 0) {
    fprintf(stderr, "HKDF-Expand MAC key failed\n");

    EVP_KDF_CTX_free(mac_ctx);
    EVP_KDF_free(kdf);
    return 1;
}
EVP_KDF_CTX_free(mac_ctx);
EVP_KDF_free(kdf);
return 0;




}

//To Do: pass actual client and server public key as transcript

int handshake(int* sockfd,unsigned char* encryption_key,unsigned char* mac_key,int role){
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
            break;
        case SERVER:
            memcpy(transcript,peer_public_key,32);
            memcpy(transcript+32, public_key,32);   
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
if(role==SERVER){
    receive_message(sockfd,workbuf,&bytes_in_buffer,peer_mac);
    sendall((unsigned char*)mac,mac_len,*sockfd);

}
else{

    sendall((unsigned char*)mac,mac_len,*sockfd);
    receive_message(sockfd,workbuf,&bytes_in_buffer,peer_mac);

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