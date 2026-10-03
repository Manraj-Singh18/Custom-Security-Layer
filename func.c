#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "func.h"

int Accept_Connection(int* fd, int* sockfd, struct sockaddr_in* client_addr){
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

int Recieve_Message(int *fd,char* workbuf,int* bytes_in_buffer,unsigned char*print_buf){
    
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

int secret_key(int *sockfd,unsigned char* secret,size_t* secret_key_len){
    EVP_PKEY* keypair = EVP_PKEY_Q_keygen(NULL,NULL,"X25519");
    if(keypair==NULL){
        fprintf(stderr,"Failed to create keypair");
        return 1;
    }
    unsigned char public_key[256];
    size_t public_key_len= sizeof(public_key);
    if(EVP_PKEY_get_raw_public_key(keypair,public_key,&public_key_len)<=0){
        fprintf(stderr,"Failed to extract public key");
    }
    sendall(public_key,public_key_len,*sockfd);
    unsigned char peer_public_key[32];
    char workbuf[64];
    int bytes_in_buffer=0;
    Recieve_Message(sockfd,workbuf,&bytes_in_buffer,peer_public_key);
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
printf("Shared secret (%zu bytes): ", secret_len);
for (size_t i = 0; i < secret_len; i++) {
    printf("%02x", secret[i]);
}

printf("\n");
EVP_PKEY_CTX_free(ctx);
EVP_PKEY_free(peer_key);
EVP_PKEY_free(keypair);
return 0;

}

