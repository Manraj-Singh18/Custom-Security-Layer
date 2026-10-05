#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <unistd.h> 
#include "func.h"

int main(){
    int sockfd;
    struct sockaddr_in dest_addr;
    const char* cp = DEST_IP;
    uint64_t send_seq=0;
    

    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0){
        perror("Socket Creation Failed!"); 
        exit(-1);
    }
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);

    if(inet_aton(cp, &dest_addr.sin_addr) == 0) {
    perror("Invalid IP address");
    close(sockfd);
    exit(EXIT_FAILURE);
}
    memset(&(dest_addr.sin_zero),'\0',sizeof(dest_addr.sin_zero));
    
    if(connect(sockfd,(struct sockaddr*)&dest_addr, sizeof(dest_addr))<0){
        perror("connection failed!");
        close(sockfd);
        exit(-1);
    }
    
    unsigned char client_encryption_key[32];
    unsigned char client_mac_key[32];
    unsigned char client_send_public_key[32];
    handshake(&sockfd,client_encryption_key,client_mac_key,client_send_public_key,CLIENT);
    unsigned char* message = NULL;
    size_t  len =0;
    while(1){
        int read = getline(&message,&len,stdin);
        if(read<0){
            printf("failed to parse your message, Try again!\n");
            continue;
        }
        message[read-1] ='\0';
        read--;
        unsigned char ciphertext[read];
        unsigned char record[1024];
        const unsigned char tag[16];
        int ciphertext_len=encrypt_message(message,read,
            client_send_public_key,
            client_encryption_key,
            send_seq,
            ciphertext,
            tag);
        //pack the seq,tag,ciphertext
        memcpy(record, &send_seq, 8);
    memcpy(record + 8, ciphertext, ciphertext_len);
    memcpy(record + 8 + ciphertext_len, tag, 16);
    int record_len = ciphertext_len+8+16;   
        sendall(record,record_len,sockfd);
        send_seq++;
        if(strcmp(message,"exit")==0){
            printf("Good-Bye User!\n");
            close(sockfd);
            exit(0);
        }
    }
    close(sockfd);
   






}