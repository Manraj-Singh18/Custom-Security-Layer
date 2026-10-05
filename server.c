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

int main(){
    int sockfd, fd;
    struct sockaddr_in my_addr;
    struct sockaddr_in client_addr;

    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0){
        perror("Socket Creation Failed."); 
        exit(-1);
    }
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(PORT);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(&(my_addr.sin_zero),'\0',sizeof(my_addr.sin_zero));
    
    if(bind(sockfd,(struct sockaddr*)&my_addr, sizeof(my_addr))<0){
        perror("bind failed!");
        close(sockfd);
        exit(-1);
    }
    
    if(listen(sockfd, BACKLOG)<0){
        perror("Listen failed!");
        close(sockfd);
        exit(-1);
    }
    //Accept Client Request
    accept_connection(&fd,&sockfd,&client_addr);
    
    unsigned char client_encryption_key[32];
    unsigned char client_mac_key[32];
    unsigned char client_send_public_key[32];
    handshake(&fd,client_encryption_key,client_mac_key,client_send_public_key,SERVER);
    
    //Recieve messages from client
    int bytes_in_buffer = 0;
    char buf[BUFFER_SIZE];
    unsigned char message_recv[BUFFER_SIZE];
    int message_len = 0;
    uint64_t expected_seq = 0;                 

    while (1) {
        int check = receive_message(&fd, buf, &bytes_in_buffer, message_recv, &message_len);
        if (check < 1) break;

        if (message_len < 8 + 16) {          
        fprintf(stderr, "Record too short\n");
        break;
        }

        int ct_len = message_len - 8 - 16;
        uint64_t recv_seq;
            memcpy(&recv_seq, message_recv, 8);
        if (recv_seq != expected_seq) {
        fprintf(stderr, "Bad sequence number\n");
        break;
    }

    unsigned char plaintext[BUFFER_SIZE];
    int pt_len = decrypt_message(message_recv + 8, ct_len,
                                 client_encryption_key,
                                 client_send_public_key,
                                 expected_seq,
                                 message_recv + 8 + ct_len,   // tag
                                 plaintext);
    if (pt_len < 0) break;               

    plaintext[pt_len] = '\0';
    if(strcmp(plaintext,"exit")==0){
        printf("User left!");
        break;
    }
    printf("%s\n", plaintext);
    expected_seq++;
}

    close(fd);
    close(sockfd);
    return 0;
 }