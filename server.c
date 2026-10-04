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
    size_t secret_len;
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
    handshake(&fd,client_encryption_key,client_mac_key,SERVER);
    
    //Recieve messages from client
    int bytes_in_buffer=0;
    char buf[BUFFER_SIZE];
    unsigned char message_recv[BUFFER_SIZE];
    while(1){
        int check = receive_message(&fd,buf,&bytes_in_buffer,message_recv);
        if(check<1){
            break;
        }
        printf("%s\n",message_recv);
    }

    close(fd);
    close(sockfd);
    return 0;
 }