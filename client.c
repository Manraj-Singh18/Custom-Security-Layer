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
    unsigned char secret[32];
    size_t secret_len;
    secret_key(&sockfd,secret,&secret_len);
    
    char buf[50];
    ssize_t n = recv(sockfd, buf,sizeof(buf)-1,0);
    if(n>0){
        buf[n] = '\0';
        printf("%s\n",buf);
    }
    else if(n==0){
        printf("Server closed connection\n");
    }
    else{
        perror("recv failed!");
    }

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
        sendall(message,read,sockfd);
        if(strcmp(message,"exit")==0){
            printf("Good-Bye User!\n");
            close(sockfd);
            exit(0);
        }
    }
    close(sockfd);
   






}