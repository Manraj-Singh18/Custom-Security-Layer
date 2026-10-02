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



int main(){
    int sockfd, fd;
    unsigned char secret[32];
    int secret_len;
    struct sockaddr_in my_addr;
    struct sockaddr_in client_addr;

    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0){
        perror("Socket Creation Failed!"); 
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
    Accept_Connection(&fd,&sockfd,&client_addr);
    secret_key(&fd,secret_key,&secret_len);
    
    //Welcome Message
    char* user = inet_ntoa(client_addr.sin_addr);
    char welcome[50];
    sprintf(welcome, "Hello user %s", user);
    int len;
    len = strlen(welcome);
    send(fd, welcome, len, 0);
    
    //Recieve messages from client
    int bytes_in_buffer=0;
    char buf[BUFFER_SIZE];
    char* message_recv;
    while(1){
        int check = Recieve_Message(&fd,buf,&bytes_in_buffer,message_recv);
        if(check<1){
            break;
        }
        printf("%s\n",message_recv);
    }
    close(fd);
    close(sockfd);
    return 0;






}