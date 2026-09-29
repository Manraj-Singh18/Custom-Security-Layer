#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 6996
#define BACKLOG 10

int main(){
    int sockfd, fd;
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
    socklen_t client_addr_len = sizeof(client_addr);
    fd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len    );
    if(fd<0){
        perror("Connection not established!");
        close(sockfd);
        exit(-1);
    }
    char* user = inet_ntoa(client_addr.sin_addr);
    char welcome[50];
    sprintf(welcome, "Welcome user %s", user);
    int len, bytes_sent;
    len = strlen(welcome);
    bytes_sent = send(fd, welcome, len, 0);
    close(fd);
    close(sockfd);
   return 0;






}