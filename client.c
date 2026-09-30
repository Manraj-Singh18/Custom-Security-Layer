#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEST_IP "127.0.0.1"
#define DEST_PORT 6996
#define BACKLOG 10


int main(){
    int sockfd;
    struct sockaddr_in dest_addr;
    const char* cp = DEST_IP;
    int bytes_sent;
    

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

    char* message = NULL;
    size_t  len =0;
    while(1){
        int read = getline(&message,&len,stdin);
        message[read-1] ='\0';
        read--;
        if(read<0){
            printf("failed to parse your message, Try again!\n");
            continue;
        }
        bytes_sent = send(sockfd, message, read, 0);
        if (bytes_sent < 0) {
            perror("Send failed");
            break;
        }

    }


   
    close(sockfd);
   






}