#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/params.h>
#include <openssl/crypto.h>
#include "com.h"



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

int receive_message(int *fd,char* workbuf,int* bytes_in_buffer,unsigned char*print_buf,int* message_len){
    
    ssize_t n;
    n = recv(*fd,workbuf + *bytes_in_buffer,BUFFER_SIZE - *bytes_in_buffer,0);
    int frame_len = (unsigned char)workbuf[0]+1;
    *message_len = frame_len-1;
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






