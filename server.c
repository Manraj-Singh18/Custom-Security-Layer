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
#define BUFFER_SIZE 1024

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

int Recieve_Message(int *fd,char* workbuf,int* bytes_in_buffer){
    

    ssize_t n;
    n = recv(*fd,workbuf + *bytes_in_buffer,BUFFER_SIZE - *bytes_in_buffer,0);
  
    size_t frame_len = (unsigned char)workbuf[0]+1;
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
fwrite(workbuf+1,1,frame_len-1,stdout);
fflush(stdout);
size_t remaining = *bytes_in_buffer-frame_len;
memmove(
    workbuf,
    workbuf + frame_len,
    remaining
);

*bytes_in_buffer= remaining;
return(1);

}

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
    
    //Accept Client Request
    Accept_Connection(&fd,&sockfd,&client_addr);
    
    //Welcome Message
    char* user = inet_ntoa(client_addr.sin_addr);
    char welcome[50];
    sprintf(welcome, "Hello user %s", user);
    int len, bytes_sent;
    len = strlen(welcome);
    bytes_sent = send(fd, welcome, len, 0);
    
    //Recieve messages from client
    int bytes_in_buffer=0;
    char buf[BUFFER_SIZE];
    while(1){
        int check = Recieve_Message(&fd,buf,&bytes_in_buffer);
        if(check<1){
            break;
        }
        printf("\n");
    }
    close(fd);
    close(sockfd);
    return 0;






}