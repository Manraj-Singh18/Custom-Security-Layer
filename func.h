#ifndef FUNC_H
#define FUNC_H

#define DEST_IP "127.0.0.1"
#define DEST_PORT 6996

#define PORT 6996
#define BACKLOG 10

#define FRAME_SIZE 256
#define BUFFER_SIZE 1024

int Accept_Connection(int* fd, int* sockfd, struct sockaddr_in* client_addr);
int sendall(unsigned char *message, int len, int sockfd);
int Recieve_Message(int *fd, char *workbuf, int *bytes_in_buffer,unsigned char*peer_public_key);
int secret_key(int* sockfd,unsigned char* secret,size_t* secret_key_len);
int derive_key(unsigned char* encryption_key, unsigned char* mac_key, unsigned char* skey);

#endif      