#ifndef FUNC_H
#define FUNC_H

#define DEST_IP "127.0.0.1"
#define DEST_PORT 6996

#define PORT 6996
#define BACKLOG 10

#define FRAME_SIZE 256
#define BUFFER_SIZE 1024

#define KEY_LEN   32
#define NONCE_LEN 12
#define TAG_LEN   16
enum TLSWriter{
    CLIENT,
    SERVER
};  

int accept_connection(int* fd, int* sockfd, struct sockaddr_in* client_addr);
int sendall(unsigned char *message, int len, int sockfd);
int receive_message(int *fd, char *workbuf, int *bytes_in_buffer,unsigned char*peer_public_key,int* message_len);
int secret_key(int* sockfd,unsigned char* secret,size_t* secret_key_len,unsigned char* public_key,unsigned char* peer_public_key);
int derive_key(unsigned char* encryption_key, unsigned char* mac_key, unsigned char* skey,enum TLSWriter writer);
int handshake(int* sockfd,unsigned char* encryption_key,unsigned char* mac_key,unsigned char* write_public_key,int role);
void make_nonce(unsigned char *nonce,const unsigned char *iv,uint64_t seq);
int encrypt_message(const unsigned char *plaintext,
    int plaintext_len,
    unsigned char* public_write_key,
    const unsigned char *write_key,
    uint64_t seq,
    unsigned char *ciphertext,
    unsigned char *tag);
int decrypt_message(
    const unsigned char *ciphertext,
    int ciphertext_len,

    const unsigned char *write_key,
    unsigned char *public_write_key,

    uint64_t seq,
    const unsigned char *tag,

    unsigned char *plaintext
);

#endif      