#ifndef KEY_H
#define KEY_H
int secret_key(int *sockfd,unsigned char* secret,size_t* secret_key_len,unsigned char* public_key,unsigned char* peer_public_key);
int handshake(int* sockfd,unsigned char* encryption_key,unsigned char* mac_key,unsigned char* write_public_key,int role);

#endif     