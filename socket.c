#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

struct sockaddr{
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_in{
    short int sin_family;
    unsigned short int sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

struct in_addr{
    u_int32_t s_addr;
};

