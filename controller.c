#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define TIMEOUT_MICROS 3000000
#define BUFLEN 512

#define OPTBUF_SETUP(NAME) \
char NAME##_opt[256]; \
int NAME##_opt_len = 0; \

#define PARSE_ADDR_FOR(NAME) \
char NAME##_ip_str[128]; \
int NAME##_ip_str_len = 0; \
int NAME##_port = 0; \
if(!(strncmp(#NAME, "client", 6) == 0 && client_wildcard) && parse_addr_opt(NAME##_opt, NAME##_opt_len, NAME##_ip_str, &NAME##_ip_str_len, &NAME##_port) == -1) \
{ \
return 0; \
} \

#define OPTCPY(NAME) \
opt_str_len = strlen(optarg); \
if(opt_str_len > 255) \
{ \
opt_str_len = 255; \
} \
strncpy(NAME##_opt, optarg, opt_str_len); \
NAME##_opt_len = opt_str_len; \

#define WRITE_ADDR(NAME) \
sscanf(NAME##_ip_str, "%hhu.%hhu.%hhu.%hhu", wptr, wptr + 1, wptr + 2, wptr + 3); \
wptr += 4; \
wptr[0] = (uint8_t)(NAME##_port); \
wptr[1] = (uint8_t)(NAME##_port >> 8); \
wptr += 2; \

#define INVALID_RET() \
printf("invalid response\n"); \
return 0; \

int parse_addr_opt(char* optbuf, int optbuf_len, char* out_ip, int* out_ip_len, int* out_port)
{
    char* buf_separator = strnstr(optbuf, ":",optbuf_len);
    if(buf_separator == NULL)
    {
        printf("invalid addr\n");
        return -1;
    }
    
    strncpy(out_ip, optbuf, (buf_separator - optbuf));
    *out_ip_len = (buf_separator - optbuf);
    
    *out_port = atoi(buf_separator + 1);
    return 0;
}

void recv_timeout(int i)
{
    printf("ERR: request timed out\n");
    exit(0);
}

int main(int argc, char** argv)
{
    //-k	- key file
    //-t	- target proxy node
    //-c	- client ip:port/WX
    //-d	- dest ip:port
    
    OPTBUF_SETUP(authkey);
    OPTBUF_SETUP(target);
    OPTBUF_SETUP(client);
    OPTBUF_SETUP(dest);
    
    uint8_t client_wildcard = 0;
    
    int opt_str_len = 0;
    char optc = '?';
    int opt_len = 0;
    opterr = 0;
    while((optc = getopt(argc, argv, "k:t:c:d:")) && optc != -1)
    {
        switch(optc)
        {
            case 'k':
                OPTCPY(authkey);
                break;
            case 't':
                OPTCPY(target);
                break;
            case 'c':
                if(strncmp(optarg, "WX", 2) == 0)
                {
                    client_wildcard = 1;
                }
                else
                {
                    OPTCPY(client);
                }
                break;
            case 'd':
                OPTCPY(dest);
                break;
            case '?':
            default:
                printf("opt parse err\n");
                return 0;
        }
        ++opt_len;
    }
    
    if(opt_len < 4)
    {
        printf("k, t, c, d opt required\n");
        return 0;
    }
    
    unsigned char keybuf[128];
    FILE* keyfile = fopen(authkey_opt, "rb");
    if(keyfile == NULL) { perror("keyfile open"); return 0; }
    
    if (fread(keybuf, 128, 1, keyfile) < 1) { printf("keyfile read err\n"); return 0; }
    
    PARSE_ADDR_FOR(target);
    PARSE_ADDR_FOR(client);
    PARSE_ADDR_FOR(dest);
    
    printf("ext controller run..\n");
    
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    ssize_t ret = 0;
    ret = bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if(ret == -1) { perror("bind"); return 0; }
    
    unsigned char buf[BUFLEN];
    size_t buflen = 0;
    
    unsigned char* wptr = buf;
    wptr[0] = 0x0e;
    wptr[1] = 0x02;
    wptr += 2;
    
    memcpy(wptr, keybuf, 128);
    wptr += 128;
    
    if(client_wildcard)
    {
        wptr[0] = 0x01;
        ++wptr;
    }
    else
    {
        wptr[0] = 0x00;
        ++wptr;
        WRITE_ADDR(client);
    }
    
    WRITE_ADDR(dest);
    
    buflen = wptr - buf;
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    
    char dest_addr_str[128];
    sprintf(dest_addr_str, "%.*s", target_ip_str_len, target_ip_str);
    ret = inet_pton(AF_INET, dest_addr_str, &(dest.sin_addr));
    if(ret == 0)
    {
        printf("can't parse address\n");
        return 0;
    }
    else if(ret == -1)
    {
        perror("inet_pton");
    }
    
    ret = sendto(fd, buf, buflen, 0, (struct sockaddr*)&dest, sizeof(struct sockaddr_in));
    
    if(ret == -1) { perror("sendto"); return 0; }
    
    printf("sent switch request to proxy node %.*s", target_opt_len, target_opt);
    if(client_wildcard)
    {
        printf(" [set dest to %.*s for all clients]\n", dest_opt_len, dest_opt);
    }
    else
    {
        printf(" [set dest to %.*s for %.*s]\n", dest_opt_len, dest_opt, client_opt_len, client_opt);
    }
    
    signal(SIGALRM, recv_timeout);
    ualarm(TIMEOUT_MICROS, 0);
    
    memset(buf, 0, BUFLEN);
    ret = recvfrom(fd, buf, BUFLEN, 0, NULL, 0);
    
    if(ret == -1) { perror("recvfrom"); return 0; }
    
    useconds_t ti = TIMEOUT_MICROS - ualarm(0, 0);
    printf("response in %u micros\n", ti);
    
    if(ret < 2) { INVALID_RET(); }
    unsigned char hdr = buf[0];
    if(hdr != 0x0e) { INVALID_RET(); }
    unsigned char id = buf[1];
    if(id == 0x07)
    {
        if(ret < 3) { INVALID_RET(); }
        unsigned char rcode = buf[2];
        if(rcode == 0x00)
        {
            printf("OK: request completed\n");
        }
        else if(rcode == 0x01)
        {
            printf("ERR: client not found\n");
        }
        else if (rcode == 0x02)
        {
            printf("ERR: invalid request\n");
        }
        else if(rcode == 0x05)
        {
            printf("ERR: unauthorized\n");
        }
    }
    
    return 0;
}
