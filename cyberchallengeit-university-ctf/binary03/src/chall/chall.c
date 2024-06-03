#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <node/zlib.h>

int connect_to_license_check_server()
{
    struct addrinfo hints, *res, *result;
    char addrstr[256];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    int errcode;
    int port = atoi(getenv("PORT"));
    errcode = getaddrinfo(getenv("REMOTE"), NULL, &hints, &result);
    if (errcode != 0)
    {
        puts("Could not resolve license check server address, please ensure you have working internet connection for license activation.");
        exit(-1);
    }

    res = result;
    if(!res){
        puts("Could not resolve license check server address, please ensure you have working internet connection for license activation.");
        exit(-1);
    }
    inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 256);

    int client_fd;
    struct sockaddr_in serv_addr;
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        puts("Could not create socket for license check server, please ensure you have working internet connection for license activation.");
        exit(-1);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    int status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if(status<0){
        puts("Could not connect to license check server, please ensure you have working internet connection for license activation.");
        exit(-1);
    }
    return client_fd;
}

int main()
{
    setbuf(stdout, NULL);
    if(!getenv("REMOTE") || !getenv("PORT")){
        puts("Usage: REMOTE=<license-server-address> PORT=<license-server-port> ./licensechecker");
        exit(-1);
    }
    puts("Your free trial has expired. Please provide your license key in order to keep using this software.");
    printf("> ");
    char *license=0;
    size_t readlen=0;
    int retval = getline(&license, &readlen, stdin);
    if (retval == -1)
    {
        exit(-1);
    }
    license[strcspn(license, "\n")] = 0;
    if (strlen(license) % 3 != 0)
    {
        puts("Invalid license. Please refer to our website in order to purchase one.");
        exit(-1);
    }
    for (int i = 0; i < strlen(license); i += 3)
    {
        if (!('0' <= license[i] <= '9') || !('A' <= license[i + 1] <= 'Z') || !('A' <= license[i + 2] <= 'Z'))
        {
            puts("Invalid license. Please refer to our website in order to purchase one.");
            exit(-1);
        }
    }
    void *globalmemory = mmap((void *)0x60000, 4096,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                              -1, 0);
    if (globalmemory != (void *)0x60000)
    {
        puts("Could not initiate license check.");
        exit(-1);
    }
    void (*execmemory)(int64_t v1, int64_t v2) = mmap(NULL, 4096,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS,
                            -1, 0);
    int client_fd = connect_to_license_check_server();
    int bytes_read=0;
    char size;
    for (int i = 0; i < strlen(license); i += 3)
    {
        send(client_fd, &(license[i]), 1, 0);
        bytes_read=read(client_fd, &size, 1);
        if(bytes_read<=0 || size<=0){
            puts("Failed to communicate with license check server. Please ensure you have working internet connection for license activation.");
            exit(-1);
        }
        bytes_read=read(client_fd, execmemory, size);
        if(bytes_read<=0){
            puts("Failed to communicate with license check server. Please ensure you have working internet connection for license activation.");
            exit(-1);
        }
        execmemory(((int64_t) license[i+1])-'A', ((int64_t) license[i+2])-'A');
    }
    unsigned long  crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const unsigned char*)globalmemory, 128);
    if(crc==0xbadc0ff3){
        char* flag = getenv("FLAG");
        if(!flag){
            flag="CCIT{fakeflag}";
        }
        printf("You have succesfully activate your license. Have fun using our product! Signed: %s\n", flag);
        exit(0);
    }
    puts("Sorry, your license is not valid.");
    return -1;
}