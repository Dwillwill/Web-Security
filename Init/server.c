#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>


int main(){
    struct sockaddr_in server;
    struct sockaddr_in client;
    socklen_t clientlen;
    char buf[1500];

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(9090);

    if(bind(sock, (struct sockaddr *) &server, sizeof(server)) < 0){
        perror("Error on binding\n");
    }

    while(1){
        bzero(buf, 1500);
        recvfrom(sock, buf, 1500 - 1, 0, (struct sockaddr *) &client, &clientlen);
        printf("buf: %s\n", buf);
        printf("clientlen: %d\n", clientlen);
    }
    close(sock);
}