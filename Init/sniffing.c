#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h> // 用于AF_PACKET和socket数据结构
#include <netinet/ether.h>

int main(){
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;
    
    int sock = sock(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    while(1){
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t*)sizeof(saddr));
        if(data_size) printf("Got one packet\n");
    }
    close(sock);
    return 0;
}

void send_raw_ip_packet(struct ipheader* ip){
    struct sockaddr_in dest_info;
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr  = ip->iph_destip;
    printf("Sending spoofed Ip packet...\n");
    if(sendto(sock, ip, ntohs(ip->iph_len),(struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){
        perror("PACKET NOT SENT\n") ;
        return;
    }
    close(sock);    
}

