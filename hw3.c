#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef struct pcap_pkthdr pcap_pkthdr;
typedef struct ether_header ether_header;
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;
typedef struct ip ip;

char *mac_ntoa(u_char *d) 
{
    char *mac = malloc(sizeof(char) * 100);
    strcpy(mac, "");
    for(int i = 0; i < 6; i++) 
    {
        char *tmp = malloc(sizeof(char) * 2);
        sprintf(tmp, "%02x", d[i]);
        if(i) strcat(mac, ":");
        strcat(mac, tmp);
    }
    return mac;
}

int main(int argc, char **argv) 
{
    char *filename;
    filename = strdup(argv[argc - 1]);

    char errbuff[PCAP_ERRBUF_SIZE] = "\0";

    pcap_t *handler = pcap_open_offline(filename, errbuff);

    int packet_cnt = 0;
    while(1) 
    {
        pcap_pkthdr *packet_header; // 1.time stamp, 2.length of portion len, 3.length of packet 
        ether_header *eth_header;
        tcphdr *tcp_header;
        udphdr *udp_header;
        time_t time_t_tmp;

        u_char *packet;
        int ret = pcap_next_ex(handler, &packet_header, (const u_char **)&packet);

        time_t_tmp = packet_header->ts.tv_sec;
        struct tm ts = *localtime(&time_t_tmp);
        char str_time[50];
        strftime(str_time, sizeof(str_time),"%a %Y-%m-%d %H:%M:%S", &ts);

        eth_header = (ether_header *)packet;
        char mac_src[100], mac_des[100];
        strcpy(mac_src, mac_ntoa(eth_header->ether_shost));
        strcpy(mac_des, mac_ntoa(eth_header->ether_dhost));

        // ---print section---

        printf("\n---Packet count : %d---\n", ++packet_cnt);

        printf("\n<Info>\n");
        printf("-Time : %s\n", str_time);  
        printf("-Length : %d\n", packet_header->len); 
        printf("-Capture Length : %d\n", packet_header->caplen); 


        printf("\n<MAC>\n");
        printf("-MAC Sourse address : %s\n", mac_src);
        printf("-MAC Destination address : %s\n", mac_des);

        unsigned short type = ntohs(eth_header->ether_type);
        ip *ip_header = (ip *)(packet + ETHER_HDR_LEN);
        
        printf("\n<Ethernet type>\n");
        if(type == ETHERTYPE_IP)  // 0x0800
        {
            char ip_src[INET_ADDRSTRLEN];
            char ip_des[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), ip_src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), ip_des, INET_ADDRSTRLEN);

            printf("-Ethernet type : IP\n");       

            printf("\n<IP>\n");
            printf("-IP Sourse address : %s\n", ip_src);       
            printf("-IP Destination address : %s\n", ip_des);       

            if(ip_header->ip_p == IPPROTO_UDP) 
            {
                udp_header = (udphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
                printf("\n<PORT>\n");
                printf("-Protocol : UDP\n"); 
                printf("-Sourse Port : %d\n", ntohs(udp_header->uh_sport));       
                printf("-Destination Port : %d\n", ntohs(udp_header->uh_dport));       
            } else if(ip_header->ip_p == IPPROTO_TCP)
            {
                tcp_header = (tcphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
                printf("\n<PORT>\n");
                printf("-Protocol : TCP\n");       
                printf("-Sourse Port : %d\n", ntohs(tcp_header->th_sport));
                printf("-Destination Port : %d\n", ntohs(tcp_header->th_dport));
            }
        } 
        else if(type == ETHERTYPE_ARP)  // 0x0806
        {
            printf("-Ethernet type : ARP\n");       
        } 
        else if(type == ETHERTYPE_PUP)  // 0x0200
        {
            printf("-Ethernet type : PUP\n");       
        } 
        else if(type == ETHERTYPE_IPV6) // 0x86dd
        {
            printf("-Ethernet type : IPv6\n");       
        } 
        else 
        {
            printf("-Ethernet type : unknown\n");       
        }
        if(ret == 0) 
            continue;
        else if(ret == -2) 
        {
            printf("\n---The end of %s---\n", filename);
            break;
        }
        else if(ret == -1) 
        {
            printf("pcap_next_ex error!!\n");
            exit(1);
        }
    }
    return 0;
}
