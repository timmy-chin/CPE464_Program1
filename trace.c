#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#define MAC_SIZE 6
#define IP_SIZE 4
#define REQUEST 256
#define REPLY 512

struct arpHeader {
    uint16_t htype;  // Hardware type
    uint16_t ptype;  // Protocol type
    uint8_t hlen;    // Hardware address length
    uint8_t plen;    // Protocol address length
    uint16_t opcode; // Operation (request/reply)
    uint8_t sender_mac[MAC_SIZE]; // Sender MAC address
    uint8_t sender_ip[IP_SIZE];  // Sender IP address
    uint8_t target_mac[MAC_SIZE]; // Target MAC address
    uint8_t target_ip[IP_SIZE];  // Target IP address
};

// use memcopy for copying bytes

void getEthernetType(uint16_t type, char *buffer) {
    if (type == ETH_P_IP){
        strcpy(buffer, "IP");
    }
    else {
        strcpy(buffer, "ARP");
    }
}

void printARPHeader(char *opCode, struct in_addr sender_ip, struct in_addr target_ip, u_char *sm, u_char *tm) {
    printf("\tARP header\n");
    printf("\t\tOpcode: %s\n", opCode);
    printf("\t\tSender MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", sm[0], sm[1], sm[2], sm[3], sm[4], sm[5]);
    printf("\t\tSender IP: %s\n", inet_ntoa(sender_ip));
    printf("\t\tTarget MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", tm[0], tm[1], tm[2], tm[3], tm[4], tm[5]);
    printf("\t\tTarget IP: %s\n", inet_ntoa(target_ip));
    printf("\n");
}

void getARPOpCode(uint16_t opcode, char *buffer){
    if (opcode == REQUEST){
        strcpy(buffer, "Request");
    }
    else {
        strcpy(buffer, "Reply");
    }
}

void processType(char *type, const u_char *packet_data, struct ethhdr *eth) {
    if (strcmp(type, "ARP") == 0){
        struct arpHeader *arp = (struct arpHeader *)(packet_data + sizeof(struct ethhdr));
        struct in_addr sender_ip;
        struct in_addr target_ip;
        u_char sm[MAC_SIZE];
        u_char tm[MAC_SIZE];
        memcpy(&sender_ip.s_addr, arp->sender_ip, IP_SIZE);   
        memcpy(&target_ip.s_addr, arp->target_ip, IP_SIZE);
        memcpy(&sm, arp->sender_mac, MAC_SIZE);
        memcpy(&tm, arp->target_mac, MAC_SIZE);
        char opCode[10];

        getARPOpCode(arp->opcode, opCode);
        printARPHeader(opCode, sender_ip, target_ip, sm, tm);
    }
    else{
        struct iphdr *ip = (struct iphdr *)(packet_data + sizeof(struct ethhdr));
        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = ip->saddr;
        dst_ip.s_addr = ip->daddr;

        printf("IP Source: %s\n", inet_ntoa(src_ip));
        printf("IP Destination: %s\n", inet_ntoa(dst_ip));
    }

}

void printEthernetHeader(int count, int length, unsigned char* dest, unsigned char* src, char* type) {
    printf("\nPacket number: %d  Packet Len: %d\n\n", count, length);
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
    printf("\t\tSource MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", src[0], src[1], src[2], src[3], src[4], src[5]);
    printf("\t\tType: %s\n", type);
    printf("\n");
}

void processPacket(struct pcap_pkthdr *packet_header,  const u_char *packet_data, int count) {
    int length = packet_header -> len;
    struct ethhdr *eth = (struct ethhdr *)packet_data;
    unsigned char *dest = eth->h_dest;
    unsigned char *src = eth->h_source;
    char ethernet_type[5];

    getEthernetType(ntohs(eth->h_proto), ethernet_type);
    printEthernetHeader(count, length, dest, src, ethernet_type);
    processType(ethernet_type, packet_data, eth);
}

int main(int argc, char *argv[]) {
    const char *packet_name = argv[1];
    struct pcap_pkthdr *packet_header;
    const u_char *packet_data;

    pcap_t *fp = pcap_open_offline(packet_name, 0);

    int count = 1;
    while ((pcap_next_ex(fp, &packet_header, &packet_data)) >= 0) {
        processPacket(packet_header, packet_data, count);
        count++;
    }

    pcap_close(fp);
    return 0;
}