#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "checksum.h"

#define MAC_SIZE 6
#define IP_SIZE 4
#define REQUEST 256
#define REPLY 512
#define DNS 53
#define HTTP 80
#define TELNET 23
#define FTP 20
#define POP3 110
#define SMTP 25
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define ETHERNET_TYPE_IP 0x0800
#define ICMP_PROTOCOL 1
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6


struct ethHeader {
    uint8_t destination[MAC_SIZE];
    uint8_t source[MAC_SIZE];
    uint16_t type;
};

struct ipHeader {
    unsigned int ip_header_len:4;
    unsigned int version:4;
    unsigned int DSCP : 6;
    unsigned int ECN : 2; 
    uint16_t total_len;
    uint16_t identity;
    uint16_t flags_and_fragment;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t destination;
};

struct arpHeader {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_addrs_len;
    uint8_t protocol_addrs_len;
    uint16_t opcode;
    uint8_t mac_source[MAC_SIZE];
    uint8_t ip_source[IP_SIZE];
    uint8_t mac_destination[MAC_SIZE];
    uint8_t ip_destination[IP_SIZE];
};

struct icmpHeader {
    uint8_t icmp_type;
    uint8_t opcode;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
};

struct udpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t udp_len;
    uint16_t checksum;
};

struct tcpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledge_number;
    unsigned int reserved1:4;
    unsigned int offset:4;
    unsigned int finish_flag:1;
    unsigned int sync_flag:1;
    unsigned int reset_flag:1;
    unsigned int push_flag:1;
    unsigned int ack_flag:1;
    unsigned int urg_flag:1;
    unsigned int reserved2:2; 
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// For TCP checksum
struct tcp_pseudo_header {
    unsigned int source;
    unsigned int destination;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short tcp_length;
};

void processPacket(struct pcap_pkthdr *packet_header, const u_char *packet_data, int count);
void processType(char *type, const u_char *packet_data, struct ethHeader *ethernet);
void processARP(const u_char *packet_data, struct ethHeader *ethernet);
void processIP(const u_char *packet_data, struct ethHeader *ethernet);
void processProtocol(char *protocol, const u_char *packet_data, unsigned int ip_header_len, struct ipHeader *ip);
void processICMP(const u_char *packet_data, unsigned int ip_header_len);
void processUDP(const u_char *packet_data, unsigned int ip_header_len);
void processTCP(const u_char *packet_data, unsigned int ip_header_len, struct ipHeader *ip);
void printEthernetHeader(int count, int length, unsigned char* dest, unsigned char* src, char* type);
void printIPHeader(struct ipHeader *ip, unsigned int ip_header_len, char *ip_protocol, struct in_addr src_ip, struct in_addr dst_ip, char *checkSum);
void printARPHeader(char *opCode, struct in_addr ip_source, struct in_addr ip_destination, u_char *sm, u_char *tm);
void printICMPHeader(char *icmp_type);
void printUDPHeader(char *source_port, char *destination_port);
void printTCPHeader(char *source_port, char *destination_port, unsigned int sequence_number, unsigned int acknowledge_number, int sf, int rf, int ff, int af, int window_size, int data_offset, int checksum, char *checkSumResult);
void getEthernetType(uint16_t type, char *buffer);
void getARPOpCode(uint16_t opcode, char *buffer);
void getIPProtocol(uint8_t protocol, char *buffer);
void getICMPType(uint8_t icmp_type, char *buffer);
void getPortNumber(int port, char *buffer);
void TCPChecksum(struct ipHeader *ip, struct tcpHeader *tcp, const u_char *packet_data, unsigned int ip_header_len, char *result);
void IPCheckSum(const u_char *packet_data, struct ethHeader *ethernet, int header_len, char *buffer);


void getEthernetType(uint16_t type, char *buffer) {
    if (type == ETHERNET_TYPE_IP){
        strcpy(buffer, "IP");
    }
    else {
        strcpy(buffer, "ARP");
    }
}

void getARPOpCode(uint16_t opcode, char *buffer){
    if (opcode == REQUEST){
        strcpy(buffer, "Request");
    }
    else if (opcode == REPLY) {
        strcpy(buffer, "Reply");
    }
    else {
        sprintf(buffer, "%d", opcode);
    }
}

void getIPProtocol(uint8_t protocol, char * buffer){
    if (protocol == ICMP_PROTOCOL) {
        strcpy(buffer, "ICMP");
    }
    else if (protocol == UDP_PROTOCOL) {
        strcpy(buffer, "UDP");
    }
    else if (protocol == TCP_PROTOCOL) {
        strcpy(buffer, "TCP");
    }
    else {
        strcpy(buffer, "Unknown");
    }
}

void getICMPType(uint8_t icmp_type, char * buffer){
    if (icmp_type == ICMP_REQUEST){
        strcpy(buffer, "Request");
    }
    else if (icmp_type == ICMP_REPLY){
        strcpy(buffer, "Reply");
    }
    else {
        sprintf(buffer, "%d", icmp_type);
    }
}

void getPortNumber(int port, char * buffer){
    if (port == DNS) {
        strcpy(buffer, "DNS");
    }
    else if (port == HTTP) {
        strcpy(buffer, "HTTP");
    }
    else if (port == TELNET) {
        strcpy(buffer, "Telnet");
    }
    else if (port == FTP) {
        strcpy(buffer, "FTP");
    }
    else if (port == POP3) {
        strcpy(buffer, "POP3");
    }
    else if (port == SMTP) {
        strcpy(buffer, "SMTP");
    }
    else {
        sprintf(buffer, "%d", port);
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

void printARPHeader(char *opCode, struct in_addr ip_source, struct in_addr ip_destination, u_char *sm, u_char *tm) {
    printf("\tARP header\n");
    printf("\t\tOpcode: %s\n", opCode);
    printf("\t\tSender MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", sm[0], sm[1], sm[2], sm[3], sm[4], sm[5]);
    printf("\t\tSender IP: %s\n", inet_ntoa(ip_source));
    printf("\t\tTarget MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", tm[0], tm[1], tm[2], tm[3], tm[4], tm[5]);
    printf("\t\tTarget IP: %s\n", inet_ntoa(ip_destination));
    printf("\n");
}

void printIPHeader(struct ipHeader *ip, unsigned int ip_header_len, char * ip_protocol, struct in_addr src_ip, struct in_addr dst_ip, char * checkSum) {
    printf("\tIP Header\n");
    printf("\t\tIP Version: %d\n", ip->version);
    printf("\t\tHeader Len (bytes): %d\n", ip_header_len);
    printf("\t\tTOS subfields:\n");
    printf("\t\t   Diffserv bits: %d\n", ip->DSCP);
    printf("\t\t   ECN bits: %d\n", ip->ECN);
    printf("\t\tTTL: %d\n", ip->time_to_live);
    printf("\t\tProtocol: %s\n", ip_protocol);
    printf("\t\tChecksum: %s (0x%04x)\n", checkSum, ntohs(ip->checksum));
    printf("\t\tSender IP: %s\n", inet_ntoa(src_ip));
    printf("\t\tDest IP: %s\n", inet_ntoa(dst_ip));
}

void printICMPHeader(char * icmp_type){
    printf("\n\tICMP Header\n");
    printf("\t\tType: %s\n", icmp_type);
}

void printUDPHeader(char * source_port, char * destination_port){
    printf("\n\tUDP Header\n");
    printf("\t\tSource Port:  %s\n", source_port);
    printf("\t\tDest Port:  %s\n", destination_port);
}

void printTCPHeader(char *source_port, char  *destination_port, unsigned int sequence_number, unsigned int acknowledge_number, int sf, int rf, int ff, int af, int window_size, int data_offset, int checksum, char *checkSumResult){
    printf("\n\tTCP Header\n");
    printf("\t\tSource Port:  %s\n", source_port);
    printf("\t\tDest Port:  %s\n", destination_port);    
    printf("\t\tSequence Number: %u\n", sequence_number);
    printf("\t\tACK Number: %u\n", acknowledge_number);
    printf("\t\tData Offset (bytes): %d\n", data_offset);
    printf("\t\tSYN Flag: %s\n", (sf) ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", (rf) ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", (ff) ? "Yes" : "No");
    printf("\t\tACK Flag: %s\n", (af) ? "Yes" : "No");
    printf("\t\tWindow Size: %d\n", window_size);
    printf("\t\tChecksum: %s (0x%04x)\n", checkSumResult, checksum);
}

void IPCheckSum(const u_char *packet_data, struct ethHeader *ethernet, int header_len, char *buffer) {
    unsigned short *ip_header = (unsigned short *)(packet_data + sizeof(struct ethHeader));
    if (in_cksum(ip_header, header_len) == 0) {
        strcpy(buffer, "Correct");
    }
    else {
        strcpy(buffer, "Incorrect");
    }
}

void TCPChecksum(struct ipHeader *ip, struct tcpHeader *tcp, const u_char *packet_data, unsigned int ip_header_len, char *result) {
    // Making the pseudo header for TCP
    struct tcp_pseudo_header tcp_pseudo_header;
    tcp_pseudo_header.source = ip->source;
    tcp_pseudo_header.destination = ip->destination;
    tcp_pseudo_header.reserved = 0;
    tcp_pseudo_header.protocol = TCP_PROTOCOL;

    // Getting the total length of the TCP segment
    unsigned short tcp_total_length = htons(ntohs(ip->total_len) - ip_header_len);
    tcp_pseudo_header.tcp_length = tcp_total_length;

    uint16_t tcp_length = ntohs(tcp_pseudo_header.tcp_length);

    // Creating the TCP segment
    int total_len = sizeof(tcp_pseudo_header) + tcp_length;
    unsigned char *tcp_segment = malloc(total_len);
    memcpy(tcp_segment, &tcp_pseudo_header, sizeof(tcp_pseudo_header));
    memcpy(tcp_segment + sizeof(tcp_pseudo_header), tcp, tcp_length);

    // Get result of checksum with segment
    unsigned short checksum_result = in_cksum((unsigned short *)tcp_segment, total_len);

    free(tcp_segment);

    if (checksum_result == 0) {
        strcpy(result, "Correct");
    } else {
        strcpy(result, "Incorrect");
    }
}

// Get ICMP info and prin them
void processICMP(const u_char *packet_data, unsigned int ip_header_len) {
    struct icmpHeader *icmp = (struct icmpHeader *)(packet_data + sizeof(struct ethHeader) + ip_header_len);
    char icmp_type[10];
    getICMPType(icmp->icmp_type, icmp_type);
    printICMPHeader(icmp_type);
}

// Get UDP info and print them
void processUDP(const u_char *packet_data, unsigned int ip_header_len){
    struct udpHeader *udp = (struct udpHeader *)(packet_data + sizeof(struct ethHeader) + ip_header_len);
    char source_port[10];
    char destination_port[10];
    getPortNumber(ntohs(udp->source_port), source_port);
    getPortNumber(ntohs(udp->destination_port), destination_port);
    printUDPHeader(source_port, destination_port);
}

// Get TCP info and print them
void processTCP(const u_char *packet_data, unsigned int ip_header_len, struct ipHeader *ip) {
    struct tcpHeader *tcp = (struct tcpHeader *)(packet_data + sizeof(struct ethHeader) + ip_header_len);
    char source_port[10];
    char destination_port[10];
    getPortNumber(ntohs(tcp->source_port), source_port);
    getPortNumber(ntohs(tcp->destination_port), destination_port);
    unsigned int sequence_number = ntohl(tcp->sequence_number);
    unsigned int acknowledge_number = ntohl(tcp->acknowledge_number);
    int sync_flag = tcp->sync_flag;
    int reset_flag = tcp->reset_flag;
    int finish_flag = tcp->finish_flag;
    int ack_flag = tcp->ack_flag;
    int window_size = ntohs(tcp->window_size);
    int data_offset = tcp->offset * 4; // multiply by 4 for bytes
    int checksum = ntohs(tcp->checksum); 
    char checkSumResult[10];
    TCPChecksum(ip, tcp, packet_data, ip_header_len, checkSumResult); // get the checksum result
    printTCPHeader(source_port, destination_port, sequence_number, acknowledge_number, sync_flag, reset_flag, finish_flag, ack_flag, window_size, data_offset, checksum, checkSumResult);
}

// Controller to process based on protocol type
void processProtocol(char * protocol, const u_char *packet_data, unsigned int ip_header_len, struct ipHeader *ip) {
    if (strcmp(protocol, "ICMP") == 0) {
        processICMP(packet_data, ip_header_len);
    }
    else if (strcmp(protocol, "UDP") == 0){
        processUDP(packet_data, ip_header_len);
    }
    else if (strcmp(protocol, "TCP") == 0){
        processTCP(packet_data, ip_header_len, ip);
    }
}

// Get IP info and print them, then process the protocol
void processIP(const u_char *packet_data, struct ethHeader *ethernet){
        struct ipHeader *ip = (struct ipHeader *)(packet_data + sizeof(struct ethHeader));
        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = ip->source;
        dst_ip.s_addr = ip->destination;
        unsigned int ip_header_len = ip->ip_header_len * 4;
        char ip_protocol[10];
        char checkSumResult[15];
        getIPProtocol(ip->protocol, ip_protocol);
        IPCheckSum(packet_data, ethernet, ip_header_len, checkSumResult);
        printIPHeader(ip, ip_header_len, ip_protocol, src_ip, dst_ip, checkSumResult);
        processProtocol(ip_protocol, packet_data, ip_header_len, ip);
}

// Get ARP info and print them
void processARP(const u_char *packet_data, struct ethHeader *ethernet) {
    struct arpHeader *arp = (struct arpHeader *)(packet_data + sizeof(struct ethHeader));
    struct in_addr ip_source;
    struct in_addr ip_destination;
    u_char sm[MAC_SIZE];
    u_char tm[MAC_SIZE];
    memcpy(&ip_source.s_addr, arp->ip_source, IP_SIZE);   
    memcpy(&ip_destination.s_addr, arp->ip_destination, IP_SIZE);
    memcpy(&sm, arp->mac_source, MAC_SIZE);
    memcpy(&tm, arp->mac_destination, MAC_SIZE);
    char opCode[10];

    getARPOpCode(arp->opcode, opCode);
    printARPHeader(opCode, ip_source, ip_destination, sm, tm);
}

// Controller based on ARP or IP
void processType(char *type, const u_char *packet_data, struct ethHeader *ethernet) {
    if (strcmp(type, "ARP") == 0){
        processARP(packet_data, ethernet);
    }
    else {
        processIP(packet_data, ethernet);
    }

}

// Process a packet by getting Ethernet header and prinnt it, then process the ethernet type
void processPacket(struct pcap_pkthdr *packet_header,  const u_char *packet_data, int count) {
    int length = packet_header -> len;
    struct ethHeader *ethernet = (struct ethHeader *)packet_data;
    unsigned char *dest = ethernet->destination;
    unsigned char *src = ethernet->source;
    char ethernet_type[5];

    getEthernetType(ntohs(ethernet->type), ethernet_type);
    printEthernetHeader(count, length, dest, src, ethernet_type);
    processType(ethernet_type, packet_data, ethernet);
}


// Main function that loops through all packets until EOF
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
    return EXIT_SUCCESS;
}
