#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#define IP_HL(ip)                (((ip)->ip_vhl) & 0x0f)
#define ETH_HARDWARE_TYPE 0x01
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

void print_packet_info(const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_ethernet_header(const u_char *packet);
void print_ip_header(const u_char *packet);
void print_tcp_header(const u_char *packet);
void print_udp_header(const u_char *packet);
void print_icmp_header(const u_char *packet);
void print_arp_header(const u_char *packet);
void analyze_packet(const u_char *packet, const struct pcap_pkthdr *pkthdr);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening file: %s\n", errbuf);
        return 1;
    }

    printf("Starting packet analysis...\n");
    pcap_loop(handle, 0, analyze_packet, NULL);

    pcap_close(handle);
    return 0;
}

void analyze_packet(const u_char *packet, const struct pcap_pkthdr *pkthdr) {
    printf("Packet Length: %d bytes\n", pkthdr->len);
    print_packet_info(pkthdr, packet);
}

void print_packet_info(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("\n--- Packet Info ---\n");
    printf("Captured at: %s.%06d\n", ctime((const time_t *)&pkthdr->ts.tv_sec), pkthdr->ts.tv_usec);
    print_ethernet_header(packet);
    print_ip_header(packet);
    print_tcp_header(packet);
    print_udp_header(packet);
    print_icmp_header(packet);
    print_arp_header(packet);
}

void print_ethernet_header(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    printf("\n== Ethernet Header ==\n");
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    printf("Ethernet Type: %04x\n", ntohs(eth_header->ether_type));
}

void print_ip_header(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet Header (14 bytes)
    printf("\n== IP Header ==\n");
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    printf("IP Version: %d\n", (ip_header->ip_vhl) >> 4);
    printf("Header Length: %d bytes\n", IP_HL(ip_header) * 4);
    printf("Protocol: %d\n", ip_header->ip_p);

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            print_tcp_header(packet);
            break;
        case IPPROTO_UDP:
            print_udp_header(packet);
            break;
        case IPPROTO_ICMP:
            print_icmp_header(packet);
            break;
        case IPPROTO_ICMPV6:
            print_icmp_header(packet);
            break;
        case IPPROTO_ARP:
            print_arp_header(packet);
            break;
        default:
            printf("Unknown Protocol\n");
    }
}

void print_tcp_header(const u_char *packet) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (IP_HL((struct ip *)(packet + 14)) * 4));
    printf("\n== TCP Header ==\n");
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
    printf("Flags: %x\n", tcp_header->th_flags);
    printf("Window Size: %d\n", ntohs(tcp_header->th_win));
    printf("Checksum: %d\n", ntohs(tcp_header->th_sum));
    printf("Urgent Pointer: %d\n", ntohs(tcp_header->th_urp));
}

void print_udp_header(const u_char *packet) {
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (IP_HL((struct ip *)(packet + 14)) * 4));
    printf("\n== UDP Header ==\n");
    printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    printf("UDP Length: %d\n", ntohs(udp_header->uh_ulen));
    printf("Checksum: %d\n", ntohs(udp_header->uh_sum));
}

void print_icmp_header(const u_char *packet) {
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + (IP_HL((struct ip *)(packet + 14)) * 4));
    printf("\n== ICMP Header ==\n");
    printf("Type: %d\n", icmp_header->icmp_type);
    printf("Code: %d\n", icmp_header->icmp_code);
    printf("Checksum: %d\n", ntohs(icmp_header->icmp_checksum));
    printf("Identifier: %d\n", ntohs(icmp_header->icmp_id));
    printf("Sequence Number: %d\n", ntohs(icmp_header->icmp_seq));
}

void print_arp_header(const u_char *packet) {
    struct ether_arp *arp_header = (struct ether_arp *)(packet + 14);
    printf("\n== ARP Header ==\n");
    printf("Hardware Type: %u\n", ntohs(arp_header->ea_hdr.ar_hrd));
    printf("Protocol Type: %04x\n", ntohs(arp_header->ea_hdr.ar_pro));
    printf("Operation: %s\n", (ntohs(arp_header->ea_hdr.ar_op) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");
    printf("Sender MAC: %s\n", ether_ntoa((struct ether_addr *)&arp_header->arp_sha));
    printf("Sender IP: %s\n", inet_ntoa(arp_header->arp_spa));
    printf("Target MAC: %s\n", ether_ntoa((struct ether_addr *)&arp_header->arp_tha));
    printf("Target IP: %s\n", inet_ntoa(arp_header->arp_tpa));
}
