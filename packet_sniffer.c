#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>

#define MAX_PACKET_SIZE 65535

// Define the honey pot IP address to detect interactions
char *honey_pot_ip = "192.168.1.100"; // Replace with your honey pot's IP

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;

    // Assuming Ethernet frames, skip past Ethernet header to IP header
    ip_header = (struct ip *)(packet + 14);

    // Check if IP packet's destination matches the honey pot IP
    if (ip_header->ip_dst.s_addr == inet_addr(honey_pot_ip)) {
        printf("Detected interaction with honey pot: %s --> %s\n", 
               inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;

    // Open network device for packet capture
    handle = pcap_open_live("eth0", MAX_PACKET_SIZE, 1, 1000, errbuf); // Replace "eth0" with your interface

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return 1;
    }

    // Set filter to capture only IP packets
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", "ip", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", "ip", pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
