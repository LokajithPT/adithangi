#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <chrono>
#include <sstream>

#define BUFFER_SIZE 65536
#define DEST_IP "127.0.0.1"
#define DEST_PORT 9999

int main() {
    int raw_sock;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    // Create raw socket to sniff all traffic
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("Socket Error");
        return 1;
    }

    // Bind to specific interface (wlo1) to ensure we get the right traffic
    const char *opt = "wlo1";
    if (setsockopt(raw_sock, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt)) < 0) {
        perror("Bind to device error (are you root?)");
        return 1;
    }

    // Create UDP socket for sending data to Python
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in py_addr;
    memset(&py_addr, 0, sizeof(py_addr));
    py_addr.sin_family = AF_INET;
    py_addr.sin_port = htons(DEST_PORT);
    py_addr.sin_addr.s_addr = inet_addr(DEST_IP);

    std::cout << "[*] Sniffer started. Forwarding metadata to " << DEST_IP << ":" << DEST_PORT << "..." << std::endl;

    long packet_counter = 0;

    while (true) {
        socklen_t saddr_size = sizeof(saddr);
        ssize_t data_size = recvfrom(raw_sock, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        
        if (data_size < 0) {
            perror("Recvfrom Error");
            return 1;
        }

        // Parse Ethernet Header
        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Only interested in IP packets (0x0800)
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            
            struct sockaddr_in source, dest;
            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = ip->saddr;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = ip->daddr;

            std::string src_ip_str = inet_ntoa(source.sin_addr);
            std::string dst_ip_str = inet_ntoa(dest.sin_addr);

            // Infinite Loop Prevention:
            // If the packet is destined for our Python script (localhost:9999 UDP), ignore it.
            // (We check protocol UDP=17 and dest IP loopback)
            if (ip->protocol == 17 && dst_ip_str == "127.0.0.1") {
                 // To be safer, we'd check the UDP header for port 9999, but this is a decent heuristic
                 // Let's actually check the port to be sure.
                 unsigned short iphdrlen = ip->ihl * 4;
                 struct udphdr {
                     u_short uh_sport;
                     u_short uh_dport;
                     short uh_ulen;
                     short uh_sum;
                 };
                 struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
                 if (ntohs(udph->uh_dport) == DEST_PORT) {
                     continue; 
                 }
            }

            // Prepare CSV string: "timestamp,src,dst,size"
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::duration<double>>(now.time_since_epoch()).count();
            
            std::stringstream ss;
            ss << timestamp << "," << src_ip_str << "," << dst_ip_str << "," << data_size;
            std::string msg = ss.str();

            // Send to Python
            sendto(udp_sock, msg.c_str(), msg.length(), 0, (struct sockaddr*)&py_addr, sizeof(py_addr));
            
            packet_counter++;
            if (packet_counter % 10 == 0) {
                std::cout << "[*] Sniffer forwarded " << packet_counter << " packets." << std::endl;
            }
        }
    }

    close(raw_sock);
    close(udp_sock);
    free(buffer);
    return 0;
}
