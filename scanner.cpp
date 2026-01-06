#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <map>
#include <set>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

struct ScanInfo {
    int ports_touched = 0;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    int total_packets = 0;
    bool is_scanner = false;
};

class TrafficScanner {
private:
    std::atomic<bool> running;
    std::map<std::string, ScanInfo> ip_scan_stats;
    std::map<std::string, std::set<int>> ip_ports;
    
    // TCP client for AI communication
    int ai_client_socket;
    struct sockaddr_in ai_server_addr;
    
    // Honeypot deployment command
    int honeypot_socket;
    struct sockaddr_in honeypot_server;
    
public:
    TrafficScanner() : running(false), ai_client_socket(-1), honeypot_socket(-1) {
        // Setup AI server connection
        ai_server_addr.sin_family = AF_INET;
        ai_server_addr.sin_port = htons(8080);
        inet_pton(AF_INET, "127.0.0.1", &ai_server_addr.sin_addr);
        
        // Setup honeypot command connection
        honeypot_server.sin_family = AF_INET;
        honeypot_server.sin_port = htons(8082);
        inet_pton(AF_INET, "127.0.0.1", &honeypot_server.sin_addr);
    }
    
    void packet_handler(const u_char* packet, uint32_t packet_len) {
        if (!running || packet_len < 14) return;
        
        // Skip Ethernet header
        const struct ip* ip_header = (struct ip*)(packet + 14);
        if (ip_header->ip_v != 4) return;
        
        // Extract IP and port info
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);
        
        std::string src_ip_str(src_ip);
        
        // Update scan detection
        auto& scan_info = ip_scan_stats[src_ip_str];
        scan_info.total_packets++;
        scan_info.last_seen = std::chrono::steady_clock::now();
        
        if (scan_info.first_seen == std::chrono::steady_clock::time_point{}) {
            scan_info.first_seen = scan_info.last_seen;
        }
        
        // Check if it's a scan (multiple ports)
        if (ip_header->ip_p == IPPROTO_TCP) {
            uint32_t ip_header_len = ip_header->ip_hl * 4;
            if (packet_len >= 14 + ip_header_len + sizeof(struct tcphdr)) {
                const struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + ip_header_len);
                uint16_t dst_port = ntohs(tcp_header->th_dport);
                
                // Track unique ports touched
                ip_ports[src_ip_str].insert(dst_port);
                scan_info.ports_touched = ip_ports[src_ip_str].size();
            }
        }
        
        // Detect if it's scanning behavior
        auto now = std::chrono::steady_clock::now();
        auto time_window = std::chrono::duration_cast<std::chrono::seconds>(now - scan_info.first_seen).count();
        
        // Scanner detection: touches many ports quickly
        scan_info.is_scanner = (scan_info.ports_touched > 5 && time_window < 60);
        
        // Send to AI if scanner detected
        if (scan_info.is_scanner && scan_info.total_packets % 10 == 0) {
            send_to_ai(src_ip_str, scan_info);
        }
        
        // Print scan detection
        if (scan_info.is_scanner) {
            std::cout << "🚨 SCANNER DETECTED: " << src_ip_str 
                     << " | Ports: " << scan_info.ports_touched 
                     << " | Packets: " << scan_info.total_packets << std::endl;
            
            // DEPLOY HONEYPOT IMMEDIATELY
            deploy_honeypot(src_ip_str);
        }
    }
    
    void deploy_honeypot(const std::string& scanner_ip) {
        if (honeypot_socket < 0) {
            honeypot_socket = socket(AF_INET, SOCK_STREAM, 0);
            if (honeypot_socket >= 0) {
                if (connect(honeypot_socket, (struct sockaddr*)&honeypot_server, sizeof(honeypot_server)) >= 0) {
                    std::cout << "🍯 CONNECTED TO HONEYPOT MANAGER" << std::endl;
                } else {
                    close(honeypot_socket);
                    honeypot_socket = -1;
                    return;
                }
            } else {
                honeypot_socket = -1;
                return;
            }
        }
        
        // Send deployment command
        std::string deploy_cmd = "deploy " + scanner_ip;
        send(honeypot_socket, deploy_cmd.c_str(), deploy_cmd.length(), 0);
    }
    
    void send_to_ai(const std::string& src_ip, const ScanInfo& scan_info) {
        if (ai_client_socket < 0) {
            connect_to_ai();
        }
        
        if (ai_client_socket < 0) return;
        
        // Create JSON message
        std::string json_data = "{";
        json_data += "\"src_ip\":\"" + src_ip + "\",";
        json_data += "\"ports_touched\":" + std::to_string(scan_info.ports_touched) + ",";
        json_data += "\"total_packets\":" + std::to_string(scan_info.total_packets) + ",";
        json_data += "\"is_scanner\":" + std::string(scan_info.is_scanner ? "true" : "false") + ",";
        json_data += "\"timestamp\":" + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + "";
        json_data += "}";
        
        // Send to AI server
        uint32_t msg_len = htonl(json_data.length());
        send(ai_client_socket, &msg_len, sizeof(msg_len), 0);
        send(ai_client_socket, json_data.c_str(), json_data.length(), 0);
    }
    
    void connect_to_ai() {
        ai_client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (ai_client_socket >= 0) {
            if (connect(ai_client_socket, (struct sockaddr*)&ai_server_addr, sizeof(ai_server_addr)) >= 0) {
                std::cout << "🤖 Connected to AI Server" << std::endl;
            } else {
                close(ai_client_socket);
                ai_client_socket = -1;
            }
        }
    }
    
    static void static_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        TrafficScanner* scanner = reinterpret_cast<TrafficScanner*>(args);
        scanner->packet_handler(packet, header->len);
    }
    
    void start() {
        running = true;
        
        std::cout << "🚀 Starting Traffic Scanner..." << std::endl;
        std::cout << "📡 Monitoring for port scans and nmap activity..." << std::endl;
        std::cout << "🍯 Will deploy honeypots IMMEDIATELY on scan detection!" << std::endl;
        
        // Connect to AI server
        connect_to_ai();
        
        // Start packet capture
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
        
        if (handle == nullptr) {
            std::cerr << "❌ Error opening interface: " << errbuf << std::endl;
            return;
        }
        
        std::cout << "🔍 Capturing on interface: lo" << std::endl;
        std::cout << "🤖 Sending scan data to AI on port 8080" << std::endl;
        std::cout << "🍯 Deploying honeypots on port 8082 when scans detected" << std::endl;
        std::cout << "Press Ctrl+C to stop..." << std::endl;
        
        // Start capture loop
        pcap_loop(handle, 0, static_packet_handler, reinterpret_cast<u_char*>(this));
        
        pcap_close(handle);
    }
    
    void stop() {
        running = false;
        if (ai_client_socket >= 0) {
            close(ai_client_socket);
        }
        if (honeypot_socket >= 0) {
            close(honeypot_socket);
        }
    }
    
    void print_scan_summary() {
        std::cout << "\n📊 SCAN SUMMARY:" << std::endl;
        std::cout << "Total unique IPs monitored: " << ip_scan_stats.size() << std::endl;
        
        int scanner_count = 0;
        for (const auto& [ip, scan_info] : ip_scan_stats) {
            if (scan_info.is_scanner) {
                scanner_count++;
                std::cout << "🚨 SCANNER: " << ip << " (ports: " << scan_info.ports_touched << ")" << std::endl;
            }
        }
        
        std::cout << "Total scanners detected: " << scanner_count << std::endl;
    }
};

int main(int argc, char* argv[]) {
    std::string interface = "lo";
    
    if (argc > 1) {
        interface = argv[1];
    }
    
    TrafficScanner scanner;
    
    try {
        scanner.start();
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
    }
    
    return 0;
}