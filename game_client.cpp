#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class GameClient {
private:
    std::atomic<bool> running;
    int server_socket;
    
public:
    GameClient() : running(false), server_socket(-1) {}
    
    void display_game_alert(const std::string& alert) {
        std::cout << "\n🎮 =======================================🎮" << std::endl;
        std::cout << "🚨 THREAT DETECTED!" << std::endl;
        std::cout << alert << std::endl;
        std::cout << "🎮 =======================================🎮" << std::endl;
        simulate_game_response();
    }
    
    void simulate_game_response() {
        std::cout << "\n💥 INITIATING COUNTER-MEASURES..." << std::endl;
        
        std::vector<std::string> responses = {
            "🔒 HARDENING FIREWALL RULES...",
            "⚡ DEPLOYING DECOY SERVICES...",
            "🛡️ ACTIVATING PORT KNOCKING...",
            "🔍 LAUNCHING ACTIVE PROBES...",
            "⚔️ IMPLEMENTING RATE LIMITING...",
            "🎯 TARGETING ATTACKER INFRASTRUCTURE..."
        };
        
        for (const auto& response : responses) {
            std::cout << response << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        
        std::cout << "\n✅ DEFENSE PROTOCOLS ACTIVATED!" << std::endl;
        std::cout << "🎮 GAME STATUS: DEFENSIVE MODE ENGAGED" << std::endl;
    }
    
    void listen_for_ai_responses() {
        running = true;
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(8081);
        inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
        
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            std::cerr << "❌ Failed to create socket" << std::endl;
            return;
        }
        
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "❌ Failed to bind to port 8081" << std::endl;
            return;
        }
        
        listen(server_socket, 5);
        std::cout << "🎮 Game Client listening for AI responses on port 8081..." << std::endl;
        
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_socket < 0) continue;
            
            char buffer[4096];
            int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                process_ai_response(std::string(buffer));
            }
            
            close(client_socket);
        }
    }
    
    void process_ai_response(const std::string& response) {
        if (response.find("malicious") != std::string::npos) {
            display_game_alert("🚨 MALICIOUS SCANNER DETECTED! AI confirms high threat level!");
        } else {
            std::cout << "\n🔍 MONITORING: AI reports low-level scanning activity" << std::endl;
            std::cout << "🎮 Game Status: OBSERVATION MODE" << std::endl;
        }
        
        // Extract IP for display
        size_t ip_start = response.find("src_ip");
        if (ip_start != std::string::npos) {
            size_t colon = response.find(":", ip_start);
            if (colon != std::string::npos) {
                size_t ip_end = response.find("\"", colon);
                if (ip_end != std::string::npos && ip_end > colon + 1) {
                    std::string ip = response.substr(colon + 1, ip_end - colon - 1);
                    std::cout << "🎯 Target IP: " << ip << std::endl;
                }
            }
        }
    }
    
    void show_game_intro() {
        std::cout << "\n🎮 =========================================🎮" << std::endl;
        std::cout << "🚀 ADITHANGI - NETWORK DEFENSE GAME" << std::endl;
        std::cout << "🎮 =========================================🎮" << std::endl;
        std::cout << "📡 Detecting port scans and nmap activity..." << std::endl;
        std::cout << "🧠 AI-Powered threat analysis" << std::endl;
        std::cout << "⚔️ Real-time counter-measures" << std::endl;
        std::cout << "🎯 Turn attackers into targets!" << std::endl;
        std::cout << "\nPress Ctrl+C to stop the game..." << std::endl;
        std::cout << "🎮 =========================================🎮\n" << std::endl;
    }
    
    void start() {
        show_game_intro();
        
        std::thread listener(&GameClient::listen_for_ai_responses, this);
        listener.detach();
        
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    void stop() {
        running = false;
        if (server_socket >= 0) {
            close(server_socket);
        }
    }
};

int main() {
    GameClient game;
    
    try {
        game.start();
    } catch (const std::exception& e) {
        std::cerr << "❌ Game Error: " << e.what() << std::endl;
    }
    
    return 0;
}