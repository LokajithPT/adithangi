#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <csignal>
#include <atomic>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

std::atomic<bool> running(true);

std::string sanitize(const std::string& input) {
    std::string output;
    for (unsigned char c : input) {
        if (std::isprint(c)) {
            output += c;
        } else {
            // Replace non-printable characters with a hex representation or a placeholder
            output += "\\x";
            std::ostringstream oss;
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
            output += oss.str();
        }
    }
    return output;
}

void logConnection(const std::string& service, const std::string& clientIP, const std::string& message) {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    
    std::ostringstream oss;
    oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
        << service << " - " << clientIP << " - " << message << std::endl;
    
    std::cout << oss.str();
    
    std::ofstream logfile("honeypot.log", std::ios::app);
    if (logfile) {
        logfile << oss.str();
    }
}

void handleSSHConnection(int clientSocket, const std::string& clientIP) {
    logConnection("SSH", clientIP, "Connection established");
    
    // TROLL: Ancient SSH version (Protocol 1.5)
    // This makes modern clients disconnect cleanly ("Protocol major versions differ") 
    // instead of crashing with crypto errors, while nmap sees a huge vulnerability.
    const char* sshBanner = "SSH-1.5-OpenSSH_1.2.3\r\n";
    size_t bannerLen = strlen(sshBanner);
    ssize_t totalSent = 0;
    
    // Ensure the entire banner is sent
    while (totalSent < bannerLen) {
        ssize_t sent = send(clientSocket, sshBanner + totalSent, bannerLen - totalSent, 0);
        if (sent < 0) {
            if (errno == EINTR) continue; // Interrupted system call, retry
            logConnection("SSH", clientIP, "Error sending banner: " + std::string(strerror(errno)));
            close(clientSocket);
            return;
        }
        totalSent += sent;
    }
    
    // Immediately close after sending banner.
    // This ensures the client only sees the old banner and then gets disconnected,
    // avoiding complex SSH handshake failures and simply showing a 'very old server'.
    logConnection("SSH", clientIP, "Banner sent, closing connection.");
    close(clientSocket);
}

void handleFTPConnection(int clientSocket, const std::string& clientIP) {
    logConnection("FTP", clientIP, "Connection established");
    
    // TROLL: The legendary backdoor version
    const char* ftpWelcome = "220 (vsFTPd 2.3.4 - BACKDOOR_ENABLED)\r\n";
    send(clientSocket, ftpWelcome, strlen(ftpWelcome), 0);
    
    char buffer[1024];
    ssize_t bytesRead;
    
    while ((bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        std::string command(buffer);
        
        // Clean up command for processing
        size_t endPos = command.find_first_of("\r\n");
        std::string cleanCommand = (endPos != std::string::npos) ? command.substr(0, endPos) : command;
        
        logConnection("FTP", clientIP, "Command: " + sanitize(cleanCommand));
        
        if (cleanCommand.empty()) continue;

        if (cleanCommand.substr(0, 4) == "USER") {
            const char* userOk = "331 Please specify the password.\r\n";
            send(clientSocket, userOk, strlen(userOk), 0);
        }
        else if (cleanCommand.substr(0, 4) == "PASS") {
            // TROLL: Make it look like it's thinking, then fail? 
            // Or just fail immediately to simulate the 2.3.4 backdoor check (which was triggered by :) in USER usually)
            logConnection("FTP", clientIP, "Password attempt detected");
            const char* loginFailed = "530 Login incorrect.\r\n";
            send(clientSocket, loginFailed, strlen(loginFailed), 0);
        }
        else if (cleanCommand.find(":)") != std::string::npos) {
             // TROLL: React to the backdoor smiley
             logConnection("FTP", clientIP, "BACKDOOR TRIGGERED! (JK)");
             const char* fakeShell = "uid=0(root) gid=0(root) groups=0(root)\r\n";
             send(clientSocket, fakeShell, strlen(fakeShell), 0);
        }
        else if (cleanCommand.substr(0, 4) == "QUIT") {
            const char* goodbye = "221 Goodbye.\r\n";
            send(clientSocket, goodbye, strlen(goodbye), 0);
            break;
        }
        else if (cleanCommand.substr(0, 3) == "SYST") {
            const char* system = "215 UNIX Type: L8\r\n";
            send(clientSocket, system, strlen(system), 0);
        }
        else {
            const char* notFound = "500 Unknown command.\r\n";
            send(clientSocket, notFound, strlen(notFound), 0);
        }
    }
    
    logConnection("FTP", clientIP, "Connection closed");
    close(clientSocket);
}

void handleHTTPTarpit(int clientSocket, const std::string& clientIP) {
    logConnection("HTTP-TARPIT", clientIP, "Connection established - TRAP ACTIVATED");
    
    // 1. Send a standard header to lure them in
    const char* fakeHeader = "HTTP/1.1 200 OK\r\n"
                             "Server: Apache/2.4.49 (Unix)\r\n"
                             "Content-Type: text/html\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n";
    send(clientSocket, fakeHeader, strlen(fakeHeader), 0);
    
    // 2. Infinite Loop of Garbage
    const char* garbage = "4\r\n" "LOLO\r\n"; // Chunked encoding format
    
    while (true) {
        ssize_t sent = send(clientSocket, garbage, strlen(garbage), 0);
        if (sent <= 0) break; // Client gave up or disconnected
    }
    
    logConnection("HTTP-TARPIT", clientIP, "Victim disconnected (Trap Success)");
    close(clientSocket);
}

void startService(int port, const std::string& serviceName, void (*handler)(int, const std::string&)) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error creating socket for " << serviceName << std::endl;
        return;
    }
    
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding " << serviceName << " to port " << port << std::endl;
        close(serverSocket);
        return;
    }
    
    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Error listening on " << serviceName << " port " << port << std::endl;
        close(serverSocket);
        return;
    }
    
    std::cout << serviceName << " honeypot listening on port " << port << std::endl;
    
    while (running) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            continue; 
        }
        
        std::string clientIP = inet_ntoa(clientAddr.sin_addr);
        std::thread clientThread(handler, clientSocket, clientIP);
        clientThread.detach();
    }
    
    close(serverSocket);
}

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        running = false;
        std::cout << "\nShutting down honeypot..." << std::endl;
        exit(0); // Force exit to break accept loops
    }
}

int main() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    std::cout << "Starting 'Exploitable' Honeypot Services..." << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    std::thread sshThread(startService, 22, "SSH", handleSSHConnection);
    std::thread ftpThread(startService, 21, "FTP", handleFTPConnection);
    std::thread httpThread(startService, 80, "HTTP-TARPIT", handleHTTPTarpit);
    
    sshThread.join();
    ftpThread.join();
    httpThread.join();
    
    return 0;
}
