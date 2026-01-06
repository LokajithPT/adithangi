# 🎮 ADITHANGI - Traffic Diversion Game System

A complete network defense system that detects port scans and attackers, then deploys fake SSH and FTP honeypots to trap them. The system sends scan data to an AI predictor and displays game-style alerts when threats are detected.

## 🚀 System Architecture

```
Network Traffic → C++ Scanner → AI Predictor → Game Display → Honeypot Deployment
                   ↓              ↓              ↓                ↓
               Port Scan     →   ML Analysis   →  Game Alerts   →  Fake Services
```

## 🎯 Components

### **1. C++ Traffic Scanner** (`scanner.cpp`)
- **Real-time packet capture** using libpcap
- **Port scan detection** - tracks multiple port access from same IP
- **Network communication** - sends scan data to AI server
- **Fast scan detection** - identifies nmap and masscan patterns

### **2. AI Prediction Server** (`ai_server.py`)
- **ML classification** - predicts scan type and attacker intent
- **Threat assessment** - confidence levels and malicious detection
- **Game integration** - sends responses back to game client

### **3. Game Client** (`game_client.cpp`)
- **Real-time alerts** - displays AI predictions with game interface
- **Defense simulation** - shows counter-measures activation
- **Threat visualization** - color-coded alerts and status displays

### **4. Honeypot Services** (`fake_services.py`)
- **Fake SSH server** - weak credentials, fake shell, command logging
- **Fake FTP server** - anonymous access, fake files, directory listing
- **Attack logging** - comprehensive JSON logging of all attacker actions

## 🛠️ Building & Running

### **Quick Start:**
```bash
# Clone and build
cd /home/skedaddle/code/hah
./start_adithangi.sh

# This will:
# - Build all C++ components
# - Start AI prediction server (port 8080)
# - Start game client (port 8081)  
# - Start traffic scanner
# - Launch honeypot services when scanners detected
```

### **Manual Testing:**
```bash
# Build C++ components
mkdir build && cd build
cmake .. && make

# Start AI server
python3 ai_server.py &

# Start game client  
./game_client &

# Start scanner
./scanner [interface]

# Start honeypots (optional)
python3 fake_services.py &
```

## 🎮 Game Features

### **Scan Detection:**
- **Port scan patterns**: Multiple ports hit quickly
- **Aggressive scanning**: High packet rates
- **Targeted scans**: Specific service probing
- **Automated tools**: Bot-like behavior

### **AI Predictions:**
- **Scan types**: MASS_PORT_SCAN, AGGRESSIVE_SCAN, NETWORK_DISCOVERY
- **Attacker intent**: HACKTOOL_AUTOMATED, RECONNAISSANCE, TARGETED_ATTACK
- **Threat levels**: HIGH, MEDIUM, LOW
- **Confidence scores**: 0.0 - 1.0 probability

### **Game Alerts:**
- **Visual indicators**: 🚨, ⚠️, 🔍 for different threat levels
- **Counter-measure simulation**: Firewall hardening, decoy deployment
- **Real-time feedback**: Immediate game response to threats

## 🍯 Honeypot Features

### **SSH Honeypot (Port 22):**
- **Weak banners**: Vulnerable OpenSSH versions
- **Default credentials**: admin/admin, root/123456, user/password
- **Fake shell**: Command execution with fake responses
- **Command logging**: All attacker commands saved to JSON

### **FTP Honeypot (Port 21):**
- **Anonymous access**: Always grants anonymous login
- **Fake files**: backup.zip, secrets.tar.gz, passwords.txt
- **Directory listing**: Simulated vulnerable file structure
- **File access tracking**: Every file access logged

### **Attack Intelligence:**
- **JSON logging**: Timestamp, IP, service, commands, credentials
- **Pattern analysis**: Tracks attacker techniques and tools
- **Forensic data**: Complete attacker behavior history

## 📊 Detection Examples

### **Port Scan Detection:**
```
🚨 SCANNER DETECTED: 192.168.1.100 | Ports: 22 | Packets: 15
🧠 AI PREDICTION:
   🎯 Source IP: 192.168.1.100
   📊 Scan Type: MASS_PORT_SCAN
   🎭 Intent: HACKTOOL_AUTOMATED
   🔥 Confidence: 0.95
   ⚠️ Threat Level: HIGH
   🚨 Malicious: YES
   🎮 Game Response: ⚔️ COUNTER-SCAN: Launching port scan probe against 192.168.1.100...
```

### **Honeypot Interaction:**
```
🔐 SSH LOGIN ATTEMPT: 192.168.1.100 - root:admin
🚨 FAKE SHELL OPENED: 192.168.1.100 compromised with admin
💻 FAKE COMMAND: 192.168.1.100 executed: ls -la
📂 FAKE FILE ACCESSED: 192.168.1.100 - secrets.tar.gz
```

## 🎯 Use Cases

### **1. Red Team Testing:**
- Deploy honeypots to simulate vulnerabilities
- Test security tools and detection capabilities
- Practice incident response procedures

### **2. Research & Education:**
- Study real attacker techniques and tools
- Collect malware samples and command patterns
- Develop better detection signatures

### **3. Network Defense:**
- Early warning system for port scanning
- Automatic deployment of defensive measures
- Intelligence gathering on attacker capabilities

## ⚙️ Configuration

### **Network Settings:**
- **Scanner interface**: Configurable (default: lo)
- **AI server port**: 8080 (scan data → predictions)
- **Game client port**: 8081 (predictions → display)
- **Honeypot ports**: SSH (22), FTP (21)

### **Detection Thresholds:**
- **Port scan detection**: >5 ports in 60 seconds
- **High confidence**: >0.7 threat level
- **Malicious auto-trigger**: For HIGH threats

## 🔧 Technical Details

### **Data Flow:**
1. **Scanner** captures packets → extracts scan patterns
2. **AI Server** receives scan data → runs ML prediction  
3. **Game Client** gets predictions → displays game alerts
4. **Honeypots** deploy automatically when HIGH threats detected

### **Performance:**
- **Real-time**: Sub-second detection and response
- **Low overhead**: Efficient packet processing
- **Scalable**: Multiple concurrent honeypot connections
- **Persistent**: All data saved to JSON for analysis

## 🏆 What Makes This Special

- **Complete Pipeline**: Detection → Analysis → Response → Deception
- **Game Interface**: Makes security monitoring engaging and educational
- **Real-world Attackers**: Actually attracts and studies malicious actors
- **Research Value**: Collects real attack patterns and techniques
- **Educational**: Learn cybersecurity through practical experience

## 🚀 Get Started

```bash
# Clone the repository
git clone https://github.com/LokajithPT/adithangi.git
cd adithangi

# Run the complete system
./start_adithangi.sh

# Try triggering a detection
nmap -sS localhost
```

**🎮 ADITHANGI - Turn network defense into a game!**

---

**Warning**: For educational and research purposes only. Use only on networks you have permission to monitor.