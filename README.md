# HAH-IDS: Honeypot & AI Heuristic Intrusion Detection System

## Project Description
HAH-IDS is a multi-component network security project designed to act as a deterrent and detection system for network intrusions. It features a customizable honeypot to lure attackers, a network sniffer to monitor traffic, an AI-driven intrusion detection system (Kitsune-inspired) to identify anomalies, and a real-time dashboard for visualization. It also includes active counter-measures like firewall blocking and an HTTP tarpit.

## Features

### 1. **Honeypot (honeypot.cpp)**
*   **Decoy Services:** Simulates vulnerable FTP (vsFTPd 2.3.4) and SSH (OpenSSH 1.2.3, Protocol 1.5) services on standard ports (21 and 22).
*   **Trolling:** Presents highly exploitable banners to confuse and delay attackers.
*   **FTP Backdoor:** Responds with a fake root shell for the infamous `:)` exploit.
*   **SSH Disconnect:** Cleanly disconnects modern SSH clients after presenting the old banner, indicating an outdated server.
*   **HTTP Tarpit:** Listens on Port 80 and sends an infinite stream of "LOLO" data to connected clients, effectively hanging their scanning tools.

### 2. **Network Sniffer (sniffer.cpp)**
*   **Packet Capture:** Uses raw sockets to capture all IP traffic on a specified Wi-Fi interface (`wlo1`).
*   **Metadata Forwarding:** Extracts essential packet metadata (timestamp, source IP, destination IP, packet size) and forwards it to the Kitsune IDS via UDP (localhost:9999).
*   **Loop Prevention:** Ignores self-generated UDP packets to prevent infinite loops.

### 3. **Kitsune-Lite IDS (kitsune.py)**
*   **AI-Driven Anomaly Detection:** Implements a simplified Kitsune-inspired autoencoder using NumPy.
*   **Online Learning:** Learns "normal" network traffic patterns during an initial training phase (first 50 packets).
*   **Feature Extraction:** Monitors packet rates and sizes to detect statistical anomalies.
*   **Real-time Alerts:** Prints alerts to the console and logs malicious events to `ids_events.json`.
*   **Active Counter-Measure (Shadow Realm):** When an anomaly is detected, it executes `iptables` NAT rules to **REDIRECT** the attacker's TCP traffic to the local **Shadow Realm** (Port 6666), effectively hijacking their connection.

### 4. **The Shadow Realm (shadow_realm.py)**
*   **TCP Trap:** A Python script listening on Port 6666.
*   **Psychological Warfare:** Simulates a laggy, broken root shell. It accepts commands but responds with typos, artificial delays, and creepy messages ("I see you...", "There is no escape").
*   **Infinite Waste:** Keeps the attacker occupied in a fake environment while their real attacks are neutralized.

### 5. **Web Dashboard (dashboard.html & dashboard_server.py)**
*   **Live Monitoring:** A "hacker-style" web interface to visualize real-time threat alerts.
*   **Event Log:** Displays detected anomalies, including timestamp, source/destination IPs, anomaly score, status, and action taken.
*   **Auto-refresh:** Automatically updates every 2 seconds by fetching data from `ids_events.json`.

## Setup Instructions

### Prerequisites
*   `g++`: C++ compiler.
*   `make`: Build tool.
*   `python3`: Python interpreter.
*   `pip`: Python package installer.
*   `numpy`: Python library for numerical operations.
*   `sudo`: For running network-privileged components.
*   `iptables`: Linux firewall utility.

### Installation
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/LokajithPT/adithangi.git
    cd adithangi
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install numpy
    ```
3.  **Compile C++ components:**
    ```bash
    make
    ```

## How to Run (Multi-Terminal Setup)

You will need **4 separate terminal windows/tabs** to run all components simultaneously.

### Terminal 1: Kitsune IDS (The Brain)
```bash
python3 kitsune.py
```
*   *(This will start listening for packet metadata and will enter a training phase for the first 50 packets.)*

### Terminal 2: Dashboard Server (The Face)
```bash
python3 dashboard_server.py
```
*   *Open your web browser and navigate to `http://localhost:8000` to view the live dashboard.*

### Terminal 3: Honeypot (The Trap)
```bash
sudo ./honeypot
```
*   *(This will start listening on ports 21 (FTP), 22 (SSH), and 80 (HTTP Tarpit).)*

### Terminal 4: Network Sniffer (The Eyes)
```bash
sudo ./sniffer
```
*   *(This will start capturing all IP traffic on your `wlo1` Wi-Fi interface and feed it to the Kitsune IDS.)*

### Terminal 5: The Shadow Realm (The Void)
```bash
python3 shadow_realm.py
```
*   *(This starts the trap server on Port 6666. Any banned IP will be silently redirected here.)*

## How to Test

1.  **Generate Normal Traffic:** While all components are running, perform normal activities like browsing, `ping google.com`, etc. Observe the `kitsune.py` terminal; you should see `[DEBUG] Packet In:` messages.
2.  **Trigger a Scan (Attack):** From a *different machine* on your network, or from your local machine, run an `nmap` scan targeting your machine's IP address (e.g., `nmap -T4 -A -p- <your_ip>`).
3.  **Observe Detection & Reaction:**
    *   In the `kitsune.py` terminal, you should see `[ALERT] Anomaly detected...` messages, along with `[FIREWALL] BLOCKING ...` if the IP is not whitelisted.
    *   The web dashboard at `http://localhost:8000` should start flashing red rows indicating malicious activity.
    *   If you attempt to access Port 80 (e.g., `curl http://<your_ip>`) from the attacking machine, it will get stuck in the HTTP Tarpit.

## Future Enhancements
*   **GeoIP Lookup:** Display geographic location of attacker IPs on the dashboard.
*   **Persistent Blocking:** Save `iptables` rules across reboots.
*   **More Advanced Kitsune:** Implement full Kitsune features (AfterImage, ensemble of autoencoders, more diverse features).
*   **Protocol Parsing:** Deeper packet inspection beyond IP headers (e.g., TCP flags, HTTP requests).
*   **Alert Notifications:** Integrate with Discord, Telegram, or email for instant alerts.
*   **Configuration File:** Externalize ports, interface names, and IDS thresholds.
