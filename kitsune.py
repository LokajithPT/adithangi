import socket
import numpy as np
import json
import time
import os
import subprocess
from collections import defaultdict

# --- Configuration ---
UDP_IP = "127.0.0.1"
UDP_PORT = 9999
LEARNING_RATE = 0.01
TRAIN_WINDOW = 50  # Number of packets to train on before detecting
HIDDEN_SIZE = 5     # Size of bottleneck layer
INPUT_SIZE = 3      # Number of features (Count, Rate, Size Variance)
THRESHOLD_STD = 3   # Anomaly threshold (standard deviations)

def block_ip(ip_address):
    # Whitelist checks (Don't ban yourself!)
    # if ip_address == "127.0.0.1" or ip_address.startswith("192.168."):
    #     # NOTE: For testing purposes, you might want to comment out the whitelist 
    #     # if you are testing from another machine on the LAN.
    #     print(f"[SAFEGUARD] Skipping Shadow Realm for local/LAN IP: {ip_address}")
    #     return False

    print(f"[SHADOW REALM] BANISHING {ip_address} to the void (Port 6666)...")
    try:
        # Check if already redirected
        check = subprocess.run(["sudo", "iptables", "-t", "nat", "-C", "PREROUTING", "-s", ip_address, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "6666"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if check.returncode != 0:
            # Add REDIRECT rule (NAT Table)
            # This hijacks ALL TCP traffic from the attacker and sends it to our python script
            subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip_address, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "6666"], check=True)
            print(f"[SHADOW REALM] SUCCESS: {ip_address} is now trapped.")
            return True
        else:
            print(f"[SHADOW REALM] IP {ip_address} is already trapped.")
            return True
    except Exception as e:
        print(f"[SHADOW REALM] ERROR: Could not banish IP: {e}")
        return False

# --- Kitsune Feature Extractor (Simplified) ---
class FeatureExtractor:
    def __init__(self, decay_lambda=0.1):
        self.stats = defaultdict(lambda: {'count': 0, 'weight': 0, 'mean': 0, 'sum_sq': 0, 'last_time': 0})
        self.decay_lambda = decay_lambda

    def update(self, ip_src, size, timestamp):
        # We track statistics per Source IP (Simplified Flow)
        s = self.stats[ip_src] 
        
        dt = timestamp - s['last_time']
        if s['last_time'] == 0: dt = 0
        
        # Damped window decay factor
        factor = 2 ** (-self.decay_lambda * dt)
        
        # Update incremental statistics
        s['weight'] = s['weight'] * factor + 1
        s['count'] += 1
        
        # Incremental Mean and Variance (Welford's algorithm adapted for decay)
        # Simplified for demo: Just tracking decayed rate and average size
        # Feature 1: Packet Rate (approx via weight)
        # Feature 2: Average Packet Size
        # Feature 3: Size Variance (mocked)
        
        # Update Mean
        delta = size - s['mean']
        s['mean'] = s['mean'] + (delta / s['weight'])
        
        s['last_time'] = timestamp
        
        # Return features vector
        return np.array([s['weight'], s['mean'], size]) # [Rate, AvgSize, CurSize]

# --- Simple Autoencoder (Numpy) ---
class Autoencoder:
    def __init__(self, input_dim, hidden_dim):
        self.W1 = np.random.randn(input_dim, hidden_dim) * 0.1
        self.b1 = np.zeros(hidden_dim)
        self.W2 = np.random.randn(hidden_dim, input_dim) * 0.1
        self.b2 = np.zeros(input_dim)
        
        self.errors = []

    def sigmoid(self, x):
        return 1 / (1 + np.exp(-x))
    
    def sigmoid_derivative(self, x):
        return x * (1 - x)

    def forward(self, x):
        self.z1 = np.dot(x, self.W1) + self.b1
        self.a1 = self.sigmoid(self.z1)
        self.z2 = np.dot(self.a1, self.W2) + self.b2
        self.a2 = self.z2 # Linear output for reconstruction
        return self.a2

    def train(self, x):
        # Forward
        output = self.forward(x)
        
        # Loss (MSE)
        error = x - output
        loss = np.mean(error ** 2)
        
        # Backward (Simplified Backprop)
        # d_output = -error (assuming MSE loss gradient)
        # Linear output layer: d_z2 = d_output
        d_z2 = -error 
        
        d_W2 = np.outer(self.a1, d_z2)
        d_b2 = d_z2
        
        d_a1 = np.dot(d_z2, self.W2.T)
        d_z1 = d_a1 * self.sigmoid_derivative(self.a1)
        
        d_W1 = np.outer(x, d_z1)
        d_b1 = d_z1
        
        # Update
        self.W1 -= LEARNING_RATE * d_W1
        self.b1 -= LEARNING_RATE * d_b1
        self.W2 -= LEARNING_RATE * d_W2
        self.b2 -= LEARNING_RATE * d_b2
        
        return loss

    def get_score(self, x):
        output = self.forward(x)
        return np.mean((x - output) ** 2)

# --- Main Logic ---
def main():
    print(f"[*] Kitsune-Lite IDS Brain listening on UDP {UDP_PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    
    extractor = FeatureExtractor()
    model = Autoencoder(INPUT_SIZE, HIDDEN_SIZE)
    
    packet_count = 0
    training_phase = True
    
    # Statistics for thresholding
    train_scores = []
    threshold = 0.0
    
    # Logging
    log_file = "ids_events.json"
    if os.path.exists(log_file): os.remove(log_file)
    
    while True:
        data, addr = sock.recvfrom(1024)
        try:
            # Parse packet metadata from C++
            # Format: "timestamp,src_ip,dst_ip,size"
            msg = data.decode('utf-8').strip()
            ts_str, src_ip, dst_ip, size_str = msg.split(',')
            
            timestamp = float(ts_str)
            size = float(size_str)
            
            # DEBUG: Print everything so we know it works
            print(f"[DEBUG] Packet In: {src_ip} -> {dst_ip} | Size: {size}")
            
            # 1. Extract Features
            x = extractor.update(src_ip, size, timestamp)
            
            # Normalize features (Simple MinMax or Log scaling is better usually)
            # Using log scaling to handle large variance in network stats
            x_norm = np.log1p(x) 
            
            # 2. Process
            if training_phase:
                loss = model.train(x_norm)
                train_scores.append(loss)
                packet_count += 1
                
                # Update every 10 packets for better feedback
                if packet_count % 10 == 0:
                    print(f"[Training] Processed {packet_count}/{TRAIN_WINDOW} packets. Loss: {loss:.5f}")
                
                if packet_count >= TRAIN_WINDOW:
                    training_phase = False
                    mean_loss = np.mean(train_scores)
                    std_loss = np.std(train_scores)
                    threshold = mean_loss + (THRESHOLD_STD * std_loss)
                    print(f"[*] Training Complete. Threshold set to: {threshold:.5f}")
                    
            else:
                # 3. Detect
                score = model.get_score(x_norm)
                
                status = "BENIGN"
                if score > threshold:
                    status = "MALICIOUS"
                    print(f"[ALERT] Anomaly detected from {src_ip}! Score: {score:.5f} (Thresh: {threshold:.5f})")
                    
                    # 4. React (Log & SHADOW REALM)
                    action_taken = "Banished to Shadow Realm"
                    blocked = block_ip(src_ip)
                    if not blocked:
                         action_taken = "Detected (Whitelisted/Failed)"

                    event = {
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "score": float(score),
                        "status": status,
                        "action": action_taken
                    }
                    
                    with open(log_file, "a") as f:
                        f.write(json.dumps(event) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                        
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    main()