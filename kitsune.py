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
    if ip_address == "127.0.0.1" or ip_address.startswith("192.168."):
        print(f"[SAFEGUARD] Skipping block for local/LAN IP: {ip_address}")
        return False

    print(f"[FIREWALL] BLOCKING {ip_address} via iptables...")
    try:
        # Check if already blocked to avoid duplicates
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if check.returncode != 0:
            # Add DROP rule
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"[FIREWALL] SUCCESS: {ip_address} has been dropped.")
            return True
        else:
            print(f"[FIREWALL] IP {ip_address} is already blocked.")
            return True
    except Exception as e:
        print(f"[FIREWALL] ERROR: Could not block IP: {e}")
        return False

# --- Kitsune Feature Extractor (Simplified) ---
class FeatureExtractor:
# ... (rest of class unchanged)

# ... (Autoencoder class unchanged)

# ... (Main logic start)
    while True:
        data, addr = sock.recvfrom(1024)
        try:
            # ... (parsing logic unchanged)
            
            # ... (feature extraction and detection logic)

            else:
                # 3. Detect
                score = model.get_score(x_norm)
                
                status = "BENIGN"
                if score > threshold:
                    status = "MALICIOUS"
                    print(f"[ALERT] Anomaly detected from {src_ip}! Score: {score:.5f} (Thresh: {threshold:.5f})")
                    
                    # 4. React (Log & BLOCK)
                    action_taken = "Blocked via Firewall"
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
