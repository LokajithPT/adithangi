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
        # NOTE: For testing purposes, you might want to comment out the whitelist 
        # if you are testing from another machine on the LAN.
        print(f"[SAFEGUARD] Skipping Shadow Realm for local/LAN IP: {ip_address}")
        return False

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
# ... (rest of file)

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
