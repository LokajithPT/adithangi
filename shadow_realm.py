import socket
import threading
import time
import random
import sys
import subprocess
import re

BIND_IP = "0.0.0.0"
BIND_PORT = 6666

CREEPY_MESSAGES = [
    "I see you...",
    "There is no escape.",
    "Why are you here?",
    "You are not alone.",
    "Look behind you.",
    "The void stares back.",
    "Delete system32? (y/n)",
    "Accessing camera...",
    "Uploading your history..."
]

ASCII_SKULL = """
      NO!
    .-"      "-.
   /            \\
  |              |
  |,  .-.  .-.  ,|
  | )(__/  \\__)( |
  |/     /\\     \\|
  (_     ^^     _)
   \\__|IIIIII|__/
    | \\IIIIII/ |
    \\          /
     `--------`
   YOU ARE TRAPPED
"""

def get_mac(ip):
    """Try to resolve IP to MAC address using system ARP table."""
    try:
        # Run arp -n to get the table
        output = subprocess.check_output(["arp", "-n", ip]).decode()
        # Regex to find MAC
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", output)
        if mac:
            return mac.group(0)
    except:
        pass
    return "UNKNOWN:LOCATION:HIDDEN"

def slow_type(conn, message, delay=0.05):
    """Simulates slow typing for maximum annoyance/creepiness."""
    try:
        for char in message:
            conn.send(char.encode())
            time.sleep(random.uniform(0.01, delay))
        conn.send(b"\r\n")
    except:
        pass

def handle_victim(conn, addr):
    victim_ip = addr[0]
    print(f"[*] VICTIM ENTERED THE SHADOW REALM: {victim_ip}")
    
    # Try to find their MAC
    victim_mac = get_mac(victim_ip)
    
    try:
        # Initial Fake Banner
        slow_type(conn, "Connected to INTERNAL_MAINFRAME_V9 [SECURE]", 0.05)
        time.sleep(1)
        
        while True:
            # Fake Prompt: PERSONALIZED
            prompt = f"root@{victim_ip}:~# "
            conn.send(prompt.encode())
            
            # Read input
            data = conn.recv(1024)
            if not data:
                break
            
            cmd = data.decode('utf-8', errors='ignore').strip()
            
            # Artificial Lag
            time.sleep(random.uniform(0.2, 0.8))
            
            # --- CUSTOM COMMANDS FOR THE SHOW ---
            if cmd == "whoami":
                response = f"USER: root\nREAL_ID: {victim_ip}\nMAC_ADDR: {victim_mac}\nSTATUS: OWNED"
                slow_type(conn, response, 0.05)
                continue

            if cmd == "ls" or cmd == "dir":
                response = "secrets.db  passwords.txt  nudes.zip  DO_NOT_OPEN.exe"
                slow_type(conn, response, 0.05)
                continue
                
            if cmd == "cat secrets.db" or cmd == "cat passwords.txt":
                slow_type(conn, "ACCESS DENIED. BIOMETRIC SCAN REQUIRED.", 0.1)
                slow_type(conn, "SCANNING FINGERPRINT...", 0.2)
                slow_type(conn, "ERROR: FINGERPRINT NOT RECOGNIZED.", 0.05)
                continue

            if cmd == "reveal":
                conn.send(ASCII_SKULL.encode())
                continue
                
            if cmd == "exit" or cmd == "quit":
                slow_type(conn, "THERE IS NO ESCAPE.", 0.2)
                continue

            # --- RANDOM CREEPINESS ---
            # 10% chance to just print a creepy message
            if random.random() < 0.1:
                slow_type(conn, random.choice(CREEPY_MESSAGES), 0.1)
                continue
            
            if cmd:
                response = f"bash: {cmd}: command not found... or is it?"
                slow_type(conn, response, 0.05)

    except Exception as e:
        pass
    finally:
        print(f"[-] Victim {victim_ip} escaped (disconnected).")
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)
    
    print(f"[*] THE SHADOW REALM IS OPEN ON PORT {BIND_PORT}")
    print("[*] Waiting for redirected souls...")
    
    while True:
        client, addr = server.accept()
        client_handler = threading.Thread(target=handle_victim, args=(client, addr))
        client_handler.start()

if __name__ == "__main__":
    start_server()
