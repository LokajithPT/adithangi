import socket
import threading
import time
import random
import sys

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

def slow_type(conn, message, delay=0.1):
    """Simulates slow typing for maximum annoyance/creepiness."""
    try:
        for char in message:
            conn.send(char.encode())
            time.sleep(random.uniform(0.05, delay))
        conn.send(b"\r\n")
    except:
        pass

def handle_victim(conn, addr):
    print(f"[*] VICTIM ENTERED THE SHADOW REALM: {addr[0]}")
    
    try:
        # Initial Fake Banner
        slow_type(conn, "Connected to INTERNAL_MAINFRAME_V9 [SECURE]", 0.05)
        time.sleep(1)
        
        while True:
            # Fake Prompt
            conn.send(b"root@mainframe:~# ")
            
            # Read input (and ignore it mostly)
            data = conn.recv(1024)
            if not data:
                break
            
            # Artificial Lag
            time.sleep(random.uniform(0.5, 2.0))
            
            # 10% chance to just print a creepy message instead of running the command
            if random.random() < 0.2:
                slow_type(conn, random.choice(CREEPY_MESSAGES), 0.1)
                continue
            
            # 20% chance to simulate a crash/error
            if random.random() < 0.2:
                 slow_type(conn, "Segmentation fault (core dumped)", 0.02)
                 continue

            # Default response: Command not found or weird output
            cmd = data.decode('utf-8', errors='ignore').strip()
            if cmd:
                response = f"bash: {cmd}: command not found... or is it?"
                slow_type(conn, response, 0.05)

    except Exception as e:
        pass
    finally:
        print(f"[-] Victim {addr[0]} escaped (disconnected).")
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
