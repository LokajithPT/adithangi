import socket
import threading
import time
import random
import sys
import subprocess
import re
import paramiko
from paramiko.py3compat import u

# --- CONFIGURATION ---
BIND_IP = "0.0.0.0"
BIND_PORT = 6666 # The firewall redirects here
HOST_KEY = paramiko.RSAKey.generate(2048) # Generate a key on startup

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
   /            \
  |              |
  |,  .-.  .-.  , |
  | )(__/  \__)( |
  |/     /\     \|
  (_     ^^     _)
   \__|IIIIII|__/
    | \IIIIII/ |
    \          /
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

def slow_type(chan, message, delay=0.05):
    """Simulates slow typing into the SSH channel."""
    try:
        for char in message:
            chan.send(char)
            time.sleep(random.uniform(0.01, delay))
        chan.send("\r\n")
    except: pass

class TrapServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # ACCEPT ALL PASSWORDS!
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_ssh_connection(client_sock, addr):
    victim_ip = addr[0]
    victim_mac = get_mac(victim_ip)
    print(f"[*] SSH TRAP: Connection from {victim_ip}")

    try:
        t = paramiko.Transport(client_sock)
        t.add_server_key(HOST_KEY)
        server = TrapServer()
        
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print(f"[-] SSH TRAP: Client {victim_ip} failed to start SSH server.")
            return

        # Wait for auth
        chan = t.accept(20)
        if chan is None:
            print(f"[-] SSH TRAP: Client {victim_ip} did not open a channel.")
            return

        server.event.wait(10) # Wait for shell request
        if not server.event.is_set():
            print(f"[-] SSH TRAP: Client {victim_ip} did not request a shell.")
            return

        # --- THEATRICS START HERE ---
        # Initial clear screen + Banner
        chan.send("\033[2J\033[H") # Clear screen ANSI code
        slow_type(chan, "Connected to INTERNAL_MAINFRAME_V9 [SECURE]", 0.05)
        time.sleep(1)

        while True:
            # Fake Prompt
            prompt = f"root@{victim_ip}:~# "
            chan.send(prompt)
            
            # Read Input char by char to handle echo (basic shell emulation)
            cmd = ""
            # Handle potential EOF from client immediately
            if chan.recv_ready():
                char = chan.recv(1)
                if not char: # EOF
                    break
                # Echo and collect first char
                if char not in [b'\r', b'\n', b'\x7f']: # Not enter/backspace
                    chan.send(char)
                    cmd += char.decode('utf-8', errors='ignore')

            # Continue reading if more input is available
            while chan.recv_ready():
                char = chan.recv(1)
                if not char: break # EOF
                
                # Handle Enter
                if char == b'\r' or char == b'\n':
                    chan.send("\r\n")
                    break
                
                # Handle Backspace (Basic)
                if char == b'\x7f':
                    if len(cmd) > 0:
                        cmd = cmd[:-1]
                        chan.send("\b \b") # Erase on terminal
                    continue
                
                # Echo back and store
                chan.send(char)
                cmd += char.decode('utf-8', errors='ignore')

            if not cmd: 
                # If command is empty, send just a newline for a new prompt
                if not char: # If EOF from last read
                    break
                else:
                    continue # Wait for next input
            
            # Artificial Lag
            time.sleep(random.uniform(0.2, 0.5))

            # --- CUSTOM COMMANDS ---
            if cmd == "whoami":
                response = f"USER: root\nREAL_ID: {victim_ip}\nMAC_ADDR: {victim_mac}\nSTATUS: OWNED"
                slow_type(chan, response)
                continue

            if cmd == "ls" or cmd == "dir":
                slow_type(chan, "secrets.db  passwords.txt  nudes.zip  DO_NOT_OPEN.exe")
                continue

            if cmd == "cat secrets.db" or cmd == "cat passwords.txt":
                slow_type(chan, "ACCESS DENIED. BIOMETRIC SCAN REQUIRED.", 0.1)
                slow_type(chan, "SCANNING FINGERPRINT...", 0.2)
                slow_type(chan, "ERROR: FINGERPRINT NOT RECOGNIZED.", 0.05)
                continue

            if cmd == "reveal":
                chan.send(ASCII_SKULL + "\r\n")
                continue

            if cmd == "exit" or cmd == "quit":
                slow_type(chan, "THERE IS NO ESCAPE.")
                break # Exit the while loop to close channel

            # Random Creepiness
            if random.random() < 0.1:
                slow_type(chan, random.choice(CREEPY_MESSAGES))
                continue

            # Command not found
            slow_type(chan, f"bash: {cmd}: command not found... or is it?")

    except Exception as e:
        print(f"[-] SSH TRAP: Error handling {victim_ip}: {e}")
    finally:
        print(f"[-] SSH TRAP: Victim {victim_ip} disconnected.")
        try: t.close()
        except: pass

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_IP, BIND_PORT))
    sock.listen(100)
    
    print(f"[*] SSH SHADOW REALM LISTENING ON PORT {BIND_PORT}")
    print("[*] Ready to accept redirected SSH connections...")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_ssh_connection, args=(client, addr)).start()

if __name__ == "__main__":
    start_server()