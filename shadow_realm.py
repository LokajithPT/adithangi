import socket
import threading
import time
import random
import sys
import subprocess
import re
import os
import paramiko

# --- CONFIGURATION ---
BIND_IP = "0.0.0.0"
BIND_PORT = 6666 # The firewall redirects here

# Load or Generate Persistent Host Key
KEY_FILE = 'host.key'
if os.path.exists(KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)
else:
    print("[*] Generating new SSH Host Key...")
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_FILE)

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

ASCII_SKULL = r"""
      NO!
    .-"      "-.
   /            \
  |              |
  |,  .-.  .-.  ,|
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
    """Try to resolve IP to MAC address using system ARP table (/proc/net/arp)."""
    # 1. Handle Localhost (No MAC)
    if ip == "127.0.0.1" or ip == "localhost":
        return "00:00:00:00:00:00 (LOCALHOST)"

    # 2. Try reading Linux ARP table directly (Most Reliable)
    try:
        with open('/proc/net/arp', 'r') as f:
            # Skip header line
            next(f)
            for line in f:
                parts = line.split()
                # parts[0] is IP, parts[3] is MAC
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00": # Filter incomplete entries
                        return mac
    except:
        pass

    # 3. Fallback to arp command
    try:
        # Run arp -n to get the table
        output = subprocess.check_output(["arp", "-n", ip]).decode()
        # Regex to find MAC
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", output)
        if mac:
            return mac.group(0)
    except:
        pass
        
    return "UNKNOWN (VPN/PROXY?)"

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
        self.command = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.event.set()
        return True
    
    def check_channel_subsystem_request(self, channel, name):
        # Reject subsystem requests (like sftp) to force clients to fall back 
        # to the simple 'scp -f' exec command which we handle.
        return False
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_scp_download(chan, command, victim_ip, victim_mac):
    """Simulates SCP protocol to serve a fake file."""
    try:
        cmd_str = command.decode('utf-8')
        print(f"[*] SCP REQUEST from {victim_ip}: {cmd_str}")
        
        # SCP -f means "from", i.e., server is sending file to client
        if not cmd_str.startswith("scp -f"):
             # Client is trying to upload (-t)? or SFTP?
             chan.send(b'\x01SCP Protocol Error: Only downloads allowed.\n')
             return

        # Determine filename
        filename = "secrets.db"
        if "passwords.txt" in cmd_str: filename = "passwords.txt"
        elif "leaked_emails.csv" in cmd_str: filename = "leaked_emails.csv"
        
        # The Trap Content
        content = f"""
===================================================
      CRITICAL SECURITY ALERT - ACCESS LOGGED
===================================================

VICTIM IDENTIFICATION:
----------------------
IP ADDRESS:  {victim_ip}
MAC ADDRESS: {victim_mac}
TIMESTAMP:   {time.ctime()}

STATUS:      TRAPPED IN SHADOW REALM
ACTION:      AUTHORITIES NOTIFIED

(Nice try. There are no secrets here, only the void.)
===================================================
"""
        
        # SCP Protocol Implementation
        # 1. Wait for initial 0x00 from client
        # (Some clients send it, some wait for us. We'll try to read it with timeout)
        chan.settimeout(1.0)
        try:
            chan.recv(1) 
        except socket.timeout:
            pass # Client didn't send start byte, proceed anyway
        
        # 2. Send File Info: C0644 <size> <filename>\n
        header = f"C0644 {len(content)} {filename}\n"
        chan.send(header.encode())
        
        # 3. Wait for ACK (0x00)
        try:
            resp = chan.recv(1)
            if resp != b'\x00': 
                 print(f"[-] SCP: Client sent {resp} instead of ACK")
        except: pass
        
        # 4. Send Content
        chan.send(content.encode())
        
        # 5. Send NULL (EOF)
        chan.send(b'\x00')
        
        # 6. Wait for final ACK
        try:
             chan.recv(1)
        except: pass
        
        print(f"[*] SCP TRAP SUCCESS: Sent fake {filename} to {victim_ip}")
        
    except Exception as e:
        print(f"[-] SCP Error: {e}")
    finally:
        chan.close()

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
        except paramiko.SSHException as e:
            print(f"[-] SSH TRAP: Client {victim_ip} SSH negotiation failed: {e}")
            return

        # Wait for auth
        chan = t.accept(20)
        if chan is None:
            print(f"[-] SSH TRAP: Client {victim_ip} did not open a channel (Auth failed/Timeout).")
            return
        
        # Wait for shell OR exec request (SCP)
        server.event.wait(10)
        if not server.event.is_set():
            print(f"[-] SSH TRAP: Client {victim_ip} did not request a shell or command.")
            return

        # CHECK: Is this SCP (exec) or Shell?
        if server.command:
            handle_scp_download(chan, server.command, victim_ip, victim_mac)
            return

        # --- THEATRICS START HERE ---
        # Initial clear screen + Banner
        chan.settimeout(None) # Remove timeout for shell
        chan.send("\033[2J\033[H") # Clear screen ANSI code
        slow_type(chan, "Connected to INTERNAL_MAINFRAME_V9 [SECURE]", 0.05)
        time.sleep(0.5)
        
        # FAKE INJECTION
        slow_type(chan, "[*] SYSTEM COMPROMISED. UPLOADING TRACKER...", 0.05)
        time.sleep(0.5)
        chan.send("[================================>] 100%\r\n")
        time.sleep(0.5)
        slow_type(chan, "[*] PAYLOAD INJECTED SUCCESSFULLY.", 0.05)
        time.sleep(1)

        while True:
            # Fake Prompt
            prompt = f"root@{victim_ip}:~# "
            chan.send(prompt)
            
            # Read Input char by char (Blocking Mode)
            cmd = ""
            while True:
                try:
                    char = chan.recv(1) # Wait for input
                    if not char: 
                        return # Connection closed by client
                except:
                    return

                # Handle Enter (CR or LF)
                if char == b'\r' or char == b'\n':
                    chan.send("\r\n")
                    break
                
                # Handle Backspace (Basic 0x7f)
                if char == b'\x7f':
                    if len(cmd) > 0:
                        cmd = cmd[:-1]
                        chan.send("\b \b") # Erase on terminal
                    continue
                
                # Echo back and store
                chan.send(char)
                cmd += char.decode('utf-8', errors='ignore')

            cmd = cmd.strip()
            if not cmd: 
                continue # Just a newline, print prompt again
            
            # Artificial Lag
            time.sleep(random.uniform(0.2, 0.5))

            # --- CUSTOM COMMANDS ---
            if cmd == "whoami":
                response = f"USER: root\nREAL_ID: {victim_ip}\nMAC_ADDR: {victim_mac}\nSTATUS: OWNED"
                slow_type(chan, response)
                continue

            if cmd == "ls" or cmd == "dir":
                slow_type(chan, "secrets.db  passwords.txt  leaked_emails.csv  DO_NOT_OPEN.exe")
                continue

            if cmd == "cat secrets.db" or cmd == "cat passwords.txt":
                # THEATRICAL REVEAL
                trap_msg = f"""
{ASCII_SKULL}

===================================================
      CRITICAL SECURITY ALERT - ACCESS LOGGED
===================================================

VICTIM IDENTIFICATION:
----------------------
IP ADDRESS:  {victim_ip}
MAC ADDRESS: {victim_mac}
TIMESTAMP:   {time.ctime()}

STATUS:      TRAPPED IN SHADOW REALM
ACTION:      AUTHORITIES NOTIFIED

(Did you really think it would be that easy?)
===================================================
"""
                # Send it slowly line by line for effect
                for line in trap_msg.split('\n'):
                    chan.send(line + '\r\n')
                    time.sleep(0.05)
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