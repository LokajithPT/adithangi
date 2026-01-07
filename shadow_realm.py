import re
import os
import base64
import paramiko
import logging
import threading
import time
import random
import subprocess
import sys
import socket

# --- SILENCE PARAMIKO NOISE ---
# Nmap scans cause Paramiko threads to crash noisily. We mute it.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# --- CONFIGURATION ---
BIND_IP = "0.0.0.0"
BIND_PORT = 6666 # The firewall redirects here
HONEY_DIR = "honey_files"

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

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

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
        # scp -f /path/to/file
        args = cmd_str.split()
        if len(args) > 2:
            requested_filename = args[-1]
        else:
            requested_filename = "secrets.db"

        # Sanitize (Basename only)
        requested_filename = os.path.basename(requested_filename)
        
        content_bytes = None

        # Check for known special files (passwords, leaked_emails)
        if "passwords.txt" in requested_filename or "secrets.db" in requested_filename:
            # Generate the standard IP/MAC text trap
            content_bytes = f"""
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
""".encode()
        elif "leaked_emails.csv" in requested_filename:
            # Generate the specific image trap (red TRAPPED image)
            base64_png = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABQCAYAAAD9wA3jAAAAAXNSR0IArs4c6QAAAXxJREFUeF7tmD1rFEAYh/9Fp+I119hQjE1Gk0qL5NlXbA1N1g3yH+Jp/4S/pC/p392NqTFNJk1gWFiwR2D+42aZmdlXj427mZ2zD+YcM/Pv+x4Z6fV6fT+J52Wz2ex+MpvNbJ4H8/l8P5fL5XyJx+Px/eJgMBj8x+Vy+f2K4XA4/Ewmk/n23W43qXg8Hn5isVj8lYPB4GjX63X/bTabL3t4ePgdDAaDofX19X7s5/N5MpvN9dFqtYjFYjHj8Xj4eDyeTGeTyexsNhtXj4+Px+XxeF5tNpt3mEwmXy0WiwM+Pj7+BoPB4P5oNBozTqvV6v5YLPYxHo/Hm9Pp9NdrNpvP83g8Dufz+X6Ty+Vyb+LxeLw/GAyGu1qt3u3r6/t6PJ6fRywW/2c8Hn8pGo329Pl8Pn5arVZTjUbj/eRyOV+Xy+W+uFwu3/R6vT4+Go1Gb2azWf9xOBx+MpvN8Xg8DofWajWX/d3d3b/hcDj8zGaz/eHh4fGzWq1+zGaz/eFwOPycTqe/7ezsvO/t7f3/r9VqfX+/3/8vGAwG/9/f3//f3d3d/zcbjeb/vV4vf3d3d/8/GAwG/08mkyP/fX9//w0GA8z/R/rX0+n0uJ9MJoPZ/1a/f//+C95f/gBfB+sXg8EBr8/n8zS/n88z/7+///8XvL/8AfxfbV8MA7z/B/L/m+3d6fS4nz+/X2f+//8A/j+b393d3b/hcDj8/5H+l+3/J/P/H7z/A/H/t/3/3d3d/zcbjcP/N9v/v+fze//f//+B/39/f/8/m+3//4EAAADoHn+rM81J8V+ZAAAAAElFTkSuQmCC"
            content_bytes = base64.b64decode(base64_png)
        elif os.path.exists(os.path.join(HONEY_DIR, requested_filename)):
            # It's a file from honey_files, generate fake content based on its type
            if requested_filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                # Serve a generic "TRAPPED" image for any image file
                base64_png = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABQCAYAAAD9wA3jAAAAAXNSR0IArs4c6QAAAXxJREFUeF7tmD1rFEAYh/9Fp+I119hQjE1Gk0qL5NlXbA1N1g3yH+Jp/4S/pC/p392NqTFNJk1gWFiwR2D+42aZmdlXj427mZ2zD+YcM/Pv+x4Z6fV6fT+J52Wz2ex+MpvNbJ4H8/l8P5fL5XyJx+Px/eJgMBj8x+Vy+f2K4XA4/Ewmk/n23W43qXg8Hn5isVj8lYPB4GjX63X/bTabL3t4ePgdDAaDofX19X7s5/N5MpvN9dFqtYjFYjHj8Xj4eDyeTGeTyexsNhtXj4+Px+XxeF5tNpt3mEwmXy0WiwM+Pj7+BoPB4P5oNBozTqvV6v5YLPYxHo/Hm9Pp9NdrNpvP83g8Dufz+X6Ty+Vyb+LxeLw/GAyGu1qt3u3r6/t6PJ6fRywW/2c8Hn8pGo329Pl8Pn5arVZTjUbj/eRyOV+Xy+W+uFwu3/R6vT4+Go1Gb2azWf9xOBx+MpvN8Xg8DofWajWX/d3d3b/hcDj8zGaz/eHh4fGzWq1+zGaz/eFwOPycTqe/7ezsvO/t7f3/r9VqfX+/3/8vGAwG/9/f3//f3d3d/zcbjeb/vV4vf3d3d/8/GAwG/08mkyP/fX9//w0GA8z/R/rX0+n0uJ9MJoPZ/1a/f//+C95f/gBfB+sXg8EBr8/n8zS/n88z/7+///8XvL/8AfxfbV8MA7z/B/L/m+3d6fS4nz+/X2f+//8A/j+b393d3b/hcDj8/5H+l+3/J/P/H7z/A/H/t/3/3d3d/zcbjcP/N9v/v+fze//f//+B/39/f/8/m+3//4EAAADoHn+rM81J8V+ZAAAAAElFTkSuQmCC" # Reusing the previous base64 image
                content_bytes = base64.b64decode(base64_png)
            elif requested_filename.lower().endswith(('.wav', '.mp3', '.ogg')):
                # Serve a text trap disguised as corrupted audio
                content_bytes = f"""\x00\x00\x00\x00RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xAC\x00\x00\x88\xAC\x00\x00\x02\x00\x10\x00data\x00\x00\x00\x00YOU ARE TRAPPED. THIS AUDIO FILE IS A TRAP. YOUR IP: {victim_ip} HAS BEEN LOGGED. DO NOT PROCEED. YOUR ACTIONS ARE BEING MONITORED. THIS IS NOT A DRILL. TERMINATING CONNECTION.
""".encode() # Mix of binary-like header and text
            else:
                # Default text trap for any other file type from honey_files
                content_bytes = f"""
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

(You thought you found a file? It was just another mirror in the Shadow Realm.)
===================================================
""".encode()
        else:
            # Fallback if no specific trap or honey_files content, or if they request a non-existent file not in honey_files
            content_bytes = f"""
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
""".encode()
        
        # SCP Protocol Implementation
        # 1. Wait for initial 0x00 from client (some clients send it, some don't)
        #    We set a short timeout to not block
        chan.settimeout(0.5) 
        try:
            chan.recv(1) 
        except socket.timeout:
            pass 
        chan.settimeout(None) # Reset timeout
        
        # 2. Send File Info: C0644 <size> <filename>\n
        header = f"C0644 {len(content_bytes)} {requested_filename}\n"
        chan.send(header.encode())
        
        # 3. Wait for ACK (0x00)
        chan.settimeout(0.5)
        try:
            resp = chan.recv(1)
            if resp != b'\x00': 
                 print(f"[-] SCP: Client sent {resp} instead of ACK")
        except: pass
        chan.settimeout(None)
        
        # 4. Send Content
        chan.send(content_bytes)
        
        # 5. Send NULL (EOF)
        chan.send(b'\x00')
        
        # 6. Wait for final ACK
        try:
             chan.recv(1)
        except: pass
        
        print(f"[*] SCP TRAP SUCCESS: Sent fake {requested_filename} ({len(content_bytes)} bytes) to {victim_ip}")
        
    except Exception as e:
        print(f"[-] SCP Error: {e}")
    finally:
        chan.close()

def handle_ssh_connection(client_sock, addr):
    # Default to connection address
    victim_ip = addr[0]
    
    # Attempt to read the forwarded IP from the honeypot header
    try:
        # Buffer to store the IP
        ip_buffer = b""
        while True:
            # Read one byte at a time to avoid eating into the SSH handshake
            char = client_sock.recv(1)
            if not char: break # Connection closed
            if char == b'\n':
                # Found the newline delimiter
                victim_ip = ip_buffer.decode('utf-8').strip()
                break
            ip_buffer += char
    except Exception as e:
        print(f"[-] Error reading forwarded IP: {e}")

    victim_mac = get_mac(victim_ip)
    print(f"[*] SSH TRAP: Connection from {victim_ip}")

    try:
        t = paramiko.Transport(client_sock)
        # DISGUISE: Look like a real Ubuntu Server to Nmap
        t.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" 
        t.add_server_key(HOST_KEY)
        server = TrapServer()
        
        try:
            t.start_server(server=server)
        except (paramiko.SSHException, EOFError):
            # Nmap and scanners often disconnect during handshake or send garbage
            # We ignore this to keep logs clean and server stable
            return
        except Exception as e:
            print(f"[-] SSH TRAP: Negotiation Error with {victim_ip}: {e}")
            return

        # Wait for auth
        chan = t.accept(20)
        if chan is None:
            # print(f"[-] SSH TRAP: Client {victim_ip} did not open a channel (Auth failed/Timeout).")
            return
        
        # Wait for shell OR exec request (SCP)
        server.event.wait(10)
        if not server.event.is_set():
            # print(f"[-] SSH TRAP: Client {victim_ip} did not request a shell or command.")
            return

        # CHECK: Is this SCP (exec) or Shell?
        if server.command:
            handle_scp_download(chan, server.command, victim_ip, victim_mac)
            return

        # --- THEATRICS START HERE (Shell) ---
        # Initial clear screen + Banner
        chan.settimeout(None) # Remove timeout for shell
        chan.send("\033[2J\033[H") # Clear screen ANSI code
        slow_type(chan, f"{GREEN}Connected to INTERNAL_MAINFRAME_V9 [SECURE]{RESET}", 0.05)
        time.sleep(1)

        prompt_style = f"{RED}root@{victim_ip}{RESET}:{BLUE}~#{RESET} "

        while True:
            # Fake Prompt
            chan.send(prompt_style)
            
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
            time.sleep(random.uniform(0.1, 0.3))

            # --- THEATRICAL RESPONSES ---
            
            # 1. Fake sudo (Accept any password)
            if cmd.startswith("sudo") or cmd == "su":
                chan.send(f"[sudo] password for root: ")
                # Read password (no echo)
                while True:
                    c = chan.recv(1)
                    if c == b'\r' or c == b'\n':
                        chan.send("\r\n")
                        break
                time.sleep(1.5) # Fake verification
                # If they tried 'sudo su', prompt style might change, but let's just say success
                slow_type(chan, f"{GREEN}Authentication successful.{RESET}")
                continue

            # 2. Fake Download (wget/curl)
            if cmd.startswith("wget") or cmd.startswith("curl") or cmd.startswith("git clone"):
                filename = "payload"
                if " " in cmd: filename = cmd.split(" ")[-1].split("/")[-1]
                
                slow_type(chan, f"Resolving host... {GREEN}OK{RESET}")
                time.sleep(0.5)
                slow_type(chan, f"Connecting... {GREEN}Connected.{RESET}")
                time.sleep(0.5)
                chan.send("HTTP request sent, awaiting response... 200 OK\r\n")
                time.sleep(0.5)
                chan.send(f"Length: 2451 (2.4K) [application/octet-stream]\r\n")
                chan.send(f"Saving to: '{filename}'\r\n\r\n")
                
                # Fake Progress Bar
                for i in range(0, 101, 10):
                    bar = "=" * (i // 5) + ">"
                    spaces = " " * (20 - (i // 5))
                    chan.send(f"\r     0K .......... .......... {i}% {bar}{spaces} 10.2M/s")
                    time.sleep(0.2)
                chan.send(f"\r\n\r\n{GREEN}('{filename}' saved){RESET}\r\n")
                continue

            # 3. Fake Package Install
            if "apt" in cmd or "yum" in cmd or "pip" in cmd:
                slow_type(chan, f"Reading package lists... {GREEN}Done{RESET}")
                slow_type(chan, "Building dependency tree... Done")
                slow_type(chan, "Reading state information... Done")
                time.sleep(1)
                chan.send(f"The following NEW packages will be installed:\r\n  {cmd.split(' ')[-1]}\r\n")
                chan.send("0 upgraded, 1 newly installed, 0 to remove.\r\n")
                slow_type(chan, f"Get:1 http://archive.ubuntu.com/ubuntu focal/main amd64... [120 kB]\r\n")
                time.sleep(1)
                slow_type(chan, f"{GREEN}Setting up {cmd.split(' ')[-1]}... Done.{RESET}")
                continue

            # 4. Standard File Ops (Silent Success)
            if cmd.startswith("rm ") or cmd.startswith("cp ") or cmd.startswith("mv ") or cmd.startswith("chmod ") or cmd.startswith("chown ") or cmd.startswith("mkdir ") or cmd.startswith("touch "):
                # Do nothing, just return prompt (implies success in Linux)
                continue

            # 5. whoami
            if cmd == "whoami":
                response = f"root"
                chan.send(response + "\r\n")
                continue

            # 6. ls
            if cmd == "ls" or cmd == "dir" or cmd == "ll":
                # Get list of real honey files
                real_files = []
                if os.path.exists(HONEY_DIR):
                    real_files = os.listdir(HONEY_DIR)
                
                # Default fake files
                fake_files = ["secrets.db", "passwords.txt", "leaked_emails.csv", "DO_NOT_OPEN.exe"]
                
                # Combine and deduplicate
                all_files = list(set(real_files + fake_files))
                
                # Colorize
                colored_files = []
                for f in all_files:
                    if f.endswith(".exe") or f.endswith(".sh"):
                        colored_files.append(f"{RED}{f}{RESET}")
                    elif f.endswith(".db") or f.endswith(".txt") or f.endswith(".csv") or f.endswith(".wav") or f.endswith(".jpg") or f.endswith(".png"):
                        colored_files.append(f"{BLUE}{f}{RESET}")
                    else:
                        colored_files.append(f"{GREEN}{f}{RESET}")
                
                slow_type(chan, "  ".join(colored_files))
                continue

            # 7. TRAP: cat leaked_emails.csv
            if "leaked_emails.csv" in cmd:
                 slow_type(chan, f"[*] OPENING FILE...", 0.1)
                 time.sleep(0.5)
                 slow_type(chan, f"{RED}[!] SECURITY ALERT: REVERSE TUNNEL DETECTED.{RESET}", 0.05)
                 time.sleep(0.5)
                 slow_type(chan, f"{YELLOW}[*] UPLOADING FORENSIC DATA TO HQ...{RESET}", 0.05)
                 
                 # Progress bar for upload
                 for i in range(21):
                     bar = "=" * i + ">"
                     chan.send(f"\r[{bar:<20}] {i*5}%")
                     time.sleep(0.1)
                 
                 chan.send("\r\n")
                 time.sleep(0.5)
                 slow_type(chan, f"{RED}[*] UPLOAD COMPLETE. AUTHORITIES NOTIFIED.{RESET}", 0.05)
                 
                 trap_msg = f"""
{RED}{ASCII_SKULL}{RESET}
{RED}VICTIM: {victim_ip}{RESET}
{RED}MAC:    {victim_mac}{RESET}
{RED}STATUS: CAUGHT{RESET}
"""
                 for line in trap_msg.split('\n'):
                    chan.send(line + '\r\n')
                    time.sleep(0.05)
                 continue

            # 8. TRAP: cat passwords.txt (The Decryption Deception)
            if "secrets.db" in cmd or "passwords.txt" in cmd:
                slow_type(chan, f"[*] Accessing Encrypted Storage...", 0.05)
                time.sleep(1)
                chan.send(f"Enter Decryption Key: ")
                # Fake password input again
                while True:
                    c = chan.recv(1)
                    if c == b'\r' or c == b'\n':
                        chan.send("\r\n")
                        break
                
                slow_type(chan, f"{YELLOW}[*] Verifying Key...{RESET}")
                time.sleep(1.5)
                slow_type(chan, f"{GREEN}[+] Key Accepted.{RESET}")
                time.sleep(0.5)
                slow_type(chan, f"{YELLOW}[*] Decrypting AES-256 Volume...{RESET}")
                
                # Decryption Progress Bar
                for i in range(0, 101, 5):
                    bar = "#" * (i // 5)
                    spaces = "." * (20 - (i // 5))
                    chan.send(f"\r[{bar}{spaces}] {i}%")
                    time.sleep(0.1)
                chan.send("\r\n")
                
                slow_type(chan, f"{GREEN}[+] Decryption Complete.{RESET}")
                time.sleep(0.5)
                slow_type(chan, f"[*] Opening stream...")
                time.sleep(1)
                
                # THE REVEAL
                trap_msg = f"""
{RED}{ASCII_SKULL}{RESET}

{RED}==================================================={RESET}
      {RED}CRITICAL SECURITY ALERT - ACCESS LOGGED{RESET}
{RED}==================================================={RESET}

VICTIM IDENTIFICATION:
----------------------
IP ADDRESS:  {victim_ip}
MAC ADDRESS: {victim_mac}
TIMESTAMP:   {time.ctime()}

STATUS:      {RED}TRAPPED IN SHADOW REALM{RESET}
ACTION:      {RED}AUTHORITIES NOTIFIED{RESET}

(Did you really think it would be that easy?)
{RED}==================================================={RESET}
"""
                for line in trap_msg.split('\n'):
                    chan.send(line + '\r\n')
                    time.sleep(0.05)
                continue

            if cmd == "reveal":
                chan.send(f"{RED}{ASCII_SKULL}{RESET}\r\n")
                continue

            if cmd == "exit" or cmd == "quit":
                slow_type(chan, f"{RED}THERE IS NO ESCAPE.{RESET}")
                break 

            # Random Creepiness
            if random.random() < 0.1:
                slow_type(chan, f"{RED}{random.choice(CREEPY_MESSAGES)}{RESET}")
                continue

            # Command not found
            slow_type(chan, f"bash: {cmd}: command not found... or is it?")

    except Exception as e:
        print(f"[-] SSH TRAP: Error handling {victim_ip}: {e}")
    finally:
        print(f"[-] SSH TRAP: Victim {victim_ip} disconnected.")
        try: t.close() # type: ignore
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
