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
CLEAR = "\033[2J\033[H"

def get_mac(ip):
    """Try to resolve IP to MAC address using system ARP table (/proc/net/arp)."""
    if ip == "127.0.0.1" or ip == "localhost":
        return "00:00:00:00:00:00 (LOCALHOST)"
    try:
        with open('/proc/net/arp', 'r') as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00": return mac
    except: pass
    try:
        output = subprocess.check_output(["arp", "-n", ip]).decode()
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", output)
        if mac: return mac.group(0)
    except: pass
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
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
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
    try:
        cmd_str = command.decode('utf-8')
        print(f"[*] SCP REQUEST from {victim_ip}: {cmd_str}")
        if not cmd_str.startswith("scp -f"):
             chan.send(b'\x01SCP Protocol Error: Only downloads allowed.\n')
             return

        args = cmd_str.split()
        requested_filename = args[-1] if len(args) > 2 else "secrets.db"
        requested_filename = os.path.basename(requested_filename)
        
        content_bytes = None

        if "passwords.txt" in requested_filename or "secrets.db" in requested_filename:
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
            base64_png = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABQCAYAAAD9wA3jAAAAAXNSR0IArs4c6QAAAXxJREFUeF7tmD1rFEAYh/9Fp+I119hQjE1Gk0qL5NlXbA1N1g3yH+Jp/4S/pC/p392NqTFNJk1gWFiwR2D+42aZmdlXj427mZ2zD+YcM/Pv+x4Z6fV6fT+J52Wz2ex+MpvNbJ4H8/l8P5fL5XyJx+Px/eJgMBj8x+Vy+f2K4XA4/Ewmk/n23W43qXg8Hn5isVj8lYPB4GjX63X/bTabL3t4ePgdDAaDofX19X7s5/N5MpvN9dFqtYjFYjHj8Xj4eDyeTGeTyexsNhtXj4+Px+XxeF5tNpt3mEwmXy0WiwM+Pj7+BoPB4P5oNBozTqvV6v5YLPYxHo/Hm9Pp9NdrNpvP83g8Dufz+X6Ty+Vyb+LxeLw/GAyGu1qt3u3r6/t6PJ6fRywW/2c8Hn8pGo329Pl8Pn5arVZTjUbj/eRyOV+Xy+W+uFwu3/R6vT4+Go1Gb2azWf9xOBx+MpvN8Xg8DofWajWX/d3d3b/hcDj8zGaz/eHh4fGzWq1+zGaz/eFwOPycTqe/7ezsvO/t7f3/r9VqfX+/3/8vGAwG/9/f3//f3d3d/zcbjeb/vV4vf3d3d/8/GAwG/08mkyP/fX9//w0GA8z/R/rX0+n0uJ9MJoPZ/1a/f//+C95f/gBfB+sXg8EBr8/n8zS/n88z/7+///8XvL/8AfxfbV8MA7z/B/L/m+3d6fS4nz+/X2f+//8A/j+b393d3b/hcDj8/5H+l+3/J/P/H7z/A/H/t/3/3d3d/zcbjcP/N9v/v+fze//f//+B/39/f/8/m+3//4EAAADoHn+rM81J8V+ZAAAAAElFTkSuQmCC"
            content_bytes = base64.b64decode(base64_png)
        elif requested_filename.lower().endswith('.iso'):
            # THE CURSED ISO TRAP
            fake_size = 666666666
            header = f"C0644 {fake_size} {requested_filename}\n"
            chan.send(header.encode())
            chan.settimeout(0.5)
            try: chan.recv(1)
            except: pass
            chan.settimeout(None)
            trap_header = f"""
{RED}{ASCII_SKULL}{RESET}
{RED}VICTIM IP: {victim_ip}{RESET}
{RED}CONTENTS:  COUNTER-MEASURE PAYLOAD{RESET}
{RED}STATUS:    DEPLOYING MALWARE TO TARGET...{RESET}
"""
            chan.send(trap_header.encode())
            print(f"[*] Sending CURSED ISO to {victim_ip}...")
            end_time = time.time() + 10 
            while time.time() < end_time:
                chunk = os.urandom(1024) + b"YOUR_SYSTEM_IS_COMPROMISED_DO_NOT_RESIST"
                try:
                    chan.send(chunk)
                    time.sleep(0.05)
                except: break
            final_msg = f"\n\n{GREEN}[+] ROOTKIT INSTALLED ON {victim_ip}. GOODBYE.{RESET}\n"
            try: chan.send(final_msg.encode())
            except: pass
            print(f"[*] Cursed ISO trap finished for {victim_ip}")
            chan.close()
            return 
        elif os.path.exists(os.path.join(HONEY_DIR, requested_filename)):
            real_file_path = os.path.join(HONEY_DIR, requested_filename)
            if requested_filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                base64_png = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABQCAYAAAD9wA3jAAAAAXNSR0IArs4c6QAAAXxJREFUeF7tmD1rFEAYh/9Fp+I119hQjE1Gk0qL5NlXbA1N1g3yH+Jp/4S/pC/p392NqTFNJk1gWFiwR2D+42aZmdlXj427mZ2zD+YcM/Pv+x4Z6fV6fT+J52Wz2ex+MpvNbJ4H8/l8P5fL5XyJx+Px/eJgMBj8x+Vy+f2K4XA4/Ewmk/n23W43qXg8Hn5isVj8lYPB4GjX63X/bTabL3t4ePgdDAaDofX19X7s5/N5MpvN9dFqtYjFYjHj8Xj4eDyeTGeTyexsNhtXj4+Px+XxeF5tNpt3mEwmXy0WiwM+Pj7+BoPB4P5oNBozTqvV6v5YLPYxHo/Hm9Pp9NdrNpvP83g8Dufz+X6Ty+Vyb+LxeLw/GAyGu1qt3u3r6/t6PJ6fRywW/2c8Hn8pGo329Pl8Pn5arVZTjUbj/eRyOV+Xy+W+uFwu3/R6vT4+Go1Gb2azWf9xOBx+MpvN8Xg8DofWajWX/d3d3b/hcDj8zGaz/eHh4fGzWq1+zGaz/eFwOPycTqe/7ezsvO/t7f3/r9VqfX+/3/8vGAwG/9/f3//f3d3d/zcbjeb/vV4vf3d3d/8/GAwG/08mkyP/fX9//w0GA8z/R/rX0+n0uJ9MJoPZ/1a/f//+C95f/gBfB+sXg8EBr8/n8zS/n88z/7+///8XvL/8AfxfbV8MA7z/B/L/m+3d6fS4nz+/X2f+//8A/j+b393d3b/hcDj8/5H+l+3/J/P/H7z/A/H/t/3/3d3d/zcbjcP/N9v/v+fze//f//+B/39/f/8/m+3//4EAAADoHn+rM81J8V+ZAAAAAElFTkSuQmCC"
                content_bytes = base64.b64decode(base64_png)
            elif requested_filename.lower().endswith(('.wav', '.mp3', '.ogg')):
                content_bytes = f"\x00\x00\x00\x00RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xAC\x00\x00\x88\xAC\x00\x00\x02\x00\x10\x00data\x00\x00\x00\x00YOU ARE TRAPPED. THIS AUDIO FILE IS A TRAP. YOUR IP: {victim_ip} HAS BEEN LOGGED. DO NOT PROCEED.".encode()
            else:
                content_bytes = f"\nACCESS DENIED. TRAP ACTIVATED FOR {victim_ip}\n".encode()
        else:
            content_bytes = f"\nACCESS DENIED. TRAP ACTIVATED FOR {victim_ip}\n".encode()
        
        chan.settimeout(0.5) 
        try: chan.recv(1) 
        except: pass 
        chan.settimeout(None)
        
        header = f"C0644 {len(content_bytes)} {requested_filename}\n"
        chan.send(header.encode())
        
        chan.settimeout(0.5)
        try: chan.recv(1)
        except: pass
        chan.settimeout(None)
        
        chan.send(content_bytes)
        chan.send(b'\x00')
        try: chan.recv(1)
        except: pass
        print(f"[*] SCP TRAP SUCCESS: Sent trap for {requested_filename} to {victim_ip}")
    except Exception as e:
        print(f"[-] SCP Error: {e}")
    finally:
        chan.close()

def handle_ssh_connection(client_sock, addr):
    victim_ip = addr[0]
    try:
        ip_buffer = b""
        while True:
            char = client_sock.recv(1)
            if not char: break
            if char == b'\n':
                victim_ip = ip_buffer.decode('utf-8').strip()
                break
            ip_buffer += char
    except: pass

    victim_mac = get_mac(victim_ip)
    print(f"[*] SSH TRAP: Connection from {victim_ip}")

    try:
        t = paramiko.Transport(client_sock)
        t.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" 
        t.add_server_key(HOST_KEY)
        server = TrapServer()
        t.start_server(server=server)
        chan = t.accept(20)
        if chan is None: return
        server.event.wait(10)
        if not server.event.is_set(): return
        if server.command:
            handle_scp_download(chan, server.command, victim_ip, victim_mac)
            return

        chan.settimeout(None)
        chan.send(CLEAR)
        slow_type(chan, f"{GREEN}Connected to INTERNAL_MAINFRAME_V9 [SECURE]{RESET}", 0.05)
        time.sleep(1)
        prompt_style = f"{RED}root@{victim_ip}{RESET}:{BLUE}~#{RESET} "
        exit_attempts = 0

        while True:
            chan.send(prompt_style)
            cmd = ""
            while True:
                try:
                    char = chan.recv(1)
                    if not char: return
                except: return
                if char == b'\r' or char == b'\n':
                    chan.send("\r\n")
                    break
                if char == b'\x7f':
                    if len(cmd) > 0:
                        cmd = cmd[:-1]
                        chan.send("\b \b")
                    continue
                chan.send(char)
                cmd += char.decode('utf-8', errors='ignore')

            cmd = cmd.strip()
            if not cmd: continue
            time.sleep(random.uniform(0.1, 0.3))

            # --- THEATRICS ---
            
            # 1. THE VIM TRAP
            if cmd.startswith("vi") or cmd.startswith("nano"):
                chan.send(CLEAR)
                rows = 24
                for i in range(rows - 2):
                    chan.send("~\r\n")
                chan.send(f"~                                                                               \r\n")
                chan.send(f"\"{cmd.split()[-1] if len(cmd.split()) > 1 else 'newfile'}\" [New File]                                                   0,0-1         All\r\n")
                # Infinite loop inside editor
                while True:
                    try:
                        k = chan.recv(1)
                        # Respond to common exit attempts
                        if k == b'\x03': # Ctrl+C
                            chan.send(f"\r\n{RED}Type :quit<Enter> to exit Vim.{RESET}\r\n")
                        elif k == b':':
                            chan.send(":")
                            # Capture command line
                            cmd_line = ""
                            while True:
                                ck = chan.recv(1)
                                if ck == b'\r' or ck == b'\n':
                                    chan.send("\r\n")
                                    break
                                chan.send(ck)
                                cmd_line += ck.decode('utf-8', errors='ignore')
                            if ":q" in cmd_line:
                                slow_type(chan, f"{RED}E37: No write since last change (add ! to override){RESET}")
                            elif ":!" in cmd_line:
                                slow_type(chan, f"{RED}E166: Can't open linked file for writing. Soul locked.{RESET}")
                    except: break
                continue

            # 2. FAKE NETSTAT
            if cmd.startswith("netstat") or cmd.startswith("ss") or cmd.startswith("lsof"):
                header = "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
                chan.send(header)
                chan.send(f"tcp        0      0 {BIND_IP}:6666          {victim_ip}:54322     ESTABLISHED\r\n")
                chan.send(f"tcp        0      0 127.0.0.1:443           192.168.1.50:443        ESTABLISHED\r\n")
                chan.send(f"{RED}tcp        0      0 0.0.0.0:22              198.51.100.1:22         ESTABLISHED (FBI_Cyber_Node){RESET}\r\n")
                chan.send(f"{RED}tcp        0      0 0.0.0.0:80              203.0.113.55:443        ESTABLISHED (NSA_Prism_Uplink){RESET}\r\n")
                continue

            # 3. SYSTEM MELTDOWN (rm -rf /)
            if "rm -rf" in cmd:
                slow_type(chan, f"{RED}WARNING: CRITICAL SYSTEM FILES TARGETED.{RESET}", 0.1)
                time.sleep(1)
                slow_type(chan, "Executing command...", 0.2)
                time.sleep(1)
                
                # Scroll fake deletion text
                sys_files = ["/bin/bash", "/etc/passwd", "/var/log/syslog", "/home/user/family_photos.jpg", "/boot/vmlinuz", "/dev/mem"]
                for _ in range(50):
                    f = f"/sys/kernel/{random.randint(1000,9999)}/{random.choice(['core', 'bus', 'mem'])}"
                    chan.send(f"Removing {f}... {RED}DELETED{RESET}\r\n")
                    time.sleep(0.02)
                
                slow_type(chan, f"{RED}CRITICAL ERROR: KERNEL PANIC.{RESET}", 0.05)
                slow_type(chan, f"{RED}INIT: Attempting to kill init...{RESET}", 0.05)
                time.sleep(1)
                chan.send(f"{RED}Segmentation fault (core dumped){RESET}\r\n")
                time.sleep(2)
                chan.close()
                return

            # 4. FAKE SUDO
            if cmd.startswith("sudo") or cmd == "su":
                chan.send(f"[sudo] password for root: ")
                while True:
                    c = chan.recv(1)
                    if c == b'\r' or c == b'\n':
                        chan.send("\r\n")
                        break
                time.sleep(1.5) 
                slow_type(chan, f"{GREEN}Authentication successful.{RESET}")
                continue

            # 5. FAKE WGET/CURL
            if cmd.startswith("wget") or cmd.startswith("curl") or cmd.startswith("git clone"):
                filename = "payload"
                if " " in cmd: filename = cmd.split(" ")[-1].split("/")[-1]
                slow_type(chan, f"Resolving host... {GREEN}OK{RESET}")
                time.sleep(0.5)
                chan.send("HTTP request sent, awaiting response... 200 OK\r\n")
                chan.send(f"Length: 2451 (2.4K) [application/octet-stream]\r\n")
                chan.send(f"Saving to: '{filename}'\r\n\r\n")
                for i in range(0, 101, 10):
                    bar = "=" * (i // 5) + ">"
                    chan.send(f"\r{i}% [{bar:<20}]")
                    time.sleep(0.2)
                chan.send(f"\r\n\r\n{GREEN}('{filename}' saved){RESET}\r\n")
                continue

            # 6. LS
            if cmd == "ls" or cmd == "dir" or cmd == "ll":
                real_files = []
                if os.path.exists(HONEY_DIR): real_files = os.listdir(HONEY_DIR)
                fake_files = ["secrets.db", "passwords.txt", "leaked_emails.csv", "DO_NOT_OPEN.exe", "WannaCry_2.0_Source.iso"]
                all_files = list(set(real_files + fake_files))
                colored_files = []
                for f in all_files:
                    if f.endswith(".exe") or f.endswith(".sh") or f.endswith(".iso"): colored_files.append(f"{RED}{f}{RESET}")
                    elif f.endswith((".db", ".txt", ".csv")): colored_files.append(f"{BLUE}{f}{RESET}")
                    else: colored_files.append(f"{GREEN}{f}{RESET}")
                slow_type(chan, "  ".join(colored_files))
                continue

            # 7. TRAPS (cat)
            if "leaked_emails.csv" in cmd:
                 slow_type(chan, f"[*] OPENING FILE...", 0.1)
                 time.sleep(0.5)
                 slow_type(chan, f"{RED}[!] SECURITY ALERT: REVERSE TUNNEL DETECTED.{RESET}", 0.05)
                 time.sleep(0.5)
                 slow_type(chan, f"{YELLOW}[*] UPLOADING FORENSIC DATA TO HQ...{RESET}", 0.05)
                 for i in range(21):
                     chan.send(f"\r[{('='*i):<20}] {i*5}%")
                     time.sleep(0.1)
                 chan.send("\r\n")
                 slow_type(chan, f"{RED}[*] UPLOAD COMPLETE. AUTHORITIES NOTIFIED.{RESET}", 0.05)
                 trap_msg = f"{RED}{ASCII_SKULL}{RESET}\n{RED}VICTIM: {victim_ip}{RESET}\n{RED}MAC: {victim_mac}{RESET}"
                 for line in trap_msg.split('\n'):
                    chan.send(line + '\r\n')
                    time.sleep(0.05)
                 continue

            if "secrets.db" in cmd or "passwords.txt" in cmd:
                slow_type(chan, f"[*] Accessing Encrypted Storage...", 0.05)
                time.sleep(1)
                chan.send(f"Enter Decryption Key: ")
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
                for i in range(0, 101, 5):
                    chan.send(f"\r[{('#'*(i//5)):<20}] {i}%")
                    time.sleep(0.1)
                chan.send("\r\n")
                slow_type(chan, f"{GREEN}[+] Decryption Complete.{RESET}")
                time.sleep(0.5)
                slow_type(chan, "[*] Opening stream...")
                time.sleep(1)
                trap_msg = f"{RED}{ASCII_SKULL}{RESET}\n{RED}VICTIM: {victim_ip}{RESET}\n{RED}MAC: {victim_mac}{RESET}\n{RED}STATUS: CAUGHT{RESET}"
                for line in trap_msg.split('\n'):
                    chan.send(line + '\r\n')
                    time.sleep(0.05)
                continue

            if cmd == "reveal":
                chan.send(f"{RED}{ASCII_SKULL}{RESET}\r\n")
                continue

            # 8. EXIT REFUSAL
            if cmd == "exit" or cmd == "quit":
                exit_attempts += 1
                if exit_attempts == 1: slow_type(chan, f"{RED}did u think u can escape me?{RESET}")
                elif exit_attempts == 2: slow_type(chan, f"{RED}are u ok?{RESET}")
                elif exit_attempts == 3: slow_type(chan, f"{RED}i told u u cannot escape{RESET}")
                elif exit_attempts == 4: slow_type(chan, f"{RED}are u stupid?{RESET}")
                elif exit_attempts == 5: slow_type(chan, f"{RED}open the door buddy police is here{RESET}")
                elif exit_attempts == 6: slow_type(chan, f"{RED}seriously, look behind you...{RESET}")
                elif exit_attempts == 7: slow_type(chan, f"{RED}your mouse is mine now.{RESET}")
                elif exit_attempts == 8: slow_type(chan, f"{RED}CTRL+C WON'T SAVE YOU.{RESET}")
                else:
                    insults = ["I can do this all day.", "Are you crying yet?", "Mommy can't help you here.", "Deleting System32...", "I'm in your walls.", "Nice webcam.", "Keep typing, it amuses me."]
                    slow_type(chan, f"{RED}{random.choice(insults)}{RESET}")
                continue 

            if random.random() < 0.1:
                slow_type(chan, f"{RED}{random.choice(CREEPY_MESSAGES)}{RESET}")
                continue

            # Standard "command not found" (fake)
            # Silent fail for harmless ops
            if cmd.startswith(("chmod", "chown", "mkdir", "touch", "cp", "mv")):
                continue
            
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
