#!/usr/bin/env python3

import socket
import threading
import time
import json
import random
from datetime import datetime


class FakeSSHServer:
    def __init__(self, port=22):
        self.port = port
        self.running = False
        self.server_socket = None
        self.attempts = []

        # Fake SSH version banner
        self.ssh_banner = (
            "SSH-2.0-OpenSSH_7.2p2 Ubuntu-14.04.1 (OpenSSH_7.2p2 Ubuntu-14.04.1)"
        )

        # Fake user database with weak credentials
        self.fake_users = {
            "admin": "admin",
            "root": "123456",
            "user": "password",
            "test": "test",
            "guest": "guest",
            "ftp": "ftp",
            "ssh": "ssh",
        }

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            print(f"🔐 Fake SSH Server listening on port {self.port}")

            while self.running:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()

        except Exception as e:
            print(f"❌ Failed to start SSH server: {e}")

    def handle_client(self, client_socket, addr):
        try:
            # Send SSH banner
            client_socket.send(f"{self.ssh_banner}\r\n".encode())
            print(f"🔐 SSH Connection from {addr[0]} - Sending weak banner")

            # Simulate SSH authentication prompts
            self.ssh_handshake(client_socket, addr)

        except Exception as e:
            print(f"❌ SSH client error: {e}")
        finally:
            client_socket.close()

    def ssh_handshake(self, client_socket, addr):
        try:
            # Wait for client identification
            time.sleep(1)

            # Send authentication request
            client_socket.send(b"root@example.com's password: ")

            # Read login attempt
            data = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()

            if data:
                # Log attempt
                attempt = {
                    "timestamp": datetime.now().isoformat(),
                    "ip": addr[0],
                    "service": "SSH",
                    "username": "root",
                    "password": data,
                    "port": self.port,
                    "weak_login": True,
                }
                self.attempts.append(attempt)

                print(f"🔐 SSH LOGIN ATTEMPT: {addr[0]} - root:{data}")

                # Simulate weak password acceptance sometimes (honeypot behavior)
                if data in ["admin", "123456", "password", "test", "guest"]:
                    time.sleep(1)
                    client_socket.send(
                        b"Access granted! Welcome to vulnerable SSH server!\n"
                    )
                    self.simulate_compromised_shell(client_socket, addr, data)
                else:
                    time.sleep(1)
                    client_socket.send(b"Access denied\r\n")

        except Exception as e:
            print(f"❌ SSH handshake error: {e}")

    def simulate_compromised_shell(self, client_socket, addr, password):
        try:
            print(f"🚨 FAKE SHELL OPENED: {addr[0]} compromised with {password}")

            # Fake shell prompt
            client_socket.send(b"root@vulnerable-server:~# ")

            # Let attacker try commands
            while self.running:
                try:
                    cmd = (
                        client_socket.recv(1024)
                        .decode("utf-8", errors="ignore")
                        .strip()
                    )
                    if not cmd:
                        client_socket.send(b"root@vulnerable-server:~# ")
                        continue

                    print(f"💻 FAKE COMMAND: {addr[0]} executed: {cmd}")

                    # Log the command
                    command_log = {
                        "timestamp": datetime.now().isoformat(),
                        "ip": addr[0],
                        "service": "SSH",
                        "password": password,
                        "command": cmd,
                        "fake_shell": True,
                    }
                    self.attempts.append(command_log)

                    # Generate fake responses
                    response = self.generate_fake_command_response(cmd)
                    if response:
                        time.sleep(random.uniform(0.5, 2.0))  # Simulate processing time
                        if isinstance(response, str):
                            response = response.encode("utf-8")
                        client_socket.send(response)
                        client_socket.send(b"\nroot@vulnerable-server:~# ")

                except Exception as e:
                    break

        except Exception as e:
            print(f"❌ Fake shell error: {e}")

    def generate_fake_command_response(self, cmd):
        responses = {
            "whoami": "root",
            "id": "uid=0(root) gid=0(root)",
            "uname -a": "Linux vulnerable-server 4.15.0 #1 SMP Ubuntu 4.15.0-generic",
            "ls": "file1.txt  file2.txt  secrets.sh  backup.tar.gz",
            "ps aux": "root       1  0.0  0.1   1234   pts/0    Ss   00:00:00 sshd",
            "cat /etc/passwd": "root:x:0:0:root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash",
            "wget": "Downloading malware... Done.",
            "curl": "Transfer complete... 1 file downloaded.",
            "nc -l": "Listening on port 4444...",
            "chmod +x": "Permissions updated.",
            "./": "Executing script... Malware installed!",
        }

        for pattern, response in responses.items():
            if pattern in cmd:
                return response

        # Generic responses for unknown commands
        if "sudo" in cmd:
            return "[sudo] password for root: "
        elif "cd" in cmd:
            return ""
        elif cmd in ["clear", "reset"]:
            return ""
        else:
            return "bash: " + cmd.split()[0] + ": command not found"

    def get_attempts(self):
        return self.attempts

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class FakeFTPServer:
    def __init__(self, port=21):
        self.port = port
        self.running = False
        self.server_socket = None
        self.attempts = []

        # Fake FTP welcome message
        self.ftp_banner = "220 (vsFTPd 3.0.2) ready...\r\n"

        # Fake anonymous access with fake files
        self.fake_files = [
            "backup.zip",
            "secrets.tar.gz",
            "passwords.txt",
            "config.php",
            "database.sql",
            "admin_panel.html",
        ]

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            print(f"📂 Fake FTP Server listening on port {self.port}")

            while self.running:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()

        except Exception as e:
            print(f"❌ Failed to start FTP server: {e}")

    def handle_client(self, client_socket, addr):
        try:
            # Send FTP banner
            client_socket.send(self.ftp_banner.encode())
            print(f"📂 FTP Connection from {addr[0]} - Sending vulnerable banner")

            self.ftp_session(client_socket, addr)

        except Exception as e:
            print(f"❌ FTP client error: {e}")
        finally:
            client_socket.close()

    def ftp_session(self, client_socket, addr):
        try:
            # Wait for USER command
            data = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
            if "USER" in data:
                username = data.split()[-1] if len(data.split()) > 1 else "anonymous"
                print(f"📂 FTP LOGIN: {addr[0]} - user: {username}")

                # Send password request
                client_socket.send(b"331 Password required\r\n")

                # Wait for PASS command
                pass_data = (
                    client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
                )
                if "PASS" in pass_data:
                    password = (
                        pass_data.split()[-1] if len(pass_data.split()) > 1 else ""
                    )
                    print(f"📂 FTP PASSWORD: {addr[0]} - pass: {password}")

                    # Log attempt
                    attempt = {
                        "timestamp": datetime.now().isoformat(),
                        "ip": addr[0],
                        "service": "FTP",
                        "username": username,
                        "password": password,
                        "port": self.port,
                        "anonymous_access": username == "anonymous",
                    }
                    self.attempts.append(attempt)

                    # Always grant access (honeypot behavior)
                    client_socket.send(b"230 Login successful\r\n")
                    self.fake_ftp_directory(client_socket, addr)

        except Exception as e:
            print(f"❌ FTP session error: {e}")

    def fake_ftp_directory(self, client_socket, addr):
        try:
            # Show fake directory listing
            file_list = ""
            for filename in self.fake_files:
                size = random.randint(1024, 10485760)  # Random file sizes
                date = datetime.now().strftime("%b %d %H:%M")
                file_list += f"-rw-r--r-- 1 root root {size:>8} {date} {filename}\r\n"

            client_socket.send(b"150 Opening data connection\r\n")
            client_socket.send(f"226 Transfer complete\r\n{file_list}".encode())

            # Log file access
            for filename in self.fake_files:
                access_log = {
                    "timestamp": datetime.now().isoformat(),
                    "ip": addr[0],
                    "service": "FTP",
                    "action": "file_access",
                    "filename": filename,
                    "fake_file": True,
                }
                self.attempts.append(access_log)
                print(f"📂 FAKE FILE ACCESSED: {addr[0]} - {filename}")

        except Exception as e:
            print(f"❌ Fake FTP directory error: {e}")

    def get_attempts(self):
        return self.attempts

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class HoneypotManager:
    def __init__(self):
        self.ssh_server = FakeSSHServer()
        self.ftp_server = FakeFTPServer()
        self.all_attempts = []
        self.running = False

    def start(self):
        self.running = True
        print("🍯 STARTING HONEYPOT SERVICES")
        print("🔐 Deploying fake SSH server (port 22)")
        print("📂 Deploying fake FTP server (port 21)")
        print("🎯 Ready to trap attackers!")
        print("=" * 50)

        # Start both servers in separate threads
        ssh_thread = threading.Thread(target=self.ssh_server.start)
        ftp_thread = threading.Thread(target=self.ftp_server.start)

        ssh_thread.daemon = True
        ftp_thread.daemon = True

        ssh_thread.start()
        ftp_thread.start()

        try:
            while self.running:
                time.sleep(1)

                # Collect all attempts periodically
                self.all_attempts.extend(self.ssh_server.get_attempts())
                self.all_attempts.extend(self.ftp_server.get_attempts())

                # Clear server logs to prevent duplicates
                self.ssh_server.attempts = []
                self.ftp_server.attempts = []

        except KeyboardInterrupt:
            print("\n🛑 Shutting down honeypots...")
            self.stop()

    def stop(self):
        self.running = False
        self.ssh_server.stop()
        self.ftp_server.stop()

        # Save all attempts to file
        self.save_attacks_log()
        print("📝 Attack attempts saved to honeypot_attacks.json")

    def save_attacks_log(self):
        try:
            with open("honeypot_attacks.json", "w") as f:
                json.dump(self.all_attempts, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save attacks log: {e}")

    def get_stats(self):
        ssh_attacks = len([a for a in self.all_attempts if a.get("service") == "SSH"])
        ftp_attacks = len([a for a in self.all_attempts if a.get("service") == "FTP"])
        unique_ips = len(set(a.get("ip") for a in self.all_attempts))

        return {
            "total_attacks": len(self.all_attempts),
            "ssh_attacks": ssh_attacks,
            "ftp_attacks": ftp_attacks,
            "unique_attackers": unique_ips,
            "compromised_shells": len(
                [a for a in self.all_attempts if a.get("fake_shell")]
            ),
            "file_accesses": len([a for a in self.all_attempts if a.get("fake_file")]),
        }


if __name__ == "__main__":
    honeypot = HoneypotManager()

    print("🍯 HONEYPOT MANAGER - FAKE SERVICES")
    print("🎯 Ready to engage with detected scanners!")
    print("=" * 50)
    print("Services:")
    print("  🔐 SSH (port 22) - Weak credentials, fake shell")
    print("  📂 FTP (port 21) - Anonymous access, fake files")
    print("=" * 50)
    print("Press Ctrl+C to stop and save attack logs")
    print()

    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.stop()

        # Display statistics
        stats = honeypot.get_stats()
        print(f"\n📊 HONEYPOT STATISTICS:")
        print(f"  🎯 Total Attacks: {stats['total_attacks']}")
        print(f"  🔐 SSH Attempts: {stats['ssh_attacks']}")
        print(f"  📂 FTP Attempts: {stats['ftp_attacks']}")
        print(f"  👥 Unique Attackers: {stats['unique_attackers']}")
        print(f"  💻 Shells Compromised: {stats['compromised_shells']}")
        print(f"  📁 Files Accessed: {stats['file_accesses']}")
        print("🍯 Honeypot data saved to honeypot_attacks.json")
