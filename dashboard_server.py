import http.server
import socketserver
import json
import os
import time
import re
import random 

PORT = 8000
LOG_FILE = "honeypot.log"
CREDS_FILE = "captured_creds.csv"

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/dashboard.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        
        # --- API: LOGS ---
        if self.path == '/api/logs':
            print(f"[*] /api/logs requested")
            data = self.get_logs()
            print(f"[*] Returning {len(data)} logs")
            self.send_json(data)
            return

        # --- API: CREDENTIALS ---
        if self.path == '/api/creds':
            self.send_json(self.get_creds())
            return

        # --- API: STATS ---
        if self.path == '/api/stats':
            self.send_json(self.get_stats())
            return

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def get_logs(self):
        logs = []
        if os.path.exists(LOG_FILE):
            try:
                # Open with errors='ignore' to handle binary garbage from attackers
                with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    # Parse standard log format: [Date Time] Service - IP - Message
                    for line in lines[-50:]: # Last 50
                        # Regex to capture: [timestamp] service - ip - message
                        # We use named groups for clarity
                        match = re.match(r'\[(?P<ts>.*?)\] (?P<service>\S+) - (?P<ip>[\d\.]+) - (?P<msg>.*)', line)
                        if match:
                            ts_parts = match.group('ts').split()
                            time_str = ts_parts[1] if len(ts_parts) > 1 else match.group('ts')
                            
                            logs.append({
                                "time": time_str,
                                "service": match.group('service'),
                                "ip": match.group('ip'),
                                "message": match.group('msg').strip()
                            })
                        else:
                            # Fallback for unparsed lines
                            logs.append({"time": "--:--:--", "service": "RAW", "ip": "-", "message": line.strip()})
            except Exception as e:
                print(f"[-] Error parsing logs: {e}")
        else:
            print(f"[-] Log file not found: {LOG_FILE}")
        return list(reversed(logs))

    def get_creds(self):
        creds = []
        if os.path.exists(CREDS_FILE):
            try:
                with open(CREDS_FILE, 'r') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) >= 4:
                            creds.append({
                                "time": parts[0],
                                "ip": parts[1],
                                "user": parts[2],
                                "pass": parts[3]
                            })
            except: pass
        return list(reversed(creds))

    def get_stats(self):
        total_attacks = 0
        unique_ips = set()
        
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    for line in f:
                        total_attacks += 1
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            unique_ips.add(ip_match.group(1))
            except: pass
            
        cred_count = 0
        if os.path.exists(CREDS_FILE):
            try:
                with open(CREDS_FILE, 'r') as f:
                    cred_count = sum(1 for line in f)
            except: pass

        return {
            "total_attacks": total_attacks,
            "unique_ips": len(unique_ips),
            "captured_creds": cred_count,
            "active_sessions": random.randint(0, 2) # Still simulated as we don't track live socket count in a file
        }

print(f"[*] REAL Dashboard running at http://localhost:{PORT}")
print(f"[*] Serving logs from: {LOG_FILE}")
print(f"[*] Serving creds from: {CREDS_FILE}")

# Ensure socket reuse to avoid "Address already in use"
class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReusableTCPServer(("", PORT), DashboardHandler) as httpd:
    httpd.serve_forever()
