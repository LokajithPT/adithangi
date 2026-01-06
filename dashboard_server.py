import http.server
import socketserver
import json
import os

PORT = 8000
LOG_FILE = "ids_events.json"

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/dashboard.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        
        if self.path == '/events':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*') # Allow all
            self.end_headers()
            
            events = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                events.append(json.loads(line))
                            except:
                                pass
            
            # Return last 20 events
            self.wfile.write(json.dumps(events[-20:]).encode())
            return

        # Serve other static files (like css/js if added)
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

print(f"[*] Dashboard running at http://localhost:{PORT}")
with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
    httpd.serve_forever()
