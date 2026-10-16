#!/usr/bin/env python3
"""
workloads/mock-app/web_server.py
Web Tier Mock Service (web1: 10.10.10.11:80, web2: 10.10.10.12:80)
Menerima request HTTP dari client/eksternal dan melakukan panggilan HTTP ke App Tier (app1/app2:8080).
"""
import http.server
import socketserver
import urllib.request
import urllib.error
import socket
import json
import time
import sys
import random

HOST = "0.0.0.0"
PORT = 80
APP_NODES = ["10.10.20.11:8080", "10.10.20.12:8080"]

def call_app_tier():
    # Pilih salah satu node App Tier secara acak/seimbang
    target = random.choice(APP_NODES)
    url = f"http://{target}/"
    req = urllib.request.Request(url, headers={"User-Agent": f"WebTier/{socket.gethostname()}"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return {"target": target, "status": "ok", "data": data}
    except Exception as e:
        return {"target": target, "status": "error", "error": str(e)}

class WebHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stdout.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.client_address[0]} - {format%args}\n")
        sys.stdout.flush()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "tier": "web"}).encode('utf-8'))
            return

        # Panggil Application Tier
        app_res = call_app_tier()
        status_code = 200 if app_res.get("status") == "ok" else 502

        response = {
            "status": "ok" if status_code == 200 else "upstream_error",
            "tier": "web",
            "node": socket.gethostname(),
            "client_ip": self.client_address[0],
            "app_tier_result": app_res,
            "timestamp": time.time()
        }

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def main():
    server = ThreadedHTTPServer((HOST, PORT), WebHandler)
    print(f"[*] Web Tier Mock Server berjalan di http://{HOST}:{PORT}")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
