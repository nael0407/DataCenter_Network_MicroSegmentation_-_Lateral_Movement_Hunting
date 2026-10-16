#!/usr/bin/env python3
"""
workloads/mock-app/app_server.py
Application Tier Mock Service (app1: 10.10.20.11:8080, app2: 10.10.20.12:8080)
Menerima request HTTP dari Web Tier dan melakukan query TCP ke Database Tier (db1: 10.10.30.11:5432).
"""
import http.server
import socketserver
import socket
import json
import time
import sys

HOST = "0.0.0.0"
PORT = 8080
DB_HOST = "10.10.30.11"
DB_PORT = 5432

def query_database(query="SELECT * FROM accounts"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((DB_HOST, DB_PORT))
        s.sendall(query.encode('utf-8'))
        raw = s.recv(4096)
        return json.loads(raw.decode('utf-8'))
    except Exception as e:
        return {"error": str(e), "status": "db_unreachable"}
    finally:
        s.close()

class AppHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stdout.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.client_address[0]} - {format%args}\n")
        sys.stdout.flush()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "tier": "app"}).encode('utf-8'))
            return

        # Query backend Database Tier
        db_res = query_database()
        status_code = 200 if db_res.get("status") == "ok" else 503

        response = {
            "status": "ok" if status_code == 200 else "degraded",
            "tier": "application",
            "node": socket.gethostname(),
            "client": self.client_address[0],
            "database_backend": f"{DB_HOST}:{DB_PORT}",
            "database_response": db_res,
            "timestamp": time.time()
        }

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def main():
    server = ThreadedHTTPServer((HOST, PORT), AppHandler)
    print(f"[*] Application Tier Mock Server berjalan di http://{HOST}:{PORT}")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
