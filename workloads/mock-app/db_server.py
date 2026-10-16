#!/usr/bin/env python3
"""
workloads/mock-app/db_server.py
Database Tier Mock Service (db1: 10.10.30.11:5432)
Menyimulasikan PostgreSQL database server yang melayani query dari App Tier.
"""
import socket
import threading
import json
import time
import sys

HOST = "0.0.0.0"
PORT = 5432

def handle_client(conn, addr):
    try:
        data = conn.recv(1024)
        query = data.decode('utf-8', errors='ignore').strip()
        response = {
            "status": "ok",
            "tier": "database",
            "service": "postgres-mock",
            "node": socket.gethostname(),
            "query_received": query if query else "SELECT * FROM core_accounts",
            "records_returned": 42,
            "latency_ms": 1.25,
            "timestamp": time.time()
        }
        payload = (json.dumps(response) + "\n").encode('utf-8')
        conn.sendall(payload)
        sys.stdout.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Query dari {addr[0]}:{addr[1]} -> OK (42 records)\n")
        sys.stdout.flush()
    except Exception as e:
        sys.stderr.write(f"Error handling client {addr}: {e}\n")
    finally:
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(128)
    print(f"[*] Database Mock Server mendengarkan di {HOST}:{PORT} (PID: {threading.get_native_id()})")
    sys.stdout.flush()

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    main()
