#!/usr/bin/env python3
"""
workloads/traffic-generator.py
Generator Trafik Normal dengan Random Jitter & Aktivitas Administratif Berkala
Membangkitkan aliran trafik cascading 3-tier (Client -> Web -> App -> DB)
sebagai baseline realistis untuk deteksi anomali / hunting di Fase 6.
"""
import urllib.request
import urllib.error
import argparse
import random
import time
import json
import sys
import os

WEB_TARGETS = [
    "http://10.10.10.11/",
    "http://10.10.10.12/"
]

def make_web_request(url, timeout=5.0):
    start = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "EnterpriseClient/2.4 (AutomatedTrafficGenerator)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.time() - start) * 1000
            data = json.loads(resp.read().decode('utf-8'))
            return True, resp.status, elapsed, data
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return False, str(e), elapsed, None

def main():
    parser = argparse.ArgumentParser(description="3-Tier Workload Traffic Generator with Jitter")
    parser.add_argument("--count", type=int, default=0, help="Jumlah request (0 = berjalan terus menerus)")
    parser.add_argument("--targets", type=str, default="", help="Daftar URL target dipisahkan koma (default: web1, web2)")
    parser.add_argument("--min-interval", type=float, default=1.0, help="Interval minimum antar request dalam detik")
    parser.add_argument("--max-interval", type=float, default=3.5, help="Interval maksimum antar request dalam detik")
    parser.add_argument("--admin-interval", type=float, default=30.0, help="Interval aktivitas admin SSH berkala dalam detik")
    args = parser.parse_args()

    targets = [t.strip() for t in args.targets.split(",") if t.strip()] if args.targets else WEB_TARGETS

    print("==========================================================")
    print("3-Tier Workload Baseline Traffic Generator (Fase 5)")
    print(f"Target Web Tier : {', '.join(targets)}")
    print(f"Random Jitter   : {args.min_interval}s s/d {args.max_interval}s")
    print(f"Aktivitas Admin : Setiap ~{args.admin_interval}s")
    print("Tekan Ctrl+C untuk menghentikan generator.")
    print("==========================================================")
    sys.stdout.flush()

    req_num = 0
    success_count = 0
    fail_count = 0
    last_admin_time = time.time()

    try:
        while True:
            req_num += 1
            url = random.choice(targets)
            ok, status, latency_ms, data = make_web_request(url)

            now_str = time.strftime('%Y-%m-%d %H:%M:%S')
            if ok:
                success_count += 1
                web_node = data.get("node", "web?")
                app_tier = data.get("app_tier_result", {})
                app_node = app_tier.get("target", "app?")
                app_data = app_tier.get("data", {})
                db_res = app_data.get("database_response", {})
                db_node = db_res.get("node", "db?")

                chain_str = f"Web: {web_node} -> App: {app_node} -> DB: {db_node}"
                print(f"[{now_str}] [REQ #{req_num:04d}] {url} [{status}] ({chain_str}) - {latency_ms:.1f}ms")
            else:
                fail_count += 1
                print(f"[{now_str}] [REQ #{req_num:04d}] {url} [GAGAL: {status}] - {latency_ms:.1f}ms")
            sys.stdout.flush()

            # Simulasi aktivitas administratif berkala (SSH / management probe)
            if time.time() - last_admin_time >= args.admin_interval:
                print(f"  -> [{now_str}] [ADMIN-PULSE] Melakukan pengecekan rutin sistem via bastion...")
                last_admin_time = time.time()
                sys.stdout.flush()

            if args.count > 0 and req_num >= args.count:
                break

            jitter = random.uniform(args.min_interval, args.max_interval)
            time.sleep(jitter)

    except KeyboardInterrupt:
        print("\n[*] Generator trafik dihentikan oleh pengguna.")

    print(f"\n--- Ringkasan Generator Trafik ---")
    print(f"Total Request : {req_num}")
    print(f"Sukses        : {success_count}")
    print(f"Gagal         : {fail_count}")

if __name__ == "__main__":
    main()
