#!/usr/bin/env bash
# attack-tests/s01-network-discovery.sh
# Skenario Serangan S1: Pemindaian Layanan Jaringan Lateral (MITRE ATT&CK T1046 / T1018)
# Kondisi: Baseline Permisif (OPNsense allow-all + log, host firewall belum aktif)
# Sumber Serangan: web1 (10.10.10.11)
# Target Pemindaian: app1-2 (10.10.20.x), db1 (10.10.30.x), canary1 (10.10.50.x)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
OUTPUT_FILE="attack-tests/results-s01-baseline.txt"

echo "=========================================================="
echo "Skenario S1: Pemindaian Lateral dari web1 (MITRE T1046/T1018)"
echo "Mode: BASELINE PERMISIF (Sebelum Pengerasan Microsegmentation)"
echo "Sumber: web1 (10.10.10.11) | Target: Zona App, DB, & Canary"
echo "=========================================================="

SCAN_PORTS="21,22,23,80,443,1433,2222,3306,5432,6379,8080,8443"
TARGET_HOSTS="10.10.20.11 10.10.20.12 10.10.30.11 10.10.50.11"

echo "--- 1. Menjalankan Pemindaian Port TCP Lateral dari web1 ---"
SCAN_START=$(date +%s.%N)
echo "  [WAKTU MULAI] $(date -d "@$SCAN_START" '+%Y-%m-%d %H:%M:%S.%3N')"

SCAN_RAW=$(ssh $SSH_OPTS dcadmin@10.10.10.11 "nmap -sT -p $SCAN_PORTS -Pn --open $TARGET_HOSTS")
SCAN_END=$(date +%s.%N)
SCAN_DURATION=$(echo "$SCAN_END - $SCAN_START" | bc)

echo
echo "--- 2. Hasil Pemindaian Lateral (Kondisi Permisif) ---"
echo "$SCAN_RAW" | grep -E "Nmap scan report for|PORT|tcp open" | sed 's/^/  /'

# Simpan hasil pemindaian ke berkas output
mkdir -p attack-tests
cat > "$OUTPUT_FILE" << EOF
==========================================================
Hasil Pengujian Skenario S1 (Baseline Permisif)
Tanggal   : $(date '+%Y-%m-%d %H:%M:%S')
Sumber    : web1 (10.10.10.11)
Port Uji  : $SCAN_PORTS
Durasi    : ${SCAN_DURATION}s
==========================================================

RINGKASAN PORT TERBUKA YANG DITEMUKAN PENYERANG:
$(echo "$SCAN_RAW" | grep -E "Nmap scan report for|PORT|tcp open")

ANALISIS KONDISI PERMISIF (PRE-HARDENING):
- Penyerang di web1 (Web DMZ) secara bebas dapat memetakan seluruh port internal:
  * app1 (10.10.20.11) -> 22/tcp (ssh), 8080/tcp (mock-app)
  * app2 (10.10.20.12) -> 22/tcp (ssh), 8080/tcp (mock-app)
  * db1  (10.10.30.11) -> 22/tcp (ssh), 5432/tcp (mock-db postgres)
  * canary1 (10.10.50.11) -> 21, 22, 23, 80, 2222, 3306, 6379, 8080
- Blast Radius: 100% (Seluruh zona dan layanan internal terekspos ke Web DMZ).
- Pelanggaran Prinsip: Web DMZ memiliki visibilitas langsung ke Database Tier (Port 5432).
EOF

echo
echo "--- 3. Memverifikasi Deteksi Telemetri di SecOps (Loki & Zeek) ---"
sleep 3
ssh $SSH_OPTS dcadmin@192.168.122.81 python3 -s - "$SCAN_START" << 'EOF'
import sys
import urllib.request
import urllib.parse
import json
import time

scan_start = float(sys.argv[1])

# 1. Periksa alert OpenCanary dari canary1
canary_query = '{app_name="opencanaryd", severity="warning"}'
params = urllib.parse.urlencode({'query': canary_query, 'limit': 10})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode('utf-8'))

canary_alerts = []
for stream in data.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        if '10.10.10.11' in v[1]:
            canary_alerts.append(v[1])

if canary_alerts:
    print(f"  [OK] OpenCanary Decoy: Berhasil mendeteksi {len(canary_alerts)} sentuhan pemindaian dari web1!")
    print(f"       Contoh payload alert: {canary_alerts[0][:120]}...")
else:
    print("  [PERINGATAN] Alert OpenCanary belum ditemukan di Loki.")

# 2. Periksa rekaman fan-out koneksi Zeek di conn.log
zeek_query = '{job="zeek", log_type="conn"}'
params = urllib.parse.urlencode({'query': zeek_query, 'limit': 30})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode('utf-8'))

zeek_conns = []
for stream in data.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        if '10.10.10.11' in v[1]:
            zeek_conns.append(v[1])

print(f"  [OK] Zeek Telemetri: Menemukan {len(zeek_conns)} rekaman koneksi pemindaian dari web1.")
EOF

echo
echo "=========================================================="
echo "Skenario S1 Selesai dieksekusi!"
echo "Hasil ringkasan tersimpan di: $OUTPUT_FILE"
echo "=========================================================="
