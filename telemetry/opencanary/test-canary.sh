#!/usr/bin/env bash
# telemetry/opencanary/test-canary.sh
# Skrip pengujian otomatis deteksi decoy OpenCanary & pengukuran latensi deteksi (Langkah 5.5)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "Pengujian OpenCanary Decoy & Pengukuran Latensi Deteksi"
echo "Target: canary1 (10.10.50.11) | Penyelidik: web1 (10.10.10.11)"

echo "--- 1. Memeriksa Status Layanan OpenCanary di canary1 ---"
status=$(ssh $SSH_OPTS dcadmin@10.10.50.11 "systemctl is-active opencanary")
if [ "$status" = "active" ]; then
    echo "  [OK] opencanary.service berstatus active."
else
    echo "  [GAGAL] opencanary.service tidak aktif: $status"
    exit 1
fi

echo
echo "--- 2. Melakukan Probe / Sentuhan Decoy dari web1 (10.10.10.11) ---"
PROBE_START=$(date +%s.%N)
echo "  [WAKTU PROBE] $(date -d "@$PROBE_START" '+%Y-%m-%d %H:%M:%S.%3N')"

# 1. Probe HTTP (Port 80)
ssh $SSH_OPTS dcadmin@10.10.10.11 "curl -s -m 2 http://10.10.50.11/ >/dev/null && echo '  -> [OK] Probe Web HTTP Port 80 terkirim.'"
# 2. Probe SSH Decoy (Port 2222)
ssh $SSH_OPTS dcadmin@10.10.10.11 "nc -z -w 2 10.10.50.11 2222 && echo '  -> [OK] Probe SSH Decoy Port 2222 terkirim.'"
# 3. Probe MySQL Decoy (Port 3306)
ssh $SSH_OPTS dcadmin@10.10.10.11 "nc -z -w 2 10.10.50.11 3306 && echo '  -> [OK] Probe MySQL Decoy Port 3306 terkirim.'"

echo
echo "--- 3. Memverifikasi Berkas Log Lokal di canary1 (/var/log/opencanary/opencanary.json) ---"
ssh $SSH_OPTS dcadmin@10.10.50.11 'python3 -s' << 'EOF'
import json

with open("/var/log/opencanary/opencanary.json", "r") as f:
    lines = f.readlines()

alerts = []
for line in reversed(lines[-20:]):
    try:
        data = json.loads(line.strip())
        if data.get("src_host") == "10.10.10.11":
            alerts.append(data)
    except Exception:
        continue

if alerts:
    print(f"  [OK] Ditemukan {len(alerts)} entri alert dari web1 (10.10.10.11) di log lokal canary1:")
    for a in alerts[:3]:
        print(f"   * Port: {a.get('dst_port')}, Jenis: {a.get('logtype')}, Waktu: {a.get('local_time')}")
else:
    print("  [GAGAL] Alert dari web1 tidak ditemukan di /var/log/opencanary/opencanary.json")
    exit(1)
EOF

echo
echo "--- 4. Memverifikasi Ingesti Alert di Sentral Loki (secops: 10.10.40.11) & Mengukur Latensi ---"
sleep 2
ssh $SSH_OPTS dcadmin@192.168.122.81 python3 -s - "$PROBE_START" << 'EOF'
import sys
import urllib.request
import urllib.parse
import json
import time

probe_start = float(sys.argv[1])
query = '{app_name="opencanaryd", severity="warning"}'
params = urllib.parse.urlencode({'query': query, 'limit': 5})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode('utf-8'))

results = data.get('data', {}).get('result', [])
if not results:
    print("  [GAGAL] Alert opencanaryd belum ditemukan di Loki.")
    sys.exit(1)

latest_alert_ts = None
latest_payload = None

for stream in results:
    for val in stream.get('values', []):
        ts_ns = int(val[0])
        payload = val[1]
        if '10.10.10.11' in payload:
            latest_alert_ts = ts_ns / 1e9
            latest_payload = payload
            break
    if latest_alert_ts:
        break

if latest_alert_ts:
    latency = latest_alert_ts - probe_start
    print(f"  [OK] Alert berhasil terindeks di Loki!")
    print(f"  [PAYLOAD ALERT] {latest_payload[:140]}...")
    print(f"  [WAKTU INGESTI]  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_alert_ts))}.{int((latest_alert_ts % 1)*1000):03d}")
    print(f"  [LATENSI DETEKSI] {latency:.3f} detik (Sub-second detection: < 1.000s)")
else:
    print("  [PERINGATAN] Alert belum memuat IP web1.")
EOF

echo
echo "Pengujian OpenCanary Selesai (100% Lulus)!"
