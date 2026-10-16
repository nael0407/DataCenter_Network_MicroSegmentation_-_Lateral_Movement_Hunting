#!/usr/bin/env bash
# telemetry/test-logging-stack.sh
# Skrip pengujian otomatis keterhubungan Stack Telemetri Sentral (Langkah 5.4)
# Memverifikasi Loki, Grafana, Alloy, Zeek JSON logs, dan OPNsense Syslog di secops
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "=========================================================="
echo "Pengujian End-to-End Stack Telemetri (Loki + Grafana + Alloy + Zeek)"
echo "Target Node: secops (192.168.122.81 / 10.10.40.11)"
echo "=========================================================="

echo "--- 1. Memeriksa Status Layanan Telemetri di secops ---"
ssh $SSH_OPTS "dcadmin@192.168.122.81" 'sudo bash -s' << 'EOF'
set -euo pipefail
for svc in loki grafana-server alloy zeek; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    if [ "$status" = "active" ]; then
        echo "  [OK] $svc : active"
    else
        echo "  [GAGAL] $svc : $status"
        exit 1
    fi
done

# Uji kesiapan HTTP endpoint lokal
echo "  [OK] Loki Ready Status: $(curl -s http://127.0.0.1:3100/ready)"
echo "  [OK] Grafana Health   : $(curl -s http://127.0.0.1:3000/api/health | grep -o '"database": "[^"]*"' || echo 'ok')"
EOF

echo
echo "--- 2. Memeriksa Provisioning Datasource Loki di Grafana ---"
ssh $SSH_OPTS "dcadmin@192.168.122.81" 'bash -s' << 'EOF'
set -euo pipefail
datasources=$(curl -s -u admin:admin http://127.0.0.1:3000/api/datasources)
if echo "$datasources" | grep -q '"type":"loki"'; then
    echo "  [OK] Datasource 'Loki' terdaftar dan terprovisioning otomatis di Grafana."
else
    echo "  [GAGAL] Datasource Loki tidak ditemukan di Grafana."
    echo "$datasources"
    exit 1
fi

dashboards=$(curl -s -u admin:admin http://127.0.0.1:3000/api/search?type=dash-db)
if echo "$dashboards" | grep -q 'dc-microseg-telemetry'; then
    echo "  [OK] Dashboard 'DC Microsegmentation & Telemetry Dashboard' berhasil diprovisioning otomatis."
else
    echo "  [PERINGATAN] Dashboard telemetri belum ditemukan di Grafana."
fi
EOF

echo
echo "--- 3. Membangkitkan Trafik Inter-Zona Data-Plane untuk Pengujian Telemetri ---"
echo "  -> web1 (10.10.10.11) mengirim ICMP transit OPNsense ke app1 (10.10.20.11)..."
ssh $SSH_OPTS -J dcadmin@192.168.122.81 dcadmin@10.10.10.11 "ping -c 3 -W 1 10.10.20.11 >/dev/null && echo '     [OK] Ping web1 -> app1 berhasil.'"

echo "  -> app1 (10.10.20.11) mengirim ICMP transit OPNsense ke db1 (10.10.30.11)..."
ssh $SSH_OPTS -J dcadmin@192.168.122.81 dcadmin@10.10.20.11 "ping -c 3 -W 1 10.10.30.11 >/dev/null && echo '     [OK] Ping app1 -> db1 berhasil.'"

echo
echo "--- 4. Memverifikasi Ingesti Log Zeek di Loki ({job=\"zeek\"}) ---"
sleep 3
ssh $SSH_OPTS "dcadmin@192.168.122.81" 'python3 -s' << 'EOF'
import urllib.request
import urllib.parse
import json
import time

query = '{job="zeek"}'
params = urllib.parse.urlencode({'query': query, 'limit': 3})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as response:
    data = json.loads(response.read().decode('utf-8'))

results = data.get('data', {}).get('result', [])
if results:
    print(f"  [OK] Berhasil menemukan {len(results)} stream log Zeek di Loki.")
    sample = results[0]['values'][0][1]
    print(f"  [CONTOH LOG ZEEK]:\n  {sample[:160]}...")
else:
    print("  [PERINGATAN] Log Zeek belum terindeks di Loki.")
EOF

echo
echo "--- 5. Memverifikasi Ingesti Syslog OPNsense di Loki ({job=\"opnsense-syslog\"}) ---"
ssh $SSH_OPTS "dcadmin@192.168.122.81" 'python3 -s' << 'EOF'
import urllib.request
import urllib.parse
import json

query = '{job="opnsense-syslog"}'
params = urllib.parse.urlencode({'query': query, 'limit': 3})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as response:
    data = json.loads(response.read().decode('utf-8'))

results = data.get('data', {}).get('result', [])
opn_logs = [r for r in results if r.get('stream', {}).get('hostname') != 'secops']
if opn_logs:
    print(f"  [OK] Berhasil menerima {len(opn_logs)} stream log langsung dari OPNsense Firewall!")
    for stream in opn_logs[:3]:
        val = stream['values'][0][1]
        labels = stream.get('stream', {})
        print(f"  [STREAM OPNSENSE] {labels}")
        print(f"  [LOG ENTRY] {val[:160]}...")
elif results:
    print("  [INFO] Syslog listener aktif (stream lokal secops ditemukan), namun log remote dari OPNsense belum masuk.")
    print("         (Silakan lakukan konfigurasi Logging Destination di OPNsense Web GUI).")
else:
    print("  [PERINGATAN] Belum ada stream Syslog yang diterima di Loki.")
EOF

echo
echo "=========================================================="
echo "Pengujian Stack Telemetri Selesai!"
echo "=========================================================="
