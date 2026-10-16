#!/usr/bin/env bash
# attack-tests/s02-lateral-ssh-movement.sh
# Skenario Serangan S2: Pergerakan Lateral Berantai SSH (MITRE ATT&CK T1021.004 / T1078)
# Kondisi: Baseline Permisif (OPNsense allow-all + log, host firewall belum aktif)
# Alur: web1 (DMZ) -> app1 (App Tier) -> db1 (Database Tier) & Direct Bypass (web1 -> db1)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
OUTPUT_FILE="attack-tests/results-s02-baseline.txt"
KEY_FILE="/tmp/compromised_id_ed25519"

echo "=========================================================="
echo "Skenario S2: Pergerakan Lateral Berantai SSH (MITRE T1021.004)"
echo "Mode: BASELINE PERMISIF (Sebelum Pengerasan Microsegmentation)"
echo "Rantai: web1 (10.10.10.11) -> app1 (10.10.20.11) -> db1 (10.10.30.11)"
echo "=========================================================="

# 1. Pastikan kunci uji compromised ada di web1
echo "--- 1. Memeriksa Kredensial Uji Kompromi di web1 ---"
if ! ssh $SSH_OPTS dcadmin@10.10.10.11 "test -f $KEY_FILE"; then
    echo "  -> Menyiapkan kunci uji di web1..."
    if [ ! -f /tmp/lateral_key ]; then
        ssh-keygen -t ed25519 -N "" -f /tmp/lateral_key -C "lateral-test-key"
        LAT_PUB=$(cat /tmp/lateral_key.pub)
        for ip in 10.10.10.11 10.10.20.11 10.10.30.11; do
            ssh $SSH_OPTS dcadmin@$ip "echo '$LAT_PUB' >> ~/.ssh/authorized_keys"
        done
    fi
    scp $SSH_OPTS /tmp/lateral_key dcadmin@10.10.10.11:$KEY_FILE
    ssh $SSH_OPTS dcadmin@10.10.10.11 "chmod 600 $KEY_FILE"
fi
echo "  [OK] Kredensial kompromi siap di $KEY_FILE"

echo
echo "--- 2. Mengeksekusi Lompatan Lateral Hop 1 (web1 -> app1:22) ---"
START_TIME=$(date +%s.%N)
HOP1_OUT=$(ssh $SSH_OPTS dcadmin@10.10.10.11 "ssh -i $KEY_FILE -o StrictHostKeyChecking=no dcadmin@10.10.20.11 'hostname && whoami'")
echo "  -> Hasil Hop 1: $(echo "$HOP1_OUT" | tr '\n' ' ')"

echo
echo "--- 3. Mengeksekusi Lompatan Berantai Hop 2 (web1 -> app1 -> db1:22) ---"
# Pastikan kunci tersedia di app1 untuk lompatan kedua
ssh $SSH_OPTS dcadmin@10.10.10.11 "scp -i $KEY_FILE -o StrictHostKeyChecking=no $KEY_FILE dcadmin@10.10.20.11:$KEY_FILE"
HOP2_OUT=$(ssh $SSH_OPTS dcadmin@10.10.10.11 "ssh -i $KEY_FILE -o StrictHostKeyChecking=no dcadmin@10.10.20.11 'ssh -i $KEY_FILE -o StrictHostKeyChecking=no dcadmin@10.10.30.11 hostname && whoami'")
echo "  -> Hasil Hop 2 (Berantai): $(echo "$HOP2_OUT" | tr '\n' ' ')"

echo
echo "--- 4. Mengeksekusi Lompatan Langsung / Bypass (web1 -> db1:22) ---"
DIRECT_OUT=$(ssh $SSH_OPTS dcadmin@10.10.10.11 "ssh -i $KEY_FILE -o StrictHostKeyChecking=no dcadmin@10.10.30.11 'hostname && whoami'")
echo "  -> Hasil Direct Jump: $(echo "$DIRECT_OUT" | tr '\n' ' ')"

# Simpan hasil pengujian ke berkas output
mkdir -p attack-tests
cat > "$OUTPUT_FILE" << EOF
==========================================================
Hasil Pengujian Skenario S2: Lateral Movement Berantai (Baseline)
Tanggal : $(date '+%Y-%m-%d %H:%M:%S')
Kondisi : Permisif (Pre-Hardening)
Kunci   : Ed25519 Compromised Decoy Key
==========================================================

STATUS LOMPATAN LATERAL:
1. Hop 1 (web1 -> app1:22)       : BERHASIL ($(echo "$HOP1_OUT" | tr '\n' ' '))
2. Hop 2 (web1 -> app1 -> db1:22) : BERHASIL ($(echo "$HOP2_OUT" | tr '\n' ' '))
3. Direct Jump (web1 -> db1:22)  : BERHASIL ($(echo "$DIRECT_OUT" | tr '\n' ' '))

ANALISIS KERENTANAN BASELINE:
- Dalam kondisi permisif, tidak ada segmentasi zona pada lapisan port SSH (Port 22).
- Penyerang yang menguasai web1 dapat melakukan pivoting berantai hingga ke database internal (db1).
- Penyerang bahkan dapat membypass tier aplikasi dan langsung mengakses db1 via SSH dari zona Web DMZ.
- Target Hardening (Fase 7):
  * Web DMZ dilarang melakukan koneksi SSH ke zona manapun (Drop).
  * Port 22 di seluruh workload hanya boleh menerima koneksi dari SecOps Bastion (10.10.40.11).
EOF

echo
echo "--- 5. Memverifikasi Deteksi Telemetri di SecOps (Zeek & Loki) ---"
sleep 3
ssh $SSH_OPTS dcadmin@192.168.122.81 python3 -s - "$START_TIME" << 'EOF'
import sys
import urllib.request
import urllib.parse
import json

start_ts = float(sys.argv[1])

# Periksa rekaman sesi SSH di Zeek conn.log
query = '{job="zeek", log_type="conn"} |= "22"'
params = urllib.parse.urlencode({'query': query, 'limit': 15})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode('utf-8'))

ssh_sessions = []
for stream in data.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        payload = v[1]
        if '10.10.10.11' in payload or '10.10.20.11' in payload:
            ssh_sessions.append(payload)

if ssh_sessions:
    print(f"  [OK] Zeek Telemetri: Menemukan {len(ssh_sessions)} rekaman sesi SSH lateral:")
    for s in ssh_sessions[:3]:
        print(f"       -> {s[:140]}...")
else:
    print("  [INFO] Menunggu agregasi log Zeek di Loki...")

# Periksa rekaman log sshd host
sshd_query = '{app_name="sshd"} |= "Accepted publickey"'
params = urllib.parse.urlencode({'query': sshd_query, 'limit': 5})
url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"
req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    sshd_data = json.loads(resp.read().decode('utf-8'))

sshd_events = []
for stream in sshd_data.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        sshd_events.append(v[1])

if sshd_events:
    print(f"  [OK] Host Syslog: Menemukan autentikasi SSH lateral di target ({len(sshd_events)} event):")
    print(f"       -> {sshd_events[0][:140]}...")
EOF

echo
echo "=========================================================="
echo "Skenario S2 Selesai dieksekusi!"
echo "Hasil ringkasan tersimpan di: $OUTPUT_FILE"
echo "=========================================================="
