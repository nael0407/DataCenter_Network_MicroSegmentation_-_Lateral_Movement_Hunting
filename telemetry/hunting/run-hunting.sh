#!/usr/bin/env bash
# telemetry/hunting/run-hunting.sh
# Eksekusi Otomatis Threat Hunting Berbasis LogQL (Loki) & Analisis Graf (Pandas + NetworkX)
# Skenario S8: Deteksi Ancaman Berbasis Telemetri Tanpa Intervensi Firewall (Mode Deteksi Saja)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
OUTPUT_FILE="telemetry/hunting/results-hunting-baseline.txt"

echo "Skenario S8: Threat Hunting & Graph-based Baseline"
echo "Mode: BASELINE PERMISIF (Deteksi Telemetri Zeek + Loki)"
echo "Target Node: secops (192.168.122.81 / 10.10.40.11)"

# Sinkronkan skrip analisis graf ke secops
scp $SSH_OPTS telemetry/hunting/build-traffic-graph.py dcadmin@192.168.122.81:/tmp/build-traffic-graph.py

# Eksekusi Threat Hunting terpadu di secops
echo "--- 1. Mengeksekusi LogQL Hunting Rules & Analisis Graf NetworkX di secops ---"
HUNTING_REPORT=$(ssh $SSH_OPTS dcadmin@192.168.122.81 'bash -s' << 'EOF'
set -euo pipefail

echo ">>> BAGIAN A: Evaluasi Katalog Aturan Threat Hunting (LogQL):"
python3 - << 'PYEOF'
import urllib.request
import urllib.parse
import json

def query_loki(query, limit=50):
    params = urllib.parse.urlencode({'query': query, 'limit': limit})
    url = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            results = []
            for stream in data.get('data', {}).get('result', []):
                for val in stream.get('values', []):
                    results.append(val[1])
            return results
    except Exception as e:
        return [f"ERR: {e}"]

# 1. HUNT-01: Fan-out Network Scanning (S1)
logs_h1 = query_loki('{job="zeek", log_type="conn"} |= "10.10.10.11"', limit=100)
ports_touched = set()
for l in logs_h1:
    try:
        j = json.loads(l)
        if j.get('id.orig_h') == '10.10.10.11':
            ports_touched.add((j.get('id.resp_h'), j.get('id.resp_p')))
    except Exception:
        pass
h1_status = "TRIGGERED" if len(ports_touched) >= 5 else "INSUFFICIENT"
print(f"  [RULE HUNT-01] Fan-out Scanning (T1046)     : {h1_status} ({len(ports_touched)} target unik dipindai dari web1)")

# 2. HUNT-02: Unauthorized Lateral SSH Movement (S2 / S3)
logs_h2 = query_loki('{job="zeek", log_type="conn"} |= "22"', limit=50)
ssh_hops = set()
for l in logs_h2:
    try:
        j = json.loads(l)
        orig = j.get('id.orig_h')
        resp = j.get('id.resp_h')
        if orig and resp and orig != '10.10.40.11' and orig != '192.168.122.81' and orig.startswith('10.10.'):
            ssh_hops.add((orig, resp))
    except Exception:
        pass
h2_status = "TRIGGERED" if ssh_hops else "CLEAN"
print(f"  [RULE HUNT-02] Lateral SSH Movement (T1021) : {h2_status} ({len(ssh_hops)} rute lompatan lateral terdeteksi: {list(ssh_hops)})")

# 3. HUNT-03: Honeypot Decoy Touch (S5)
logs_h3 = query_loki('{job="opnsense-syslog", app_name="opencanaryd"}', limit=20)
h3_status = "TRIGGERED" if logs_h3 else "CLEAN"
print(f"  [RULE HUNT-03] OpenCanary Decoy Touch (S5)  : {h3_status} ({len(logs_h3)} alert interaksi honeypot)")

# 4. HUNT-04: Database Egress Exfiltration (S6)
logs_h4 = query_loki('{job="zeek"} |= "203.0.113.11"', limit=30)
exfil_flows = 0
for l in logs_h4:
    if '10.10.30.11' in l:
        exfil_flows += 1
h4_status = "TRIGGERED" if exfil_flows > 0 else "CLEAN"
print(f"  [RULE HUNT-04] DB Egress Exfiltration (T1048): {h4_status} ({exfil_flows} aliran data DB ke WAN teridentifikasi)")

# 5. HUNT-05: Direct Web to DB Tier Bypass
logs_h5 = query_loki('{job="zeek", log_type="conn"} |= "10.10.30.11"', limit=50)
bypass_flows = 0
for l in logs_h5:
    if '10.10.10.11' in l:
        bypass_flows += 1
h5_status = "TRIGGERED" if bypass_flows > 0 else "CLEAN"
print(f"  [RULE HUNT-05] Cross-Tier Web->DB Bypass    : {h5_status} ({bypass_flows} koneksi langsung melanggar 3-tier)")
PYEOF

echo
echo ">>> BAGIAN B: Analisis Graf Baseline & Sentralitas Tepi NetworkX:"
python3 /tmp/build-traffic-graph.py
EOF
)

echo "$HUNTING_REPORT"

# Simpan hasil laporan ke berkas artefak
cat > "$OUTPUT_FILE" << EOF
==========================================================
Laporan Hasil Threat Hunting & Analisis Graf Baseline (S8)
Tanggal   : $(date '+%Y-%m-%d %H:%M:%S')
Kondisi   : Baseline Permisif (Mode Deteksi Saja)
Target    : SecOps (Loki + Zeek Sensor)
==========================================================

$HUNTING_REPORT
EOF

echo
echo "Threat Hunting & Graph Baseline Selesai!"
echo "Hasil ringkasan tersimpan di: $OUTPUT_FILE"
