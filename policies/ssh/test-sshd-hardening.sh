#!/usr/bin/env bash
# policies/ssh/test-sshd-hardening.sh
# Verifikasi Pengerasan Konfigurasi SSH Daemon (sshd) pada Workload Servers
# Langkah 7.3: Penegakan AllowAgentForwarding no & AllowTcpForwarding no
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3"
BASTION="192.168.122.81"

echo "=========================================================="
echo "Verifikasi Pengerasan SSH Daemon (sshd_config Hardening)"
echo "Mitigasi MITRE: T1563.001 (Agent Hijacking) & T1572 (Tunneling)"
echo "=========================================================="

echo
echo "--- [BAGIAN 1] Audit Parameter Efektif sshd pada Seluruh Workload ---"
ALL_NODES_OK=true
for node in web1:10.10.10.11 web2:10.10.10.12 app1:10.10.20.11 app2:10.10.20.12 db1:10.10.30.11 canary1:10.10.50.11; do
    name=$(echo $node | cut -d: -f1)
    ip=$(echo $node | cut -d: -f2)
    
    agent_fwd=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@$ip "sudo sshd -T | grep '^allowagentforwarding '" 2>/dev/null | awk '{print $2}')
    tcp_fwd=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@$ip "sudo sshd -T | grep '^allowtcpforwarding '" 2>/dev/null | awk '{print $2}')
    
    if [ "$agent_fwd" = "no" ] && [ "$tcp_fwd" = "no" ]; then
        echo "  [OK] $name ($ip): AllowAgentForwarding=no, AllowTcpForwarding=no"
    else
        echo "  [FAIL] $name ($ip): AllowAgentForwarding=$agent_fwd, AllowTcpForwarding=$tcp_fwd"
        ALL_NODES_OK=false
    fi
done

echo
echo "--- [BAGIAN 2] Pengujian Empiris Penolakan TCP Port Forwarding (Mitigasi S4 / T1572) ---"
echo -n "1. Menguji pembukaan tunnel port-forwarding (-L) ke web1 ... "
# Coba buat tunnel lokal port 18080 menuju app1 lewat web1
TUNNEL_OUTPUT=$(ssh $SSH_OPTS -J dcadmin@$BASTION -o ExitOnForwardFailure=yes -L 18080:10.10.20.11:8080 dcadmin@10.10.10.11 "sleep 1" 2>&1 || true)
if echo "$TUNNEL_OUTPUT" | grep -qi "administratively prohibited\|Forwarding failed\|rejected"; then
    echo "[PASS] DITOLAK oleh sshd server: $TUNNEL_OUTPUT"
else
    # Uji verifikasi apakah socket lokal dapat digunakan
    if nc -z -w 1 127.0.0.1 18080 2>/dev/null; then
        echo "[FAIL] Tunnel Berhasil Terbentuk (Seharusnya Ditolak!)"
    else
        echo "[PASS] DITOLAK: TCP Port Forwarding tidak diizinkan oleh sshd web1"
    fi
fi

echo
echo "--- [BAGIAN 3] Pengujian Empiris Penolakan Agent Forwarding (Mitigasi S3 / T1563.001) ---"
echo -n "2. Menguji pendelegasian agent forwarding (-A) ke web1 ... "
AGENT_SOCK=$(ssh $SSH_OPTS -J dcadmin@$BASTION -A dcadmin@10.10.10.11 'echo $SSH_AUTH_SOCK' 2>/dev/null || echo "")
if [ -z "$AGENT_SOCK" ]; then
    echo "[PASS] BERHASIL DICEGAH (SSH_AUTH_SOCK kosong / tidak didelegasikan oleh sshd)"
else
    echo "[FAIL] SSH_AUTH_SOCK tetap terbentuk di RAM server: $AGENT_SOCK"
fi

echo
echo "--- [BAGIAN 4] Verifikasi Keterjangkauan Administratif Sah (Positive Access) ---"
echo -n "3. Akses SSH reguler via SecOps Bastion ProxyJump ... "
UPTIME_RES=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.10.11 "uptime" 2>/dev/null || echo "FAILED")
if echo "$UPTIME_RES" | grep -q "load average"; then
    echo "[PASS] Berhasil (Akses administratif reguler tetap berjalan lancar)"
else
    echo "[FAIL] Akses administratif terputus: $UPTIME_RES"
fi

echo
echo "=========================================================="
echo "Verifikasi Pengerasan SSH Daemon Selesai!"
echo "=========================================================="
