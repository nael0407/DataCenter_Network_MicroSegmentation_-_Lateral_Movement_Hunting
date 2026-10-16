#!/usr/bin/env bash
# policies/nftables/test-nftables-rules.sh
# Verifikasi Host-based Micro-segmentation (nftables) pada Seluruh Server Beban Kerja
# Langkah 7.2: Penegakan Microsegmentation Lapisan Host via Ansible
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3"
BASTION="192.168.122.81"

echo "=========================================================="
echo "Verifikasi Host-based Micro-segmentation (nftables)"
echo "Mode: ROLE-BASED ZERO-TRUST FILTERING (Tiap Host Mengontrol Akses)"
echo "=========================================================="

echo
echo "--- [BAGIAN 1] Status Layanan nftables.service pada Seluruh Node ---"
for node in web1:10.10.10.11 web2:10.10.10.12 app1:10.10.20.11 app2:10.10.20.12 db1:10.10.30.11 canary1:10.10.50.11; do
    name=$(echo $node | cut -d: -f1)
    ip=$(echo $node | cut -d: -f2)
    st=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@$ip "sudo systemctl is-active nftables" 2>/dev/null || echo "FAILED")
    rules=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@$ip "sudo nft list ruleset | grep -c 'chain input'" 2>/dev/null || echo "0")
    if [ "$st" = "active" ] && [ "$rules" -ge 1 ]; then
        echo "  [OK] $name ($ip): status=$st, table inet filter active"
    else
        echo "  [FAIL] $name ($ip): status=$st, rules=$rules"
    fi
done

echo
echo "--- [BAGIAN 2] Pengujian Penegakan Egress Host-level (Output Chain Drop) ---"

# 2.1 Web1 mencoba membuka SSH keluar (Output Chain harus memblokir port 22 keluar)
echo -n "1. [HOST EGRESS] Web1 (10.10.10.11) mencoba SSH keluar ke App1 (10.10.20.11:22) ... "
if ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.10.11 "nc -z -w 2 10.10.20.11 22 2>/dev/null"; then
    echo "[FAIL] Terbuka (Output chain gagal memblokir)"
else
    echo "[PASS] DIBLOKIR oleh nftables output chain Web1"
fi

# 2.2 App1 mencoba membuka SSH keluar ke DB1 (Output Chain harus memblokir port 22 keluar)
echo -n "2. [HOST EGRESS] App1 (10.10.20.11) mencoba SSH keluar ke DB1 (10.10.30.11:22) ... "
if ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.20.11 "nc -z -w 2 10.10.30.11 22 2>/dev/null"; then
    echo "[FAIL] Terbuka (Output chain gagal memblokir)"
else
    echo "[PASS] DIBLOKIR oleh nftables output chain App1"
fi

# 2.3 DB1 mencoba koneksi langsung ke WAN (Output Chain Zero-Trust Egress)
echo -n "3. [HOST EGRESS] DB1 (10.10.30.11) mencoba akses keluar ke Internet/WAN (203.0.113.11:8000) ... "
if ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.30.11 "nc -z -w 2 203.0.113.11 8000 2>/dev/null"; then
    echo "[FAIL] Terbuka"
else
    echo "[PASS] DIBLOKIR oleh nftables output chain DB1"
fi

echo
echo "--- [BAGIAN 3] Pengujian Alur Layanan Legal Aplikasi 3-Tier (Positive Verification) ---"

# 3.1 Web1 ke App1 (Port 8080)
echo -n "4. [LEGITIMATE APP] Web1 -> App1 (:8080) API Call ... "
RESP_APP=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.10.11 "curl -s -m 2 http://10.10.20.11:8080/health || echo 'FAILED'")
if echo "$RESP_APP" | grep -q '"tier": "app'; then
    echo "[PASS] Berhasil (200 OK, nftables mengizinkan)"
else
    echo "[FAIL] Gagal: $RESP_APP"
fi

# 3.2 App1 ke DB1 (Port 5432)
echo -n "5. [LEGITIMATE DB] App1 -> DB1 (:5432) Query Backend ... "
RESP_DB=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.20.11 "echo 'PING' | nc -w 2 10.10.30.11 5432 2>/dev/null || echo 'FAILED'")
if echo "$RESP_DB" | grep -q '"tier": "database"'; then
    echo "[PASS] Berhasil (DB Response Valid, nftables mengizinkan)"
else
    echo "[FAIL] Gagal: $RESP_DB"
fi

# 3.3 SecOps Bastion ke Seluruh Workload (Port 22 Inbound)
echo -n "6. [ADMIN SSH] SecOps Bastion -> Workload Inbound SSH ... "
RESP_ADMIN=$(ssh $SSH_OPTS -J dcadmin@$BASTION dcadmin@10.10.30.11 hostname 2>/dev/null || echo 'FAILED')
if [ "$RESP_ADMIN" = "db1" ]; then
    echo "[PASS] Berhasil (Bastion Admin diizinkan oleh nftables input chain)"
else
    echo "[FAIL] Gagal: $RESP_ADMIN"
fi

echo
echo "=========================================================="
echo "Seluruh Pengujian Host-based Micro-segmentation Selesai!"
echo "=========================================================="
