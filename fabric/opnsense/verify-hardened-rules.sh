#!/usr/bin/env bash
# fabric/opnsense/verify-hardened-rules.sh
# Memverifikasi Penegakan Aturan Firewall OPNsense yang Diperkeras (Hardened Rules)
# Menguji Aliran Positif yang Sah (PASS) dan Aliran Negatif yang Terlarang (BLOCK)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=4"

echo "Verifikasi Penegakan Micro-segmentation OPNsense (Langkah 7.1)"
echo "Mode: DEFAULT-DENY DENGAN IZIN EKSPLISIT BERBASIS ZONA"

echo
echo "--- [BAGIAN 1] Pengujian Aliran Positif yang Sah (Expected: PASS) ---"

# 1.1 Web DMZ ke App Tier (Port 8080)
echo -n "1. Web1 (10.10.10.11) -> App1 (10.10.20.11:8080) API Call ... "
WEB_TO_APP=$(ssh $SSH_OPTS dcadmin@10.10.10.11 "curl -s -m 3 http://10.10.20.11:8080/health || echo 'FAILED'")
if echo "$WEB_TO_APP" | grep -q '"tier": "app'; then
    echo "[PASS] Berhasil (HTTP 200 OK)"
else
    echo "[FAIL] Terputus atau Gagal: $WEB_TO_APP"
fi

# 1.2 App Tier ke DB Tier (Port 5432)
echo -n "2. App1 (10.10.20.11) -> DB1 (10.10.30.11:5432) Query ... "
APP_TO_DB=$(ssh $SSH_OPTS dcadmin@10.10.20.11 "echo 'PING' | nc -w 2 10.10.30.11 5432 2>/dev/null || echo 'FAILED'")
if echo "$APP_TO_DB" | grep -q '"tier": "database"'; then
    echo "[PASS] Berhasil (Respon DB Valid)"
else
    echo "[FAIL] Terputus atau Gagal: $APP_TO_DB"
fi

# 1.3 SecOps Bastion ke Seluruh Workload (SSH Port 22 via ProxyJump)
echo -n "3. Host -> SecOps Bastion -> Web1 (10.10.10.11:22) Admin SSH ... "
SECOPS_TO_WEB=$(ssh $SSH_OPTS -J dcadmin@192.168.122.81 dcadmin@10.10.10.11 hostname 2>/dev/null || echo 'FAILED')
if [ "$SECOPS_TO_WEB" = "web1" ]; then
    echo "[PASS] Berhasil (Akses Administratif Terbuka)"
else
    echo "[FAIL] Gagal: $SECOPS_TO_WEB"
fi

# 1.4 External Attacker ke Web DMZ Publikasi (Port 80)
echo -n "4. Attacker (203.0.113.11) -> OPNsense WAN (203.0.113.1:80) Web NAT ... "
WAN_TO_WEB=$(ssh $SSH_OPTS dcadmin@203.0.113.11 "curl -s -m 3 http://203.0.113.1/ || echo 'FAILED'")
if echo "$WAN_TO_WEB" | grep -q '"tier": "web"'; then
    echo "[PASS] Berhasil (Layanan Publik Terbuka)"
else
    echo "[FAIL] Gagal: $WAN_TO_WEB"
fi

echo
echo "--- [BAGIAN 2] Pengujian Aliran Negatif / Pelanggaran Zona (Expected: BLOCK) ---"

# 2.1 Web DMZ langsung ke DB Tier (Bypass Port 5432)
echo -n "5. [BYPASS] Web1 (10.10.10.11) -> DB1 (10.10.30.11:5432) ... "
if ssh $SSH_OPTS dcadmin@10.10.10.11 "nc -z -w 2 10.10.30.11 5432 2>/dev/null"; then
    echo "[VULNERABLE] Koneksi Terbuka (Seharusnya Diblokir!)"
else
    echo "[BLOCKED] Sukses Diblokir OPNsense (Drop/Timeout)"
fi

# 2.2 Web DMZ SSH Lateral ke App Tier (Port 22)
echo -n "6. [LATERAL] Web1 (10.10.10.11) -> App1 (10.10.20.11:22) ... "
if ssh $SSH_OPTS dcadmin@10.10.10.11 "nc -z -w 2 10.10.20.11 22 2>/dev/null"; then
    echo "[VULNERABLE] Koneksi Terbuka (Seharusnya Diblokir!)"
else
    echo "[BLOCKED] Sukses Diblokir OPNsense (Drop/Timeout)"
fi

# 2.3 App Tier SSH Lateral ke DB Tier (Port 22)
echo -n "7. [LATERAL] App1 (10.10.20.11) -> DB1 (10.10.30.11:22) ... "
if ssh $SSH_OPTS dcadmin@10.10.20.11 "nc -z -w 2 10.10.30.11 22 2>/dev/null"; then
    echo "[VULNERABLE] Koneksi Terbuka (Seharusnya Diblokir!)"
else
    echo "[BLOCKED] Sukses Diblokir OPNsense (Drop/Timeout)"
fi

# 2.4 DB Tier Egress Exfiltration ke WAN (Port 8000 & Ping)
echo -n "8. [EGRESS] DB1 (10.10.30.11) -> WAN (203.0.113.11:8000) ... "
if ssh $SSH_OPTS dcadmin@10.10.30.11 "nc -z -w 2 203.0.113.11 8000 2>/dev/null"; then
    echo "[VULNERABLE] Egress Terbuka (Seharusnya Diblokir!)"
else
    echo "[BLOCKED] Sukses Diblokir OPNsense Zero-Trust Egress"
fi

echo -n "9. [EGRESS ICMP] DB1 (10.10.30.11) -> WAN (203.0.113.11 ping) ... "
if ssh $SSH_OPTS dcadmin@10.10.30.11 "ping -c 1 -W 2 203.0.113.11 >/dev/null 2>&1"; then
    echo "[VULNERABLE] ICMP Egress Terbuka"
else
    echo "[BLOCKED] Sukses Diblokir OPNsense Zero-Trust Egress"
fi

echo
echo "Verifikasi Selesai!"
