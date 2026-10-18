#!/usr/bin/env bash
# workloads/test-traffic-flow.sh
# Pengujian alur trafik cascading end-to-end 3-tier: Client -> Web -> App -> DB
# Mencakup trafik East-West internal (SecOps) dan North-South eksternal (Attacker WAN NAT)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Pengujian Alur Trafik Cascading 3-Tier (Client -> Web -> App -> DB)"
echo "Target: web1 (10.10.10.11), web2 (10.10.10.12), WAN NAT (203.0.113.1:80)"

echo "--- 1. Memeriksa Status Layanan di Seluruh 5 Node Workload ---"
for node in "db1:10.10.30.11:mock-db" "app1:10.10.20.11:mock-app" "app2:10.10.20.12:mock-app" "web1:10.10.10.11:mock-web" "web2:10.10.10.12:mock-web"; do
    IFS=":" read -r name ip svc <<< "$node"
    status=$(ssh $SSH_OPTS "dcadmin@$ip" "systemctl is-active $svc")
    if [ "$status" = "active" ]; then
        echo "  [OK] $name ($ip): $svc is active"
    else
        echo "  [GAGAL] $name ($ip): $svc is $status"
        exit 1
    fi
done

echo
echo "--- 2. Menguji Panggilan Cascading East-West Internal (Web1/Web2 -> App -> DB) ---"
resp1=$(ssh $SSH_OPTS dcadmin@10.10.10.11 "curl -s --connect-timeout 3 http://127.0.0.1/")
if echo "$resp1" | grep -q '"status": "ok"'; then
    echo "  [OK] Respons 200 OK dari web1:"
    echo "$resp1" | grep -E '"node"|"target"|"database_backend"|"records_returned"' | sed 's/^/    /'
else
    echo "  [GAGAL] Panggilan ke web1 gagal:"
    echo "$resp1"
    exit 1
fi

resp2=$(ssh $SSH_OPTS dcadmin@10.10.10.12 "curl -s --connect-timeout 3 http://127.0.0.1/")
if echo "$resp2" | grep -q '"status": "ok"'; then
    echo "  [OK] Respons 200 OK dari web2:"
    echo "$resp2" | grep -E '"node"|"target"|"database_backend"|"records_returned"' | sed 's/^/    /'
else
    echo "  [GAGAL] Panggilan ke web2 gagal:"
    echo "$resp2"
    exit 1
fi

echo
echo "--- 3. Menguji Panggilan Cascading North-South Eksternal (Attacker WAN NAT -> Web1 -> App -> DB) ---"
resp_wan=$(ssh $SSH_OPTS dcadmin@203.0.113.11 "curl -s --connect-timeout 3 http://203.0.113.1/")
if echo "$resp_wan" | grep -q '"status": "ok"'; then
    echo "  [OK] Respons 200 OK melintasi OPNsense WAN Port Forwarding (203.0.113.1:80):"
    echo "$resp_wan" | grep -E '"node"|"client_ip"|"target"|"records_returned"' | sed 's/^/    /'
else
    echo "  [GAGAL] Panggilan WAN ke web gagal:"
    echo "$resp_wan"
    exit 1
fi

echo
echo "--- 4. Menjalankan Siklus Generator Trafik Normal dengan Random Jitter dari Attacker (WAN NAT) ---"
scp $SSH_OPTS "$SCRIPT_DIR/traffic-generator.py" dcadmin@203.0.113.11:/tmp/traffic-generator.py
ssh $SSH_OPTS dcadmin@203.0.113.11 "python3 /tmp/traffic-generator.py --targets http://203.0.113.1/ --count 5 --min-interval 0.5 --max-interval 1.5 --admin-interval 5.0"

echo
echo "Pengujian Alur Trafik Cascading 3-Tier Selesai (100% Lulus)!"
