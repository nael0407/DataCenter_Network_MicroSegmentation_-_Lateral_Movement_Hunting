#!/usr/bin/env bash
# workloads/deploy-mock-app.sh
# Skrip otomasi penyebaran aplikasi 3-tier mock (Web -> App -> DB)
# Target: web1-2 (port 80), app1-2 (port 8080), db1 (port 5432)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Penyebaran Aplikasi 3-Tier Mock Workload (Fase 5 - Langkah 5.6)"
echo "Target: web1-2 (:80) -> app1-2 (:8080) -> db1 (:5432)"

# 1. Penyebaran Database Tier (db1: 10.10.30.11)
echo "--- [1/3] Menyebarkan Mock DB Server di db1 (10.10.30.11:5432) ---"
scp $SSH_OPTS "$SCRIPT_DIR/mock-app/db_server.py" dcadmin@10.10.30.11:/tmp/db_server.py
ssh $SSH_OPTS dcadmin@10.10.30.11 'sudo bash -s' << 'EOF'
set -euo pipefail
mkdir -p /opt/mock-app
cp /tmp/db_server.py /opt/mock-app/db_server.py
chmod 755 /opt/mock-app/db_server.py

cat > /etc/systemd/system/mock-db.service << 'SERVICE'
[Unit]
Description=3-Tier Mock Database Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/mock-app/db_server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable mock-db
systemctl restart mock-db
sleep 1
systemctl is-active mock-db
EOF
echo "  [OK] mock-db.service aktif di db1"

# 2. Penyebaran Application Tier (app1: 10.10.20.11, app2: 10.10.20.12)
echo "--- [2/3] Menyebarkan Mock App Server di app1 & app2 (:8080) ---"
for node_ip in 10.10.20.11 10.10.20.12; do
    echo "  -> Konfigurasi di $node_ip..."
    scp $SSH_OPTS "$SCRIPT_DIR/mock-app/app_server.py" dcadmin@$node_ip:/tmp/app_server.py
    ssh $SSH_OPTS dcadmin@$node_ip 'sudo bash -s' << 'EOF'
set -euo pipefail
mkdir -p /opt/mock-app
cp /tmp/app_server.py /opt/mock-app/app_server.py
chmod 755 /opt/mock-app/app_server.py

cat > /etc/systemd/system/mock-app.service << 'SERVICE'
[Unit]
Description=3-Tier Mock Application Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/mock-app/app_server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable mock-app
systemctl restart mock-app
sleep 1
systemctl is-active mock-app
EOF
    echo "  [OK] mock-app.service aktif di $node_ip"
done

# 3. Penyebaran Web Tier (web1: 10.10.10.11, web2: 10.10.10.12)
echo "--- [3/3] Menyebarkan Mock Web Server di web1 & web2 (:80) ---"
for node_ip in 10.10.10.11 10.10.10.12; do
    echo "  -> Konfigurasi di $node_ip..."
    scp $SSH_OPTS "$SCRIPT_DIR/mock-app/web_server.py" dcadmin@$node_ip:/tmp/web_server.py
    ssh $SSH_OPTS dcadmin@$node_ip 'sudo bash -s' << 'EOF'
set -euo pipefail
mkdir -p /opt/mock-app
cp /tmp/web_server.py /opt/mock-app/web_server.py
chmod 755 /opt/mock-app/web_server.py

cat > /etc/systemd/system/mock-web.service << 'SERVICE'
[Unit]
Description=3-Tier Mock Web Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/mock-app/web_server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable mock-web
systemctl restart mock-web
sleep 1
systemctl is-active mock-web
EOF
    echo "  [OK] mock-web.service aktif di $node_ip"
done

echo
echo "Seluruh Layanan 3-Tier Mock Workload Berhasil Disebarkan!"
