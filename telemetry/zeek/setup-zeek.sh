#!/usr/bin/env bash
# telemetry/zeek/setup-zeek.sh
# Mengonfigurasi Zeek multi-interface sniffing (eth1, eth2, eth3) dengan JSON logging
# dan mengaktifkan service systemd pada VM secops (Langkah 5.3)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "=========================================================="
echo "Konfigurasi Zeek Multi-Interface Sniffing & JSON Logging"
echo "Target Node: secops (192.168.122.81)"
echo "=========================================================="

ssh $SSH_OPTS "dcadmin@192.168.122.81" 'sudo bash -s' << 'EOF'
set -euo pipefail

# 1. Pastikan biner Zeek terdeteksi di PATH global
if ! grep -q "/opt/zeek/bin" /etc/environment 2>/dev/null; then
  echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/zeek/bin"' > /etc/environment
fi
cat > /etc/profile.d/zeek.sh << 'PROF'
export PATH="$PATH:/opt/zeek/bin"
PROF

# 2. Siapkan direktori log Zeek
mkdir -p /var/log/zeek
chmod 755 /var/log/zeek

# 3. Konfigurasikan local.zeek agar menghasilkan log berformat JSON
SITE_ZEEK="/opt/zeek/share/zeek/site/local.zeek"
if ! grep -q "json-logs.zeek" "$SITE_ZEEK" 2>/dev/null; then
  echo "" >> "$SITE_ZEEK"
  echo "# Konfigurasi JSON Logging untuk Grafana Alloy & Loki" >> "$SITE_ZEEK"
  echo "@load policy/tuning/json-logs.zeek" >> "$SITE_ZEEK"
fi

# 4. Buat unit systemd zeek.service untuk sniffing antarmuka agregasi br-sensor
cat > /etc/systemd/system/zeek.service << 'SERVICE'
[Unit]
Description=Zeek Network Security Monitor (Aggregated Sensor Sniffing)
After=network.target sensor-bridge.service
Wants=sensor-bridge.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/log/zeek
ExecStart=/opt/zeek/bin/zeek -C -i br-sensor local
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable zeek.service
systemctl restart zeek.service

sleep 3
if systemctl is-active --quiet zeek.service; then
  echo "[OK] zeek.service berhasil dijalankan dan aktif."
else
  echo "[ERROR] zeek.service gagal berjalan!"
  journalctl -u zeek.service -n 20 --no-pager
  exit 1
fi
EOF

echo
echo "=========================================================="
echo "Zeek Multi-Interface Sniffing Berhasil Dikonfigurasi!"
echo "=========================================================="
