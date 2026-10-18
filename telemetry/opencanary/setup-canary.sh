#!/usr/bin/env bash
# telemetry/opencanary/setup-canary.sh
# Skrip otomasi instalasi dan konfigurasi OpenCanary Honeypot Decoy di canary1 (10.10.50.11)
# Sesuai Fase 5 (Langkah 5.5) dan mitigasi isolasi OOB (Section 6.5)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Penyebaran OpenCanary Honeypot Decoy (Fase 5 - Langkah 5.5)"
echo "Target Node: canary1 (10.10.50.11 - Zona Canary / Leaf3)"

# 1. Pastikan bundel paket roda (wheels) siap di host
WHEELS_DIR="/tmp/opencanary-wheels"
if [ ! -d "$WHEELS_DIR" ] || [ -z "$(ls -A "$WHEELS_DIR" 2>/dev/null)" ]; then
    echo "--- [1/4] Mengunduh paket roda offline OpenCanary di host ---"
    mkdir -p "$WHEELS_DIR"
    pip3 download --dest "$WHEELS_DIR" opencanary
else
    echo "--- [1/4] Paket roda offline OpenCanary sudah tersedia di $WHEELS_DIR ---"
fi

# 2. Transfer berkas ke canary1 via secops bastion
echo "--- [2/4] Mengunggah bundel roda & konfigurasi ke canary1 via Bastion ---"
scp $SSH_OPTS -r "$WHEELS_DIR" dcadmin@10.10.50.11:/tmp/opencanary-wheels
scp $SSH_OPTS "$SCRIPT_DIR/opencanary.conf" dcadmin@10.10.50.11:/tmp/opencanary.conf

# 3. Instalasi & konfigurasi di canary1
echo "--- [3/4] Mengonfigurasi Virtual Environment, Layanan Decoy & Rsyslog di canary1 ---"
ssh $SSH_OPTS dcadmin@10.10.50.11 'sudo bash -s' << 'EOF'
set -euo pipefail

# Buat virtual environment jika belum ada
if [ ! -d /opt/opencanary-venv ]; then
    python3 -m venv /opt/opencanary-venv
fi

# Pasang OpenCanary secara offline dari direktori wheels
/opt/opencanary-venv/bin/pip install --no-index --find-links=/tmp/opencanary-wheels opencanary

# Siapkan direktori konfigurasi dan log
mkdir -p /etc/opencanaryd /var/log/opencanary
cp /tmp/opencanary.conf /etc/opencanaryd/opencanary.conf
chmod 755 /etc/opencanaryd /var/log/opencanary
chmod 644 /etc/opencanaryd/opencanary.conf

# Konfigurasi pengalihan rsyslog RFC 5424 ke SecOps (10.10.40.11:1514)
cat > /etc/rsyslog.d/90-secops.conf << 'RSYSLOG'
*.* action(type="omfwd" target="10.10.40.11" port="1514" protocol="udp" template="RSYSLOG_SyslogProtocol23Format")
RSYSLOG
systemctl restart rsyslog

# Buat unit systemd opencanary
cat > /etc/systemd/system/opencanary.service << 'SERVICE'
[Unit]
Description=OpenCanary Decoy Honeypot Daemon
After=network.target rsyslog.service

[Service]
Type=simple
Environment="PATH=/opt/opencanary-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/opencanary-venv/bin/twistd -noy /opt/opencanary-venv/bin/opencanary.tac --syslog --prefix=opencanaryd
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable opencanary
systemctl restart opencanary

sleep 3
EOF

echo
echo "--- [4/4] Memverifikasi Status Layanan & Port Decoy di canary1 ---"
ssh $SSH_OPTS dcadmin@10.10.50.11 'bash -s' << 'EOF'
set -euo pipefail
echo "Status opencanary.service: $(systemctl is-active opencanary)"
echo "Port decoy yang mendengarkan:"
sudo ss -tulpn | grep twistd | awk '{print "  -> Port:", $5}'
EOF

echo
echo "OpenCanary Honeypot Decoy Berhasil Dikonfigurasi di canary1!"
