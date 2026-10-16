#!/usr/bin/env bash
# telemetry/setup-port-mirroring.sh
# Mengonfigurasi port mirroring (tc mirred ingress) pada seluruh switch Leaf (leaf1, leaf2, leaf3)
# dan mengaktifkan mode promiskus pada 3 antarmuka sensor di VM secops (Langkah 5.3)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "=========================================================="
echo "Konfigurasi Port Mirroring (tc mirred) & Sensor Telemetri"
echo "=========================================================="

# 1. Konfigurasi Port Mirroring di Leaf1 (Web Zone: eth3 -> mirror-l1: eth4)
echo "--- [1/4] Mengonfigurasi tc mirred di leaf1 (eth3 -> eth4) ---"
ssh $SSH_OPTS "dcadmin@192.168.122.31" 'sudo bash -s' << 'EOF'
set -euo pipefail
ip link set dev eth4 up
tc qdisc del dev eth3 ingress 2>/dev/null || true
tc qdisc add dev eth3 ingress
tc filter add dev eth3 ingress matchall action mirred egress mirror dev eth4

# Persistensikan ke dalam script dataplane overlay leaf1
if ! grep -q "tc filter add dev eth3 ingress" /usr/local/bin/setup-overlay-dataplane.sh 2>/dev/null; then
  cat >> /usr/local/bin/setup-overlay-dataplane.sh << 'DATAPLANE'

# Port Mirroring (tc mirred ingress): eth3 (Web) -> eth4 (mirror-l1 ke secops)
ip link set dev eth4 up
tc qdisc del dev eth3 ingress 2>/dev/null || true
tc qdisc add dev eth3 ingress
tc filter add dev eth3 ingress matchall action mirred egress mirror dev eth4
DATAPLANE
fi
echo "[OK] leaf1 port mirroring aktif & dipersistenkan."
EOF

# 2. Konfigurasi Port Mirroring di Leaf2 (App Zone: eth3 -> mirror-l2: eth4)
echo "--- [2/4] Mengonfigurasi tc mirred di leaf2 (eth3 -> eth4) ---"
ssh $SSH_OPTS "dcadmin@192.168.122.32" 'sudo bash -s' << 'EOF'
set -euo pipefail
ip link set dev eth4 up
tc qdisc del dev eth3 ingress 2>/dev/null || true
tc qdisc add dev eth3 ingress
tc filter add dev eth3 ingress matchall action mirred egress mirror dev eth4

# Persistensikan ke dalam script dataplane overlay leaf2
if ! grep -q "tc filter add dev eth3 ingress" /usr/local/bin/setup-overlay-dataplane.sh 2>/dev/null; then
  cat >> /usr/local/bin/setup-overlay-dataplane.sh << 'DATAPLANE'

# Port Mirroring (tc mirred ingress): eth3 (App) -> eth4 (mirror-l2 ke secops)
ip link set dev eth4 up
tc qdisc del dev eth3 ingress 2>/dev/null || true
tc qdisc add dev eth3 ingress
tc filter add dev eth3 ingress matchall action mirred egress mirror dev eth4
DATAPLANE
fi
echo "[OK] leaf2 port mirroring aktif & dipersistenkan."
EOF

# 3. Konfigurasi Port Mirroring di Leaf3 (DB: eth3 & Decoy: eth4 -> mirror-l3: eth7)
echo "--- [3/4] Mengonfigurasi tc mirred di leaf3 (eth3 & eth4 -> eth7) ---"
ssh $SSH_OPTS "dcadmin@192.168.122.33" 'sudo bash -s' << 'EOF'
set -euo pipefail
ip link set dev eth7 up

# Mirror akses DB (eth3) ke eth7
tc qdisc del dev eth3 ingress 2>/dev/null || true
tc qdisc add dev eth3 ingress
tc filter add dev eth3 ingress matchall action mirred egress mirror dev eth7

# Mirror akses Decoy/Canary (eth4) ke eth7
tc qdisc del dev eth4 ingress 2>/dev/null || true
tc qdisc add dev eth4 ingress
tc filter add dev eth4 ingress matchall action mirred egress mirror dev eth7

# Persistensikan ke dalam script dataplane overlay leaf3
if ! grep -q "action mirred egress mirror dev eth7" /usr/local/bin/setup-overlay-dataplane.sh 2>/dev/null; then
  cat >> /usr/local/bin/setup-overlay-dataplane.sh << 'DATAPLANE'

# Port Mirroring (tc mirred ingress): eth3 (DB) & eth4 (Decoy) -> eth7 (mirror-l3 ke secops)
ip link set dev eth7 up
tc qdisc del dev eth3 ingress 2>/dev/null || true
tc qdisc add dev eth3 ingress
tc filter add dev eth3 ingress matchall action mirred egress mirror dev eth7
tc qdisc del dev eth4 ingress 2>/dev/null || true
tc qdisc add dev eth4 ingress
tc filter add dev eth4 ingress matchall action mirred egress mirror dev eth7
DATAPLANE
fi
echo "[OK] leaf3 port mirroring aktif & dipersistenkan."
EOF

# 4. Konfigurasi Antarmuka Sniffing di VM secops (eth1, eth2, eth3 promisc up)
echo "--- [4/4] Mengaktifkan Promiscuous Mode pada Sensor NIC di secops ---"
ssh $SSH_OPTS "dcadmin@192.168.122.81" 'sudo bash -s' << 'EOF'
set -euo pipefail

# Buat skrip penyelarasan sensor bridge
cat > /usr/local/bin/setup-sensor-bridge.sh << 'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

ip link del dev br-sensor 2>/dev/null || true
ip link add dev br-sensor type bridge
ip link set dev eth1 master br-sensor
ip link set dev eth2 master br-sensor
ip link set dev eth3 master br-sensor

bridge link set dev eth1 learning off
bridge link set dev eth2 learning off
bridge link set dev eth3 learning off
ip link set dev br-sensor type bridge stp_state 0

ip link set dev eth1 up promisc on
ip link set dev eth2 up promisc on
ip link set dev eth3 up promisc on
ip link set dev br-sensor up promisc on
SCRIPT

chmod +x /usr/local/bin/setup-sensor-bridge.sh
/usr/local/bin/setup-sensor-bridge.sh

# Buat unit oneshot systemd agar br-sensor otomatis terbentuk pasca-reboot
cat > /etc/systemd/system/sensor-bridge.service << 'SERVICE'
[Unit]
Description=Zeek Aggregated Sensor Bridge (br-sensor)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-sensor-bridge.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable sensor-bridge.service >/dev/null 2>&1 || true
echo "[OK] secops br-sensor (menggabungkan eth1, eth2, eth3 nolearning) aktif & dipersistenkan."
EOF

echo
echo "=========================================================="
echo "Seluruh Port Mirroring & Sensor Interface Berhasil Dikonfigurasi!"
echo "=========================================================="
