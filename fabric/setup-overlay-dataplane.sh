#!/usr/bin/env bash
# fabric/setup-overlay-dataplane.sh
# Konfigurasi perangkat data-plane Overlay EVPN/VXLAN (Bridge per L2 VNI & antarmuka VXLAN nolearning)
# di leaf1 (Web), leaf2 (App), dan leaf3 (Border GW / OPNsense Trunk + DB + Canary + SecOps).
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "=========================================================="
echo "Konfigurasi Data-Plane EVPN/VXLAN (Bridge & VXLAN per VNI)"
echo "=========================================================="

# -----------------------------------------------------------------------------
# 1. leaf1: VNI 10010 (Web Zone)
# -----------------------------------------------------------------------------
echo "--- [leaf1 (192.168.122.31)] Mengonfigurasi br10010 & vxlan10010 (VNI 10010) ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" sudo bash << 'EOF'
set -euo pipefail

# Buat script provisi data-plane lokal
cat << 'SCRIPT' > /usr/local/bin/setup-overlay-dataplane.sh
#!/usr/bin/env bash
set -euo pipefail

VTEP_IP="10.255.0.11"

# 1. Buat bridge br10010
ip link add dev br10010 type bridge 2>/dev/null || true
ip link set dev br10010 up

# 2. Buat antarmuka VXLAN 10010
ip link add dev vxlan10010 type vxlan id 10010 local "${VTEP_IP}" dstport 4789 nolearning 2>/dev/null || true
ip link set dev vxlan10010 master br10010
bridge link set dev vxlan10010 learning off
ip link set dev vxlan10010 up

# 3. Pasang port akses eth3 (Zona Web)
ip link set dev eth3 master br10010
ip link set dev eth3 up
SCRIPT

chmod +x /usr/local/bin/setup-overlay-dataplane.sh

# Pasang systemd service agar persisten pasca-reboot
cat << 'SERVICE' > /etc/systemd/system/overlay-dataplane.service
[Unit]
Description=EVPN/VXLAN Overlay Data-Plane Bridges and Tunnels
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-overlay-dataplane.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now overlay-dataplane.service
/usr/local/bin/setup-overlay-dataplane.sh
EOF

# -----------------------------------------------------------------------------
# 2. leaf2: VNI 10020 (App Zone)
# -----------------------------------------------------------------------------
echo "--- [leaf2 (192.168.122.32)] Mengonfigurasi br10020 & vxlan10020 (VNI 10020) ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.32" sudo bash << 'EOF'
set -euo pipefail

cat << 'SCRIPT' > /usr/local/bin/setup-overlay-dataplane.sh
#!/usr/bin/env bash
set -euo pipefail

VTEP_IP="10.255.0.12"

# 1. Buat bridge br10020
ip link add dev br10020 type bridge 2>/dev/null || true
ip link set dev br10020 up

# 2. Buat antarmuka VXLAN 10020
ip link add dev vxlan10020 type vxlan id 10020 local "${VTEP_IP}" dstport 4789 nolearning 2>/dev/null || true
ip link set dev vxlan10020 master br10020
bridge link set dev vxlan10020 learning off
ip link set dev vxlan10020 up

# 3. Pasang port akses eth3 (Zona App)
ip link set dev eth3 master br10020
ip link set dev eth3 up
SCRIPT

chmod +x /usr/local/bin/setup-overlay-dataplane.sh

cat << 'SERVICE' > /etc/systemd/system/overlay-dataplane.service
[Unit]
Description=EVPN/VXLAN Overlay Data-Plane Bridges and Tunnels
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-overlay-dataplane.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now overlay-dataplane.service
/usr/local/bin/setup-overlay-dataplane.sh
EOF

# -----------------------------------------------------------------------------
# 3. leaf3: Border Leaf (Trunk OPNsense + DB + Canary + SecOps: VNI 10010 - 10050)
# -----------------------------------------------------------------------------
echo "--- [leaf3 (192.168.122.33)] Mengonfigurasi 5 Bridge & VXLAN (VNI 10010 - 10050) ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.33" sudo bash << 'EOF'
set -euo pipefail

cat << 'SCRIPT' > /usr/local/bin/setup-overlay-dataplane.sh
#!/usr/bin/env bash
set -euo pipefail

VTEP_IP="10.255.0.13"

# Aktifkan interface fisik
ip link set dev eth3 up   # Akses DB
ip link set dev eth4 up   # Akses Decoy/Canary
ip link set dev eth5 up   # Akses SecOps
ip link set dev eth6 up   # Trunk ke OPNsense

# Buat subinterface 802.1Q pada eth6 untuk trunk ke OPNsense
for vlan in 10 20 30 40 50; do
  ip link add link eth6 name "eth6.${vlan}" type vlan id "${vlan}" 2>/dev/null || true
  ip link set dev "eth6.${vlan}" up
done

# Fungsi pembantu untuk membuat bridge dan vxlan per VNI
create_vni_domain() {
  local vni="$1"
  local br="br${vni}"
  local vx="vxlan${vni}"

  # 1. Bridge
  ip link add dev "${br}" type bridge 2>/dev/null || true
  ip link set dev "${br}" up

  # 2. VXLAN
  ip link add dev "${vx}" type vxlan id "${vni}" local "${VTEP_IP}" dstport 4789 nolearning 2>/dev/null || true
  ip link set dev "${vx}" master "${br}"
  bridge link set dev "${vx}" learning off
  ip link set dev "${vx}" up
}

# 1. VNI 10010 (Web): Bridge + VXLAN + Trunk eth6.10
create_vni_domain 10010
ip link set dev eth6.10 master br10010

# 2. VNI 10020 (App): Bridge + VXLAN + Trunk eth6.20
create_vni_domain 10020
ip link set dev eth6.20 master br10020

# 3. VNI 10030 (DB): Bridge + VXLAN + Akses eth3 + Trunk eth6.30
create_vni_domain 10030
ip link set dev eth3 master br10030
ip link set dev eth6.30 master br10030

# 4. VNI 10040 (SecOps): Bridge + VXLAN + Akses eth5 + Trunk eth6.40
create_vni_domain 10040
ip link set dev eth5 master br10040
ip link set dev eth6.40 master br10040

# 5. VNI 10050 (Decoy): Bridge + VXLAN + Akses eth4 + Trunk eth6.50
create_vni_domain 10050
ip link set dev eth4 master br10050
ip link set dev eth6.50 master br10050
SCRIPT

chmod +x /usr/local/bin/setup-overlay-dataplane.sh

cat << 'SERVICE' > /etc/systemd/system/overlay-dataplane.service
[Unit]
Description=EVPN/VXLAN Overlay Data-Plane Bridges and Tunnels
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-overlay-dataplane.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now overlay-dataplane.service
/usr/local/bin/setup-overlay-dataplane.sh
EOF

echo
echo "=========================================================="
echo "Verifikasi Status Data-Plane di Ketiga Leaf Nodes:"
echo "=========================================================="

echo ">>> [leaf1] Daftar Bridge & Slave Ports:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "bridge link show"

echo
echo ">>> [leaf2] Daftar Bridge & Slave Ports:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "bridge link show"

echo
echo ">>> [leaf3] Daftar 5 Bridge & Slave Ports:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "bridge link show"

echo
echo "Konfigurasi Data-Plane EVPN/VXLAN (Bridge & VXLAN per VNI) Berhasil Diterapkan!"
