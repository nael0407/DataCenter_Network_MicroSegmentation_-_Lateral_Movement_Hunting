#!/usr/bin/env bash
# infra/setup-node-kernel.sh
# Mengonfigurasi modul kernel dan sysctl untuk routing, VXLAN, VRF, dan tc mirroring di kelima node fabric
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_KEY="$HOME/.ssh/k8s-lab"
NODES=(
  "spine1:192.168.122.21"
  "spine2:192.168.122.22"
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

echo "Mengonfigurasi kernel pada 5 node jaringan (Spine & Leaf)..."

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo "--- [$name ($ip)] Mengonfigurasi modul & sysctl ---"

  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "dcadmin@$ip" sudo bash << 'EOF'
set -euo pipefail

# 1. Pastikan paket linux-modules-extra terpasang (diperlukan untuk modul vrf di Ubuntu cloud image)
if ! modinfo vrf >/dev/null 2>&1; then
  echo "Menginstal paket linux-modules-extra-$(uname -r)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y --no-install-recommends "linux-modules-extra-$(uname -r)" >/dev/null
fi

# 2. Konfigurasi pemuatan modul kernel secara persisten
cat << 'MOD' > /etc/modules-load.d/fabric.conf
# Modul kernel untuk Spine-Leaf Fabric & Telemetri
vrf
vxlan
bridge
sch_ingress
cls_flower
cls_u32
act_mirred
MOD

# Muat modul sekarang
modprobe vrf
modprobe vxlan
modprobe bridge
modprobe sch_ingress
modprobe cls_flower
modprobe cls_u32
modprobe act_mirred

# 2. Konfigurasi sysctl persisten untuk IP forwarding & VRF
cat << 'SYS' > /etc/sysctl.d/99-fabric.conf
# Mengaktifkan IP Forwarding agar node bisa merutekan paket (Layer 3)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Loose reverse path filtering agar tidak mendrop paket asimetris atau VRF
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# Izinkan soket TCP/UDP menerima koneksi lintas VRF domain (L3 Master Device)
net.ipv4.tcp_l3mdev_accept = 1
net.ipv4.udp_l3mdev_accept = 1
SYS

# Terapkan sysctl
sysctl -p /etc/sysctl.d/99-fabric.conf >/dev/null

echo "Konfigurasi kernel berhasil diterapkan."
EOF

done

echo
echo "Memverifikasi hasil konfigurasi kernel di seluruh node:"

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo "--- [$name] Status Modul & Forwarding ---"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" bash << 'EOF'
echo -n "IP Forwarding: " && sysctl net.ipv4.ip_forward
echo -n "Modul aktif  : " && lsmod | grep -E "^(vrf|vxlan|bridge|act_mirred)" | awk '{print $1}' | tr '\n' ' ' && echo
EOF
  echo
done

echo "Verifikasi kernel selesai dengan sukses!"
