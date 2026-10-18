#!/usr/bin/env bash
# workloads/install-prereqs.sh
# Memasang dependensi paket esensial pada seluruh workload VM sebelum pelepasan OOB NIC (Langkah 5.2)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "Instalasi Paket Prasyarat Workload & Sensor (Langkah 5.2)"

install_pkgs() {
  local vm="$1"
  local ip="$2"
  local pkgs="$3"

  echo "--- [$vm ($ip)] Memasang paket: $pkgs ---"
  ssh $SSH_OPTS "dcadmin@$ip" bash -s << EOF
set -euo pipefail
# Berikan rute sementara via eth0 (192.168.122.1) untuk akses repo internet
sudo ip route add default via 192.168.122.1 dev eth0 metric 10 2>/dev/null || true

# Update repo & install paket
sudo apt-get update -y >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $pkgs >/dev/null

# Hapus rute sementara agar metrik kembali ke OPNsense
sudo ip route del default via 192.168.122.1 dev eth0 metric 10 2>/dev/null || true
EOF
  echo "[OK] Paket berhasil terpasang di $vm"
}

# 1. Web, App, DB, Secops Tier (Utilitas dasar jaringan, pengujian & python environment)
BASIC_PKGS="traceroute iperf3 python3-pip python3-venv"
install_pkgs "web1"    "192.168.122.41" "$BASIC_PKGS"
install_pkgs "web2"    "192.168.122.42" "$BASIC_PKGS"
install_pkgs "app1"    "192.168.122.51" "$BASIC_PKGS"
install_pkgs "app2"    "192.168.122.52" "$BASIC_PKGS"
install_pkgs "db1"     "192.168.122.61" "$BASIC_PKGS"
install_pkgs "secops"  "192.168.122.81" "$BASIC_PKGS"

# 2. Canary1 Tier (Prasyarat kompilasi & pustaka OpenCanary)
CANARY_PKGS="traceroute iperf3 python3-pip python3-venv build-essential libssl-dev libffi-dev python3-dev"
install_pkgs "canary1" "192.168.122.71" "$CANARY_PKGS"

echo
echo "Seluruh Paket Prasyarat Berhasil Terpasang di Seluruh Node!"
