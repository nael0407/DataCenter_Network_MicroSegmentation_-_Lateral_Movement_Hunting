#!/usr/bin/env bash
# fabric/setup-frr-install.sh
# Memasang paket FRRouting dari repositori resmi Ubuntu 24.04 (Noble) dan mengunci versinya di 5 node
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
NODES=(
  "spine1:192.168.122.21"
  "spine2:192.168.122.22"
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

echo "=========================================================="
echo "Memasang dan mengunci versi FRRouting (FRR) di 5 node..."
echo "=========================================================="

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo "--- [$name ($ip)] Menginstal FRR ---"

  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" sudo bash << 'EOF'
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y --no-install-recommends frr frr-pythontools >/dev/null

# Kunci versi paket agar tidak ter-upgrade otomatis
apt-mark hold frr frr-pythontools >/dev/null

echo "FRR berhasil diinstal dan versinya dikunci."
EOF

done

echo
echo "=========================================================="
echo "Verifikasi versi FRR yang terpasang di seluruh node:"
echo "=========================================================="

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo -n "[$name] "
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" "dpkg -l frr | grep '^hi '"
done

echo
echo "Pemasangan FRR selesai dengan sukses!"
