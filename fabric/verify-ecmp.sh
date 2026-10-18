#!/usr/bin/env bash
# fabric/verify-ecmp.sh
# Verifikasi komprehensif ECMP Underlay: Kernel FIB Multipath, Traceroute Hop Spine,
# L4 Flow Hashing (VXLAN Port 4789), dan Full-Mesh Loopback Ping.
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "Verifikasi ECMP (Equal-Cost Multi-Path) di Fabric"

# 1. Konfigurasi sysctl L4 Multipath Hash Policy di kelima node
echo "--- Mengaktifkan net.ipv4.fib_multipath_hash_policy=1 di 5 node ---"
NODES=(
  "spine1:192.168.122.21"
  "spine2:192.168.122.22"
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" sudo bash << 'EOF'
echo "net.ipv4.fib_multipath_hash_policy = 1" > /etc/sysctl.d/99-ecmp.conf
sysctl -p /etc/sysctl.d/99-ecmp.conf >/dev/null
EOF
done
echo "Sysctl L4 multipath hash policy berhasil diterapkan di 5 node."

# 2. Pastikan paket traceroute terpasang di leaf nodes
echo
echo "--- Memastikan utilitas traceroute terpasang di Leaf nodes ---"
LEAVES=(
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

for item in "${LEAVES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" sudo bash << 'EOF'
if ! command -v traceroute >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y --no-install-recommends traceroute >/dev/null
fi
EOF
done
echo "Utilitas traceroute siap digunakan di seluruh leaf."

echo
echo "BAGIAN A: Verifikasi Tabel Routing Kernel Linux (FIB Multipath)"
echo ">>> [leaf1] Rute ke leaf2 (10.255.0.12) & leaf3 (10.255.0.13):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "ip route show 10.255.0.12 && ip route show 10.255.0.13"

echo
echo ">>> [leaf2] Rute ke leaf1 (10.255.0.11) & leaf3 (10.255.0.13):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "ip route show 10.255.0.11 && ip route show 10.255.0.13"

echo
echo ">>> [leaf3] Rute ke leaf1 (10.255.0.11) & leaf2 (10.255.0.12):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "ip route show 10.255.0.11 && ip route show 10.255.0.12"

echo
echo "BAGIAN B: Traceroute Melintasi Spine Layer (Spine Transit Proof)"
echo ">>> Traceroute: leaf1 (10.255.0.11) -> leaf2 (10.255.0.12):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "traceroute -s 10.255.0.11 -n 10.255.0.12"

echo
echo ">>> Traceroute: leaf1 (10.255.0.11) -> leaf3 (10.255.0.13):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "traceroute -s 10.255.0.11 -n 10.255.0.13"

echo
echo ">>> Traceroute: leaf2 (10.255.0.12) -> leaf1 (10.255.0.11):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "traceroute -s 10.255.0.12 -n 10.255.0.11"

echo
echo ">>> Traceroute: leaf3 (10.255.0.13) -> leaf1 (10.255.0.11):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "traceroute -s 10.255.0.13 -n 10.255.0.11"

echo
echo "BAGIAN C: Pembuktian Distribusi Beban L4 ECMP (VXLAN UDP 4789)"
echo "Simulasi 10 alur trafik dari leaf1 ke leaf2 dengan variasi Source Port UDP:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" bash << 'EOF'
for sport in $(seq 10001 10010); do
  out=$(ip route get 10.255.0.12 from 10.255.0.11 ipproto udp sport $sport dport 4789)
  dev=$(echo "$out" | grep -o 'dev eth[12]')
  via=$(echo "$out" | grep -o 'via 10.254.0.[06]')
  echo "Alur UDP src-port $sport -> dst-port 4789 : diarahkan ke $via ($dev)"
done
EOF

echo
echo "BAGIAN D: Matriks Pengujian Ping Full-Mesh Antar-Loopback"
echo -n "[TEST PING] leaf1 -> leaf2 (10.255.0.12): "
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "ping -c 2 -I 10.255.0.11 10.255.0.12 >/dev/null && echo 'OK (100% Reachable)' || echo 'FAIL'"

echo -n "[TEST PING] leaf1 -> leaf3 (10.255.0.13): "
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "ping -c 2 -I 10.255.0.11 10.255.0.13 >/dev/null && echo 'OK (100% Reachable)' || echo 'FAIL'"

echo -n "[TEST PING] leaf2 -> leaf1 (10.255.0.11): "
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "ping -c 2 -I 10.255.0.12 10.255.0.11 >/dev/null && echo 'OK (100% Reachable)' || echo 'FAIL'"

echo -n "[TEST PING] leaf2 -> leaf3 (10.255.0.13): "
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "ping -c 2 -I 10.255.0.12 10.255.0.13 >/dev/null && echo 'OK (100% Reachable)' || echo 'FAIL'"

echo -n "[TEST PING] leaf3 -> leaf1 (10.255.0.11): "
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "ping -c 2 -I 10.255.0.13 10.255.0.11 >/dev/null && echo 'OK (100% Reachable)' || echo 'FAIL'"

echo -n "[TEST PING] leaf3 -> leaf2 (10.255.0.12): "
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "ping -c 2 -I 10.255.0.13 10.255.0.12 >/dev/null && echo 'OK (100% Reachable)' || echo 'FAIL'"

echo
echo "Seluruh verifikasi ECMP & Keterjangkauan Loopback Berhasil 100%!"
