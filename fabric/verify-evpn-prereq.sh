#!/usr/bin/env bash
# fabric/verify-evpn-prereq.sh
# Verifikasi Prasyarat Kernel Linux & FRR 8.4 untuk EVPN Bridged Overlay (L2 VNI)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "=========================================================="
echo "Verifikasi Prasyarat EVPN/VXLAN Bridged Overlay di 5 Node"
echo "=========================================================="

NODES=(
  "spine1:192.168.122.21:spine"
  "spine2:192.168.122.22:spine"
  "leaf1:192.168.122.31:leaf"
  "leaf2:192.168.122.32:leaf"
  "leaf3:192.168.122.33:leaf"
)

echo "--- 1. Verifikasi Modul Kernel (vxlan, bridge) & Sysctl ---"
for item in "${NODES[@]}"; do
  IFS=':' read -r name ip role <<< "$item"
  echo -n "[$name] "
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" bash << 'EOF'
mod_vxlan=$(lsmod | grep -c '^vxlan' || true)
mod_bridge=$(lsmod | grep -c '^bridge' || true)
fwd=$(sysctl -n net.ipv4.ip_forward)
hash_pol=$(sysctl -n net.ipv4.fib_multipath_hash_policy)

if [ "$mod_vxlan" -gt 0 ] && [ "$mod_bridge" -gt 0 ] && [ "$fwd" -eq 1 ] && [ "$hash_pol" -eq 1 ]; then
  echo "OK (Modul vxlan & bridge AKTIF, ip_forward=1, hash_policy=1)"
else
  echo "FAIL (vxlan:$mod_vxlan, bridge:$mod_bridge, fwd:$fwd, hash:$hash_pol)"
  exit 1
fi
EOF
done

echo
echo "--- 2. Verifikasi Sintaks Kernel Data-Plane (nolearning & learning off) di Leaf Nodes ---"
for item in "${NODES[@]}"; do
  IFS=':' read -r name ip role <<< "$item"
  if [ "$role" = "leaf" ]; then
    echo -n "[$name] Uji sintaks bridge & vxlan nolearning: "
    ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" sudo bash << 'EOF'
# Buat interface uji sementara
ip link add dev br-test type bridge
ip link add dev vx-test type vxlan id 99999 local 127.0.0.1 dstport 4789 nolearning
ip link set dev vx-test master br-test
bridge link set dev vx-test learning off

# Periksa status atribut detail (memerlukan flag -d)
vxlan_nolearn=$(ip -d link show dev vx-test | grep -o 'nolearning' || true)
bridge_nolearn=$(bridge -d link show dev vx-test | grep -o 'learning off' || true)

# Hapus interface uji
ip link del dev vx-test
ip link del dev br-test

if [ "$vxlan_nolearn" = "nolearning" ] && [ "$bridge_nolearn" = "learning off" ]; then
  echo "OK (Kernel mendukung nolearning pada VXLAN & learning off pada Bridge)"
else
  echo "FAIL (vxlan_nolearn:$vxlan_nolearn, bridge_nolearn:$bridge_nolearn)"
  exit 1
fi
EOF
  fi
done

echo
echo "--- 3. Verifikasi Dukungan Sintaks BGP EVPN di FRR 8.4 ---"
for item in "${NODES[@]}"; do
  IFS=':' read -r name ip role <<< "$item"
  echo -n "[$name] Dukungan address-family l2vpn evpn: "
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" bash << 'EOF'
check_cmd=$(vtysh -c "show bgp l2vpn evpn summary" 2>&1 || true)
if echo "$check_cmd" | grep -qE "No BGP neighbors|Neighbor|VRF"; then
  echo "OK (Daemon bgpd mendukung BGP EVPN)"
else
  echo "FAIL ($check_cmd)"
  exit 1
fi
EOF
done

echo
echo "--- 4. Verifikasi Dukungan 'attribute-unchanged next-hop' pada Spine Nodes ---"
for item in "${NODES[@]}"; do
  IFS=':' read -r name ip role <<< "$item"
  if [ "$role" = "spine" ]; then
    echo -n "[$name] Dukungan attribute-unchanged next-hop: "
    ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" bash << 'EOF'
help_output=$(vtysh -c "configure terminal" -c "router bgp 65000" -c "address-family l2vpn evpn" -c "neighbor 10.254.0.1 attribute-unchanged ?" 2>&1 || true)
if echo "$help_output" | grep -q "next-hop"; then
  echo "OK (FRR mendukung attribute-unchanged next-hop untuk Spine eBGP EVPN)"
else
  echo "FAIL (Opsi next-hop tidak ditemukan)"
  exit 1
fi
EOF
  fi
done

echo
echo "Seluruh prasyarat Kernel & FRR untuk EVPN Bridged Overlay LULUS 100%!"
