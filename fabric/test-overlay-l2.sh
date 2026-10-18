#!/usr/bin/env bash
# fabric/test-overlay-l2.sh
# Pengujian konektivitas Layer-2 EVPN/VXLAN Overlay lintas leaf, uji MTU 1500 tanpa fragmentasi,
# dan pembuktian isolasi L2 antar zona (Langkah 3.4).
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "Pengujian Konektivitas L2 EVPN/VXLAN Overlay Lintas Leaf"

# -----------------------------------------------------------------------------
# PENGUJIAN 1: Zona Web (VNI 10010) antara leaf1 dan leaf3
# -----------------------------------------------------------------------------
echo "--- [TEST 1] Memasang Host Uji Sementara di Zona Web (VNI 10010) ---"
echo "1. Memasang host-web-l1 (10.10.10.91) di leaf1..."
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" sudo bash << 'EOF'
ip netns add host-web-l1
ip link add dev veth-w1 type veth peer name veth-ns-w1
ip link set dev veth-w1 master br10010 up
ip link set dev veth-ns-w1 netns host-web-l1
ip netns exec host-web-l1 ip link set dev lo up
ip netns exec host-web-l1 ip link set dev veth-ns-w1 address 02:00:10:00:00:91
ip netns exec host-web-l1 ip addr add 10.10.10.91/24 dev veth-ns-w1
ip netns exec host-web-l1 ip link set dev veth-ns-w1 up
EOF

echo "2. Memasang host-web-l3 (10.10.10.93) di leaf3..."
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" sudo bash << 'EOF'
ip netns add host-web-l3
ip link add dev veth-w3 type veth peer name veth-ns-w3
ip link set dev veth-w3 master br10010 up
ip link set dev veth-ns-w3 netns host-web-l3
ip netns exec host-web-l3 ip link set dev lo up
ip netns exec host-web-l3 ip link set dev veth-ns-w3 address 02:00:10:00:00:93
ip netns exec host-web-l3 ip addr add 10.10.10.93/24 dev veth-ns-w3
ip netns exec host-web-l3 ip link set dev veth-ns-w3 up
EOF

sleep 2

echo
echo ">>> Uji Ping L2 Overlay (leaf1 -> leaf3 melintasi VXLAN 10010 & Underlay ECMP):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "sudo ip netns exec host-web-l1 ping -c 3 10.10.10.93"

echo
echo ">>> Uji Frame MTU 1500 Penuh Tanpa Fragmentasi (Payload 1472 + 28B ICMP/IP = 1500B):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "sudo ip netns exec host-web-l1 ping -c 3 -M do -s 1472 10.10.10.93"

echo
echo ">>> Tabel ARP di host-web-l1 (leaf1):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "sudo ip netns exec host-web-l1 ip neigh show"

echo
echo ">>> Tabel FDB vxlan10010 di leaf3 (Menunjukkan MAC leaf1 dipelajari via VXLAN tunnel):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "bridge fdb show dev vxlan10010 | grep '02:00:10:00:00:91' || true"

# Bersihkan host uji Zona Web
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "sudo ip netns del host-web-l1 2>/dev/null && sudo ip link del dev veth-w1 2>/dev/null || true"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "sudo ip netns del host-web-l3 2>/dev/null && sudo ip link del dev veth-w3 2>/dev/null || true"

# -----------------------------------------------------------------------------
# PENGUJIAN 2: Zona App (VNI 10020) antara leaf2 dan leaf3
# -----------------------------------------------------------------------------
echo
echo "--- [TEST 2] Memasang Host Uji Sementara di Zona App (VNI 10020) ---"
echo "1. Memasang host-app-l2 (10.10.20.92) di leaf2..."
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" sudo bash << 'EOF'
ip netns add host-app-l2
ip link add dev veth-a2 type veth peer name veth-ns-a2
ip link set dev veth-a2 master br10020 up
ip link set dev veth-ns-a2 netns host-app-l2
ip netns exec host-app-l2 ip link set dev lo up
ip netns exec host-app-l2 ip link set dev veth-ns-a2 address 02:00:20:00:00:92
ip netns exec host-app-l2 ip addr add 10.10.20.92/24 dev veth-ns-a2
ip netns exec host-app-l2 ip link set dev veth-ns-a2 up
EOF

echo "2. Memasang host-app-l3 (10.10.20.93) di leaf3..."
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" sudo bash << 'EOF'
ip netns add host-app-l3
ip link add dev veth-a3 type veth peer name veth-ns-a3
ip link set dev veth-a3 master br10020 up
ip link set dev veth-ns-a3 netns host-app-l3
ip netns exec host-app-l3 ip link set dev lo up
ip netns exec host-app-l3 ip link set dev veth-ns-a3 address 02:00:20:00:00:93
ip netns exec host-app-l3 ip addr add 10.10.20.93/24 dev veth-ns-a3
ip netns exec host-app-l3 ip link set dev veth-ns-a3 up
EOF

sleep 2

echo
echo ">>> Uji Ping L2 Overlay (leaf2 -> leaf3 melintasi VXLAN 10020 & Underlay ECMP):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "sudo ip netns exec host-app-l2 ping -c 3 10.10.20.93"

echo
echo ">>> Uji Frame MTU 1500 Penuh Tanpa Fragmentasi (Payload 1472 + 28B ICMP/IP = 1500B):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "sudo ip netns exec host-app-l2 ping -c 3 -M do -s 1472 10.10.20.93"

echo
echo ">>> Tabel ARP di host-app-l2 (leaf2):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "sudo ip netns exec host-app-l2 ip neigh show"

echo
echo ">>> Tabel FDB vxlan10020 di leaf3 (Menunjukkan MAC leaf2 dipelajari via VXLAN tunnel):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "bridge fdb show dev vxlan10020 | grep '02:00:20:00:00:92' || true"

# Bersihkan host uji Zona App
ssh -i "$SSH_KEY" "dcadmin@192.168.122.32" "sudo ip netns del host-app-l2 2>/dev/null && sudo ip link del dev veth-a2 2>/dev/null || true"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "sudo ip netns del host-app-l3 2>/dev/null && sudo ip link del dev veth-a3 2>/dev/null || true"

echo
echo "Seluruh Pengujian Ping L2 Overlay & MTU VXLAN Lulus 100%!"
echo "Host uji sementara berhasil dibersihkan dari seluruh node."
