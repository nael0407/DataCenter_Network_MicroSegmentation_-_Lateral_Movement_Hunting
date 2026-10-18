#!/usr/bin/env bash
# fabric/opnsense/test-interzone-routing.sh
# Menguji perutean antar-zona (East-West Microsegmentation) melintasi OPNsense Stateful Firewall
# Skenario: Host Zona Web (leaf1: 10.10.10.91) <-> OPNsense Gateway <-> Host Zona App (leaf2: 10.10.20.92)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_USER="dcadmin"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no"

LEAF1_IP="192.168.122.31"
LEAF2_IP="192.168.122.32"

echo "Pengujian Perutean Inter-Zona Melintasi OPNsense Firewall"
echo "Topologi: leaf1 (Web: 10.10.10.91) <-> OPNsense <-> leaf2 (App: 10.10.20.92)"

# Trap pembersihan darurat jika skrip terhenti di tengah jalan
cleanup() {
  ssh $SSH_OPTS "$SSH_USER@$LEAF1_IP" 'sudo ip netns del ns-web-l1 2>/dev/null; sudo ip link del veth-br-w1 2>/dev/null' >/dev/null 2>&1 || true
  ssh $SSH_OPTS "$SSH_USER@$LEAF2_IP" 'sudo ip netns del ns-app-l2 2>/dev/null; sudo ip link del veth-br-a2 2>/dev/null' >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Menyiapkan host uji di Zona App (leaf2)
echo "--- 1. Memasang Host Uji Sementara di leaf2 (Zona App: 10.10.20.92) ---"
ssh $SSH_OPTS "$SSH_USER@$LEAF2_IP" 'sudo bash -s' << 'EOF'
set -euo pipefail
ns="ns-app-l2"
ip netns del "$ns" 2>/dev/null || true
ip netns add "$ns"
ip link add "veth-ns-a2" type veth peer name "veth-br-a2"
ip link set "veth-ns-a2" netns "$ns"
ip link set "veth-br-a2" master br10020
ip link set "veth-br-a2" up

ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip link set "veth-ns-a2" up
ip netns exec "$ns" ip addr add 10.10.20.92/24 dev "veth-ns-a2"
# Default gateway mengarah ke OPNsense App Gateway (10.10.20.1)
ip netns exec "$ns" ip route add default via 10.10.20.1 dev "veth-ns-a2"

# Pra-resolusi ARP ke gateway lokal
ip netns exec "$ns" ping -c 1 -W 2 10.10.20.1 >/dev/null 2>&1 || true

echo "[OK] Host ns-app-l2 siap di leaf2 (IP: 10.10.20.92, Default GW: 10.10.20.1)"
EOF

# 2. Menyiapkan host uji di Zona Web (leaf1) dan menjalankan pengujian
echo
echo "--- 2. Memasang Host Uji Sementara di leaf1 (Zona Web: 10.10.10.91) ---"
ssh $SSH_OPTS "$SSH_USER@$LEAF1_IP" 'sudo bash -s' << 'EOF'
set -euo pipefail
ns="ns-web-l1"
ip netns del "$ns" 2>/dev/null || true
ip netns add "$ns"
ip link add "veth-ns-w1" type veth peer name "veth-br-w1"
ip link set "veth-ns-w1" netns "$ns"
ip link set "veth-br-w1" master br10010
ip link set "veth-br-w1" up

ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip link set "veth-ns-w1" up
ip netns exec "$ns" ip addr add 10.10.10.91/24 dev "veth-ns-w1"
# Default gateway mengarah ke OPNsense Web Gateway (10.10.10.1)
ip netns exec "$ns" ip route add default via 10.10.10.1 dev "veth-ns-w1"

# Pra-resolusi ARP ke gateway lokal
ip netns exec "$ns" ping -c 1 -W 2 10.10.10.1 >/dev/null 2>&1 || true

echo "[OK] Host ns-web-l1 siap di leaf1 (IP: 10.10.10.91, Default GW: 10.10.10.1)"

echo
echo "BAGIAN A: Uji Ping Inter-Zona (Web: 10.10.10.91 -> App: 10.10.20.92)"
echo "Melintasi: VXLAN 10010 (leaf1 -> leaf3) -> OPNsense SPI (Web -> App) -> VXLAN 10020 (leaf3 -> leaf2)"
ip netns exec "$ns" ping -c 4 -W 2 10.10.20.92

echo
echo "BAGIAN B: Uji Traceroute Inter-Zona (Pembuktian Hop OPNsense)"
echo "Hop 1 harus berupa Gateway OPNsense (10.10.10.1) dan Hop 2 adalah target (10.10.20.92):"
ip netns exec "$ns" traceroute -n -N 1 -w 2 10.10.20.92

echo
echo "BAGIAN C: Uji Frame Penuh MTU 1500 DF=1 (Don't Fragment)"
echo "Payload 1472 byte + 28 byte Header IP/ICMP = 1500 byte tanpa fragmentasi:"
ip netns exec "$ns" ping -c 3 -M do -s 1472 -W 2 10.10.20.92
EOF

# 3. Pembersihan lingkungan uji di kedua Leaf
echo
echo "--- 3. Membersihkan Namespace Pengujian Sementara di Kedua Leaf ---"
ssh $SSH_OPTS "$SSH_USER@$LEAF1_IP" 'sudo bash -s' << 'EOF'
ip netns del "ns-web-l1" 2>/dev/null || true
ip link del "veth-br-w1" 2>/dev/null || true
EOF

ssh $SSH_OPTS "$SSH_USER@$LEAF2_IP" 'sudo bash -s' << 'EOF'
ip netns del "ns-app-l2" 2>/dev/null || true
ip link del "veth-br-a2" 2>/dev/null || true
EOF

echo "[OK] Lingkungan pengujian dibersihkan secara bersih."
echo "Pengujian Perutean Inter-Zona Selesai!"
