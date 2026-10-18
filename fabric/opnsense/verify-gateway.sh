#!/usr/bin/env bash
# fabric/opnsense/verify-gateway.sh
# Memverifikasi keterjangkauan L2/L3 dari Fabric Leaf ke seluruh Gateway OPNsense (10.10.10.1 - 10.10.50.1)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_USER="dcadmin"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no"

LEAF1_IP="192.168.122.31"
LEAF2_IP="192.168.122.32"
LEAF3_IP="192.168.122.33"

echo "Verifikasi Keterjangkauan Gateway OPNsense dari Fabric"

# 1. Uji Ping dari Border Leaf (leaf3) ke seluruh 5 Gateway VLAN
echo "--- [BAGIAN 1] Uji Keterjangkauan Gateway Langsung dari leaf3 (Trunk 802.1Q) ---"

ssh $SSH_OPTS "$SSH_USER@$LEAF3_IP" 'sudo bash -s' << 'EOF'
set -euo pipefail

test_gw() {
  local vlan_id="$1"
  local br_name="br100${vlan_id}"
  local gw_ip="10.10.${vlan_id}.1"
  local test_ip="10.10.${vlan_id}.93/24"
  local ns="ns-test-gw-${vlan_id}"

  # Bersihkan namespace lama jika ada
  ip netns del "$ns" 2>/dev/null || true

  # Buat namespace dan veth pair
  ip netns add "$ns"
  ip link add "veth-ns" type veth peer name "veth-br"
  ip link set "veth-ns" netns "$ns"
  ip link set "veth-br" master "$br_name"
  ip link set "veth-br" up

  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set "veth-ns" up
  ip netns exec "$ns" ip addr add "$test_ip" dev "veth-ns"

  echo -n ">>> [leaf3 -> Gateway $gw_ip (VLAN $vlan_id)]: "
  if ip netns exec "$ns" ping -c 2 -W 2 "$gw_ip" >/dev/null 2>&1; then
    echo "SUCCESS (Gateway Merespons)"
  else
    echo "FAIL (Gateway Tidak Merespons / Ping Timeout)"
  fi

  # Bersihkan namespace
  ip netns del "$ns" 2>/dev/null || true
  ip link del "veth-br" 2>/dev/null || true
}

test_gw 10
test_gw 20
test_gw 30
test_gw 40
test_gw 50
EOF

# 2. Uji Ping dari leaf1 ke Gateway Web (10.10.10.1) melintasi EVPN Overlay VXLAN 10010
echo
echo "--- [BAGIAN 2] Uji Keterjangkauan Gateway Web dari leaf1 (Melintasi EVPN VXLAN 10010) ---"
ssh $SSH_OPTS "$SSH_USER@$LEAF1_IP" 'sudo bash -s' << 'EOF'
set -euo pipefail
ns="ns-test-l1-gw"
ip netns del "$ns" 2>/dev/null || true
ip netns add "$ns"
ip link add "veth-ns" type veth peer name "veth-br"
ip link set "veth-ns" netns "$ns"
ip link set "veth-br" master br10010
ip link set "veth-br" up
ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip link set "veth-ns" up
ip netns exec "$ns" ip addr add "10.10.10.91/24" dev "veth-ns"

echo "Ping dari leaf1 (10.10.10.91) ke Gateway OPNsense (10.10.10.1):"
if ip netns exec "$ns" ping -c 3 -W 2 10.10.10.1; then
  echo ">>> [leaf1 -> OPNsense GW Web]: SUCCESS (L2 EVPN Overlay -> OPNsense Berfungsi Penuh)"
else
  echo ">>> [leaf1 -> OPNsense GW Web]: FAIL"
fi

ip netns del "$ns" 2>/dev/null || true
ip link del "veth-br" 2>/dev/null || true
EOF

# 3. Uji Ping dari leaf2 ke Gateway App (10.10.20.1) melintasi EVPN Overlay VXLAN 10020
echo
echo "--- [BAGIAN 3] Uji Keterjangkauan Gateway App dari leaf2 (Melintasi EVPN VXLAN 10020) ---"
ssh $SSH_OPTS "$SSH_USER@$LEAF2_IP" 'sudo bash -s' << 'EOF'
set -euo pipefail
ns="ns-test-l2-gw"
ip netns del "$ns" 2>/dev/null || true
ip netns add "$ns"
ip link add "veth-ns" type veth peer name "veth-br"
ip link set "veth-ns" netns "$ns"
ip link set "veth-br" master br10020
ip link set "veth-br" up
ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip link set "veth-ns" up
ip netns exec "$ns" ip addr add "10.10.20.92/24" dev "veth-ns"

echo "Ping dari leaf2 (10.10.20.92) ke Gateway OPNsense (10.10.20.1):"
if ip netns exec "$ns" ping -c 3 -W 2 10.10.20.1; then
  echo ">>> [leaf2 -> OPNsense GW App]: SUCCESS (L2 EVPN Overlay -> OPNsense Berfungsi Penuh)"
else
  echo ">>> [leaf2 -> OPNsense GW App]: FAIL"
fi

ip netns del "$ns" 2>/dev/null || true
ip link del "veth-br" 2>/dev/null || true
EOF

echo
echo "Pengujian Verifikasi Gateway Selesai!"
