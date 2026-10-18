#!/usr/bin/env bash
# infra/setup-underlay-ips.sh
# Mengonfigurasi IP loopback /32 dan link point-to-point /31 (MTU 9000) pada seluruh node fabric via Netplan
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "Menerapkan konfigurasi IP Underlay & MTU 9000 pada 5 node..."

# 1. Konfigurasi spine1
echo "[spine1] Menerapkan IP Loopback & P2P /31..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 dcadmin@192.168.122.21 sudo bash << 'EOF'
cat << 'NET' > /etc/netplan/60-underlay.yaml
network:
  version: 2
  ethernets:
    lo:
      match:
        name: lo
      addresses:
        - 10.255.0.1/32
    eth1:
      addresses:
        - 10.254.0.0/31
      mtu: 9000
    eth2:
      addresses:
        - 10.254.0.2/31
      mtu: 9000
    eth3:
      addresses:
        - 10.254.0.4/31
      mtu: 9000
NET
chmod 600 /etc/netplan/60-underlay.yaml
netplan apply
EOF

# 2. Konfigurasi spine2
echo "[spine2] Menerapkan IP Loopback & P2P /31..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 dcadmin@192.168.122.22 sudo bash << 'EOF'
cat << 'NET' > /etc/netplan/60-underlay.yaml
network:
  version: 2
  ethernets:
    lo:
      match:
        name: lo
      addresses:
        - 10.255.0.2/32
    eth1:
      addresses:
        - 10.254.0.6/31
      mtu: 9000
    eth2:
      addresses:
        - 10.254.0.8/31
      mtu: 9000
    eth3:
      addresses:
        - 10.254.0.10/31
      mtu: 9000
NET
chmod 600 /etc/netplan/60-underlay.yaml
netplan apply
EOF

# 3. Konfigurasi leaf1
echo "[leaf1] Menerapkan IP Loopback & P2P /31..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 dcadmin@192.168.122.31 sudo bash << 'EOF'
cat << 'NET' > /etc/netplan/60-underlay.yaml
network:
  version: 2
  ethernets:
    lo:
      match:
        name: lo
      addresses:
        - 10.255.0.11/32
    eth1:
      addresses:
        - 10.254.0.1/31
      mtu: 9000
    eth2:
      addresses:
        - 10.254.0.7/31
      mtu: 9000
NET
chmod 600 /etc/netplan/60-underlay.yaml
netplan apply
EOF

# 4. Konfigurasi leaf2
echo "[leaf2] Menerapkan IP Loopback & P2P /31..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 dcadmin@192.168.122.32 sudo bash << 'EOF'
cat << 'NET' > /etc/netplan/60-underlay.yaml
network:
  version: 2
  ethernets:
    lo:
      match:
        name: lo
      addresses:
        - 10.255.0.12/32
    eth1:
      addresses:
        - 10.254.0.3/31
      mtu: 9000
    eth2:
      addresses:
        - 10.254.0.9/31
      mtu: 9000
NET
chmod 600 /etc/netplan/60-underlay.yaml
netplan apply
EOF

# 5. Konfigurasi leaf3
echo "[leaf3] Menerapkan IP Loopback & P2P /31..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 dcadmin@192.168.122.33 sudo bash << 'EOF'
cat << 'NET' > /etc/netplan/60-underlay.yaml
network:
  version: 2
  ethernets:
    lo:
      match:
        name: lo
      addresses:
        - 10.255.0.13/32
    eth1:
      addresses:
        - 10.254.0.5/31
      mtu: 9000
    eth2:
      addresses:
        - 10.254.0.11/31
      mtu: 9000
NET
chmod 600 /etc/netplan/60-underlay.yaml
netplan apply
EOF

echo
echo "Pengujian Ping Tetangga P2P & Uji Jumbo Frame (MTU 9000):"

TESTS=(
  # node_asal:ip_node:ip_target:nama_link
  "spine1:192.168.122.21:10.254.0.1:lnk-s1-l1 (spine1 -> leaf1)"
  "spine1:192.168.122.21:10.254.0.3:lnk-s1-l2 (spine1 -> leaf2)"
  "spine1:192.168.122.21:10.254.0.5:lnk-s1-l3 (spine1 -> leaf3)"
  "spine2:192.168.122.22:10.254.0.7:lnk-s2-l1 (spine2 -> leaf1)"
  "spine2:192.168.122.22:10.254.0.9:lnk-s2-l2 (spine2 -> leaf2)"
  "spine2:192.168.122.22:10.254.0.11:lnk-s2-l3 (spine2 -> leaf3)"
)

ALL_PASSED=true

for t in "${TESTS[@]}"; do
  IFS=':' read -r src_name src_ip dst_ip desc <<< "$t"
  echo -n "[TEST] Ping $desc: "
  
  # Ping standar (paket kecil)
  if ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$src_ip" "ping -c 2 -W 2 $dst_ip" >/dev/null 2>&1; then
    echo -n "OK (L3 Reachable) | "
  else
    echo "GAGAL (Ping standar timeout)!"
    ALL_PASSED=false
    continue
  fi

  # Ping Jumbo Frame MTU 9000 (payload 8972 + ICMP 8 + IP 20 = 9000 bytes)
  if ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$src_ip" "ping -c 2 -W 2 -M do -s 8972 $dst_ip" >/dev/null 2>&1; then
    echo "OK (Jumbo 9000B No Fragmentation)"
  else
    echo "GAGAL (Jumbo Frame MTU 9000 drop/fragment)!"
    ALL_PASSED=false
  fi
done

echo
if [ "$ALL_PASSED" = true ]; then
  echo "SELURUH 6 LINK UNDERLAY P2P BERHASIL TERHUBUNG & TERVERIFIKASI MTU 9000!"
else
  echo "PERINGATAN: Ada link yang gagal. Periksa koneksi interface."
  exit 1
fi
