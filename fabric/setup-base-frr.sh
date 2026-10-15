#!/usr/bin/env bash
# fabric/setup-base-frr.sh
# Mengaktifkan daemon bgpd & bfdd, menambahkan dcadmin ke grup frrvty,
# serta mengonfigurasi basis BGP (ASN, router-id) di 5 node fabric.
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

# Format: hostname:mgmt_ip:asn:router_id
NODES=(
  "spine1:192.168.122.21:65000:10.255.0.1"
  "spine2:192.168.122.22:65000:10.255.0.2"
  "leaf1:192.168.122.31:65001:10.255.0.11"
  "leaf2:192.168.122.32:65002:10.255.0.12"
  "leaf3:192.168.122.33:65003:10.255.0.13"
)

echo "=========================================================="
echo "Konfigurasi Dasar FRR (Daemons, Grup VTY, & BGP Router-ID)"
echo "=========================================================="

for node_info in "${NODES[@]}"; do
  IFS=':' read -r name ip asn router_id <<< "$node_info"
  echo "--- [$name ($ip)] Menerapkan konfigurasi dasar FRR ---"

  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" sudo bash -s "$name" "$asn" "$router_id" << 'EOF'
set -euo pipefail
NODE_NAME="$1"
ASN="$2"
ROUTER_ID="$3"

# 1. Aktifkan bgpd dan bfdd di /etc/frr/daemons
sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons

# 2. Tambahkan user dcadmin ke grup frr dan frrvty
usermod -aG frr,frrvty dcadmin

# 3. Tulis konfigurasi dasar /etc/frr/frr.conf
cat << CONF > /etc/frr/frr.conf
frr version 8.4.4
frr defaults datacenter
hostname ${NODE_NAME}
log syslog informational
service integrated-vtysh-config
!
router bgp ${ASN}
 bgp router-id ${ROUTER_ID}
 no bgp default ipv4-unicast
!
line vty
!
CONF

# 4. Atur kepemilikan dan izin akses file
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf

# 5. Restart service FRR
systemctl restart frr
EOF

done

echo
echo "=========================================================="
echo "Verifikasi Status Daemon & Running-Config di Semua Node:"
echo "=========================================================="

for node_info in "${NODES[@]}"; do
  IFS=':' read -r name ip asn router_id <<< "$node_info"
  echo ">>> [$name] Daemons aktif:"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" "vtysh -c 'show daemons'"
  echo ">>> [$name] BGP Base Config:"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" "vtysh -c 'show running-config' | grep -E 'hostname|router bgp|bgp router-id'"
  echo
done

echo "Konfigurasi dasar FRR berhasil diterapkan di seluruh node fabric!"
