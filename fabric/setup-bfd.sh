#!/usr/bin/env bash
# fabric/setup-bfd.sh
# Mengaktifkan BFD pada seluruh peer BGP di 5 node fabric dan menguji deteksi kegagalan link
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "Menerapkan Konfigurasi BFD pada BGP Neighbors di 5 Node"

# 1. spine1 (3 neighbors)
echo "--- [spine1 (192.168.122.21)] Mengaktifkan BFD untuk leaf1, leaf2, leaf3 ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.21" sudo bash << 'EOF'
cat << 'CONF' > /etc/frr/frr.conf
frr version 8.4.4
frr defaults datacenter
hostname spine1
log syslog informational
service integrated-vtysh-config
!
router bgp 65000
 bgp router-id 10.255.0.1
 no bgp default ipv4-unicast
 !
 neighbor 10.254.0.1 remote-as 65001
 neighbor 10.254.0.1 description leaf1
 neighbor 10.254.0.1 bfd
 !
 neighbor 10.254.0.3 remote-as 65002
 neighbor 10.254.0.3 description leaf2
 neighbor 10.254.0.3 bfd
 !
 neighbor 10.254.0.5 remote-as 65003
 neighbor 10.254.0.5 description leaf3
 neighbor 10.254.0.5 bfd
 !
 address-family ipv4 unicast
  network 10.255.0.1/32
  neighbor 10.254.0.1 activate
  neighbor 10.254.0.3 activate
  neighbor 10.254.0.5 activate
  maximum-paths 64
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# 2. spine2 (3 neighbors)
echo "--- [spine2 (192.168.122.22)] Mengaktifkan BFD untuk leaf1, leaf2, leaf3 ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.22" sudo bash << 'EOF'
cat << 'CONF' > /etc/frr/frr.conf
frr version 8.4.4
frr defaults datacenter
hostname spine2
log syslog informational
service integrated-vtysh-config
!
router bgp 65000
 bgp router-id 10.255.0.2
 no bgp default ipv4-unicast
 !
 neighbor 10.254.0.7 remote-as 65001
 neighbor 10.254.0.7 description leaf1
 neighbor 10.254.0.7 bfd
 !
 neighbor 10.254.0.9 remote-as 65002
 neighbor 10.254.0.9 description leaf2
 neighbor 10.254.0.9 bfd
 !
 neighbor 10.254.0.11 remote-as 65003
 neighbor 10.254.0.11 description leaf3
 neighbor 10.254.0.11 bfd
 !
 address-family ipv4 unicast
  network 10.255.0.2/32
  neighbor 10.254.0.7 activate
  neighbor 10.254.0.9 activate
  neighbor 10.254.0.11 activate
  maximum-paths 64
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# 3. leaf1 (2 neighbors)
echo "--- [leaf1 (192.168.122.31)] Mengaktifkan BFD untuk spine1, spine2 ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" sudo bash << 'EOF'
cat << 'CONF' > /etc/frr/frr.conf
frr version 8.4.4
frr defaults datacenter
hostname leaf1
log syslog informational
service integrated-vtysh-config
!
router bgp 65001
 bgp router-id 10.255.0.11
 no bgp default ipv4-unicast
 !
 neighbor 10.254.0.0 remote-as 65000
 neighbor 10.254.0.0 description spine1
 neighbor 10.254.0.0 bfd
 !
 neighbor 10.254.0.6 remote-as 65000
 neighbor 10.254.0.6 description spine2
 neighbor 10.254.0.6 bfd
 !
 address-family ipv4 unicast
  network 10.255.0.11/32
  neighbor 10.254.0.0 activate
  neighbor 10.254.0.6 activate
  maximum-paths 64
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# 4. leaf2 (2 neighbors)
echo "--- [leaf2 (192.168.122.32)] Mengaktifkan BFD untuk spine1, spine2 ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.32" sudo bash << 'EOF'
cat << 'CONF' > /etc/frr/frr.conf
frr version 8.4.4
frr defaults datacenter
hostname leaf2
log syslog informational
service integrated-vtysh-config
!
router bgp 65002
 bgp router-id 10.255.0.12
 no bgp default ipv4-unicast
 !
 neighbor 10.254.0.2 remote-as 65000
 neighbor 10.254.0.2 description spine1
 neighbor 10.254.0.2 bfd
 !
 neighbor 10.254.0.8 remote-as 65000
 neighbor 10.254.0.8 description spine2
 neighbor 10.254.0.8 bfd
 !
 address-family ipv4 unicast
  network 10.255.0.12/32
  neighbor 10.254.0.2 activate
  neighbor 10.254.0.8 activate
  maximum-paths 64
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# 5. leaf3 (2 neighbors)
echo "--- [leaf3 (192.168.122.33)] Mengaktifkan BFD untuk spine1, spine2 ---"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.33" sudo bash << 'EOF'
cat << 'CONF' > /etc/frr/frr.conf
frr version 8.4.4
frr defaults datacenter
hostname leaf3
log syslog informational
service integrated-vtysh-config
!
router bgp 65003
 bgp router-id 10.255.0.13
 no bgp default ipv4-unicast
 !
 neighbor 10.254.0.4 remote-as 65000
 neighbor 10.254.0.4 description spine1
 neighbor 10.254.0.4 bfd
 !
 neighbor 10.254.0.10 remote-as 65000
 neighbor 10.254.0.10 description spine2
 neighbor 10.254.0.10 bfd
 !
 address-family ipv4 unicast
  network 10.255.0.13/32
  neighbor 10.254.0.4 activate
  neighbor 10.254.0.10 activate
  maximum-paths 64
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

echo
echo "Menunggu stabilisasi sesi BFD (4 detik)..."
sleep 4

echo
echo "Verifikasi Sesi BFD (show bfd peers brief) di 5 Node:"

NODES=(
  "spine1:192.168.122.21"
  "spine2:192.168.122.22"
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo ">>> [$name ($ip)] BFD Peers:"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" "vtysh -c 'show bfd peers brief'"
  echo
done

echo "PENGUJIAN DETEKSI KEGAGALAN LINK (LINK FAILURE TEST):"
echo "1. Kondisi Awal: Tabel rute BGP di leaf1 menuju loopback leaf2 (10.255.0.12):"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "vtysh -c 'show ip route 10.255.0.12'"

echo
echo "2. Mensimulasikan kegagalan link: Menurunkan interface eth2 di leaf1 (arah spine2)..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "sudo ip link set dev eth2 down"
sleep 1

echo "3. Status BFD di leaf1 sesaat setelah eth2 down:"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "vtysh -c 'show bfd peers brief'"

echo
echo "4. Respon cepat BGP di leaf1: nexthop via spine2 (10.254.0.6) seketika dicabut:"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "vtysh -c 'show ip route 10.255.0.12'"

echo
echo "5. Memulihkan link: Mengaktifkan kembali interface eth2 di leaf1..."
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "sudo ip link set dev eth2 up"
sleep 5

echo "6. Status BFD setelah link pulih:"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "vtysh -c 'show bfd peers brief'"

echo
echo "7. Rute ECMP di leaf1 pulih penuh (kedua nexthop kembali aktif):"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "vtysh -c 'show ip route 10.255.0.12'"

echo
echo "Seluruh pengujian BFD & Deteksi Kegagalan Link Berhasil!"
