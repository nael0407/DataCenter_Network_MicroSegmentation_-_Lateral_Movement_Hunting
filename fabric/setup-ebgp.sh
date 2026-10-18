#!/usr/bin/env bash
# fabric/setup-ebgp.sh
# Konfigurasi eBGP Underlay, aktivasi address-family ipv4 unicast,
# advertise loopback /32, dan aktivasi ECMP (maximum-paths 64).
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "Konfigurasi eBGP Underlay & ECMP di 5 Node Fabric"

# 1. Konfigurasi spine1
echo "--- [spine1 (192.168.122.21)] Menerapkan eBGP Underlay ---"
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
 !
 neighbor 10.254.0.3 remote-as 65002
 neighbor 10.254.0.3 description leaf2
 !
 neighbor 10.254.0.5 remote-as 65003
 neighbor 10.254.0.5 description leaf3
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

# 2. Konfigurasi spine2
echo "--- [spine2 (192.168.122.22)] Menerapkan eBGP Underlay ---"
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
 !
 neighbor 10.254.0.9 remote-as 65002
 neighbor 10.254.0.9 description leaf2
 !
 neighbor 10.254.0.11 remote-as 65003
 neighbor 10.254.0.11 description leaf3
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

# 3. Konfigurasi leaf1
echo "--- [leaf1 (192.168.122.31)] Menerapkan eBGP Underlay ---"
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
 !
 neighbor 10.254.0.6 remote-as 65000
 neighbor 10.254.0.6 description spine2
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

# 4. Konfigurasi leaf2
echo "--- [leaf2 (192.168.122.32)] Menerapkan eBGP Underlay ---"
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
 !
 neighbor 10.254.0.8 remote-as 65000
 neighbor 10.254.0.8 description spine2
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

# 5. Konfigurasi leaf3
echo "--- [leaf3 (192.168.122.33)] Menerapkan eBGP Underlay ---"
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
 !
 neighbor 10.254.0.10 remote-as 65000
 neighbor 10.254.0.10 description spine2
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
echo "Menunggu konvergensi sesi BGP (5 detik)..."
sleep 5

echo
echo "Verifikasi Ringkasan BGP (show ip bgp summary) di Seluruh Node"

NODES=(
  "spine1:192.168.122.21"
  "spine2:192.168.122.22"
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo ">>> BGP Summary di $name ($ip):"
  ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@$ip" "vtysh -c 'show ip bgp summary'"
  echo
done

echo "Verifikasi Rute BGP di leaf1 (Harus memiliki multipath/ECMP ke loopback leaf lain):"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "vtysh -c 'show ip route bgp'"

echo
echo "Verifikasi Tabel Routing Kernel Linux (FIB) di leaf1:"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "ip route show | grep 'proto bgp'"
ssh -i "$SSH_KEY" -o ConnectTimeout=5 "dcadmin@192.168.122.31" "ip route show 10.255.0.12"
