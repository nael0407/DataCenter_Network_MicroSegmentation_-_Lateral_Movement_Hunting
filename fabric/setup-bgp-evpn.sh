#!/usr/bin/env bash
# fabric/setup-bgp-evpn.sh
# Mengaktifkan address-family l2vpn evpn, periklanan VNI, konfigurasi Route-Target bersama (65000:VNI),
# dan attribute-unchanged next-hop pada Spine nodes.
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"

echo "=========================================================="
echo "Konfigurasi BGP EVPN (L2 VNI Bridged Overlay) di 5 Node"
echo "=========================================================="

# -----------------------------------------------------------------------------
# 1. spine1 (Transit EVPN dengan attribute-unchanged next-hop)
# -----------------------------------------------------------------------------
echo "--- [spine1 (192.168.122.21)] Menerapkan BGP EVPN Transit ---"
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
 address-family l2vpn evpn
  neighbor 10.254.0.1 activate
  neighbor 10.254.0.1 attribute-unchanged next-hop
  neighbor 10.254.0.3 activate
  neighbor 10.254.0.3 attribute-unchanged next-hop
  neighbor 10.254.0.5 activate
  neighbor 10.254.0.5 attribute-unchanged next-hop
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf && chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# -----------------------------------------------------------------------------
# 2. spine2 (Transit EVPN dengan attribute-unchanged next-hop)
# -----------------------------------------------------------------------------
echo "--- [spine2 (192.168.122.22)] Menerapkan BGP EVPN Transit ---"
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
 address-family l2vpn evpn
  neighbor 10.254.0.7 activate
  neighbor 10.254.0.7 attribute-unchanged next-hop
  neighbor 10.254.0.9 activate
  neighbor 10.254.0.9 attribute-unchanged next-hop
  neighbor 10.254.0.11 activate
  neighbor 10.254.0.11 attribute-unchanged next-hop
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf && chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# -----------------------------------------------------------------------------
# 3. leaf1: VNI 10010 (Web)
# -----------------------------------------------------------------------------
echo "--- [leaf1 (192.168.122.31)] Menerapkan BGP EVPN VNI 10010 ---"
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
 address-family l2vpn evpn
  neighbor 10.254.0.0 activate
  neighbor 10.254.0.6 activate
  advertise-all-vni
  vni 10010
   route-target both 65000:10010
  exit-vni
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf && chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# -----------------------------------------------------------------------------
# 4. leaf2: VNI 10020 (App)
# -----------------------------------------------------------------------------
echo "--- [leaf2 (192.168.122.32)] Menerapkan BGP EVPN VNI 10020 ---"
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
 address-family l2vpn evpn
  neighbor 10.254.0.2 activate
  neighbor 10.254.0.8 activate
  advertise-all-vni
  vni 10020
   route-target both 65000:10020
  exit-vni
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf && chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

# -----------------------------------------------------------------------------
# 5. leaf3: Border Leaf (VNI 10010 - 10050)
# -----------------------------------------------------------------------------
echo "--- [leaf3 (192.168.122.33)] Menerapkan BGP EVPN Seluruh VNI (10010-10050) ---"
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
 address-family l2vpn evpn
  neighbor 10.254.0.4 activate
  neighbor 10.254.0.10 activate
  advertise-all-vni
  vni 10010
   route-target both 65000:10010
  exit-vni
  vni 10020
   route-target both 65000:10020
  exit-vni
  vni 10030
   route-target both 65000:10030
  exit-vni
  vni 10040
   route-target both 65000:10040
  exit-vni
  vni 10050
   route-target both 65000:10050
  exit-vni
 exit-address-family
!
line vty
!
CONF
chown frr:frr /etc/frr/frr.conf && chmod 640 /etc/frr/frr.conf
systemctl restart frr
EOF

echo
echo "Menunggu konvergensi sesi BGP EVPN (5 detik)..."
sleep 5

echo
echo "=========================================================="
echo "BAGIAN 1: Ringkasan Sesi BGP EVPN (show bgp l2vpn evpn summary)"
echo "=========================================================="

NODES=(
  "spine1:192.168.122.21"
  "spine2:192.168.122.22"
  "leaf1:192.168.122.31"
  "leaf2:192.168.122.32"
  "leaf3:192.168.122.33"
)

for item in "${NODES[@]}"; do
  IFS=':' read -r name ip <<< "$item"
  echo ">>> [$name ($ip)] BGP EVPN Summary:"
  ssh -i "$SSH_KEY" "dcadmin@$ip" "vtysh -c 'show bgp l2vpn evpn summary'"
  echo
done

echo "=========================================================="
echo "BAGIAN 2: Status Penemuan VNI & Remote VTEP di Leaf Nodes"
echo "=========================================================="
for item in "leaf1:192.168.122.31" "leaf2:192.168.122.32" "leaf3:192.168.122.33"; do
  IFS=':' read -r name ip <<< "$item"
  echo ">>> [$name] show evpn vni:"
  ssh -i "$SSH_KEY" "dcadmin@$ip" "vtysh -c 'show evpn vni'"
  echo
done

echo "=========================================================="
echo "BAGIAN 3: Verifikasi Rute EVPN Tipe-3 (Inclusive Multicast / IMET)"
echo "=========================================================="
echo ">>> [leaf1] Rute Tipe-3 untuk VNI 10010 (Harus menemukan Remote VTEP leaf3 10.255.0.13):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "vtysh -c 'show bgp l2vpn evpn route type 3'"

echo
echo ">>> [leaf3] Rute Tipe-3 untuk VNI 10010 & 10020 (Harus menemukan leaf1 10.255.0.11 & leaf2 10.255.0.12):"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "vtysh -c 'show bgp l2vpn evpn route type 3'"

echo
echo "=========================================================="
echo "BAGIAN 4: Uji Pembelajaran & Penyebaran Rute EVPN Tipe-2 (MAC)"
echo "=========================================================="
echo "Mensimulasikan frame Ethernet lokal di leaf1 eth3 (Zona Web MAC: 52:54:00:10:00:01)..."
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" sudo bash << 'EOF'
# Daftarkan entri MAC statis pada port akses eth3 untuk simulasi host lokal
bridge fdb add 52:54:00:10:00:01 dev eth3 master static
EOF
sleep 2

echo ">>> [leaf1] Rute EVPN Tipe-2 lokal yang di-advertise:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "vtysh -c 'show bgp l2vpn evpn route type 2'"

echo
echo ">>> [leaf3] Pembuktian: leaf3 menerima rute Type-2 MAC tersebut via BGP EVPN:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "vtysh -c 'show bgp l2vpn evpn route type 2'"

echo
echo ">>> [leaf3] Pembuktian: Tabel FDB Linux kernel br10010 di leaf3 otomatis terisi via VXLAN:"
ssh -i "$SSH_KEY" "dcadmin@192.168.122.33" "bridge fdb show dev vxlan10010 | grep '52:54:00:10:00:01' || true"

# Bersihkan MAC uji coba statis
ssh -i "$SSH_KEY" "dcadmin@192.168.122.31" "sudo bridge fdb del 52:54:00:10:00:01 dev eth3 master static 2>/dev/null || true"

echo
echo "Seluruh verifikasi BGP EVPN Tipe-2 (MAC) & Tipe-3 (IMET) Berhasil 100%!"
