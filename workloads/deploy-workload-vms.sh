#!/usr/bin/env bash
# workloads/deploy-workload-vms.sh
# Meluncurkan 8 Virtual Machine Workload & Sensor (Fase 5) dan mengonfigurasi IP data per zona
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRA_DIR="$ROOT_DIR/infra"
SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
VIRSH="virsh --connect qemu:///system"

WORKLOADS=("web1" "web2" "app1" "app2" "db1" "canary1" "secops" "attacker")

echo "=========================================================="
echo "Penyebaran VM Workload, Sensor, & Attacker (8 Node - Fase 5)"
echo "=========================================================="

# 1. Pembuatan VM menggunakan create-vm.sh
for vm in "${WORKLOADS[@]}"; do
  if $VIRSH dominfo "$vm" >/dev/null 2>&1; then
    state=$($VIRSH domstate "$vm" 2>/dev/null || echo "shut off")
    if [ "$state" = "running" ]; then
      echo "[EXISTING] VM '$vm' sudah ada dan menyala."
    else
      echo "[START]    Menyalakan VM '$vm'..."
      $VIRSH start "$vm" >/dev/null
    fi
  else
    echo "[CREATE]   Membuat VM '$vm' via create-vm.sh..."
    "$INFRA_DIR/create-vm.sh" "$vm"
  fi
done

echo
echo "--- Menunggu bootstrap cloud-init dan akses SSH siap di seluruh 8 VM ---"
IP_MAP=(
  "web1:192.168.122.41"
  "web2:192.168.122.42"
  "app1:192.168.122.51"
  "app2:192.168.122.52"
  "db1:192.168.122.61"
  "canary1:192.168.122.71"
  "secops:192.168.122.81"
  "attacker:192.168.122.91"
)

for entry in "${IP_MAP[@]}"; do
  vm="${entry%%:*}"
  ip="${entry##*:}"
  echo -n "Menunggu SSH di $vm ($ip)... "
  until ssh $SSH_OPTS "dcadmin@$ip" "cloud-init status --wait >/dev/null 2>&1" 2>/dev/null; do
    echo -n "."
    sleep 3
  done
  echo " [SIAP]"
done

echo
echo "=========================================================="
echo "Menerapkan Konfigurasi Jaringan Netplan Data-Plane (60-data.yaml)"
echo "=========================================================="

apply_netplan() {
  local ip="$1"
  local yaml_content="$2"
  ssh $SSH_OPTS "dcadmin@$ip" "sudo bash -c 'cat > /etc/netplan/60-data.yaml << \"EOF\"
$yaml_content
EOF
chmod 600 /etc/netplan/60-data.yaml
netplan apply'"
}

# 1. web1 (10.10.10.11/24) di Leaf1 Web Zone
echo "--- [web1] Konfigurasi eth1: 10.10.10.11/24 (GW: 10.10.10.1) ---"
apply_netplan "192.168.122.41" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 10.10.10.11/24
      routes:
        - to: default
          via: 10.10.10.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 2. web2 (10.10.10.12/24) di Leaf1 Web Zone
echo "--- [web2] Konfigurasi eth1: 10.10.10.12/24 (GW: 10.10.10.1) ---"
apply_netplan "192.168.122.42" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 10.10.10.12/24
      routes:
        - to: default
          via: 10.10.10.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 3. app1 (10.10.20.11/24) di Leaf2 App Zone
echo "--- [app1] Konfigurasi eth1: 10.10.20.11/24 (GW: 10.10.20.1) ---"
apply_netplan "192.168.122.51" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 10.10.20.11/24
      routes:
        - to: default
          via: 10.10.20.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 4. app2 (10.10.20.12/24) di Leaf2 App Zone
echo "--- [app2] Konfigurasi eth1: 10.10.20.12/24 (GW: 10.10.20.1) ---"
apply_netplan "192.168.122.52" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 10.10.20.12/24
      routes:
        - to: default
          via: 10.10.20.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 5. db1 (10.10.30.11/24) di Leaf3 DB Zone
echo "--- [db1] Konfigurasi eth1: 10.10.30.11/24 (GW: 10.10.30.1) ---"
apply_netplan "192.168.122.61" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 10.10.30.11/24
      routes:
        - to: default
          via: 10.10.30.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 6. canary1 (10.10.50.11/24) di Leaf3 Decoy Zone
echo "--- [canary1] Konfigurasi eth1: 10.10.50.11/24 (GW: 10.10.50.1) ---"
apply_netplan "192.168.122.71" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 10.10.50.11/24
      routes:
        - to: default
          via: 10.10.50.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 7. secops (10.10.40.11/24) di Leaf3 SecOps Zone & 3 Sensor NIC
echo "--- [secops] Konfigurasi eth4: 10.10.40.11/24 & eth1-3 (Sensors) ---"
apply_netplan "192.168.122.81" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      optional: true
    eth2:
      dhcp4: false
      optional: true
    eth3:
      dhcp4: false
      optional: true
    eth4:
      dhcp4: false
      addresses:
        - 10.10.40.11/24
      routes:
        - to: 10.10.0.0/16
          via: 10.10.40.1
        - to: 203.0.113.0/24
          via: 10.10.40.1
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

# 8. attacker (203.0.113.11/24) di WAN Simulation (ext-sim)
echo "--- [attacker] Konfigurasi eth1: 203.0.113.11/24 (GW: 203.0.113.1) ---"
apply_netplan "192.168.122.91" 'network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses:
        - 203.0.113.11/24
      routes:
        - to: default
          via: 203.0.113.1
          metric: 50
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]'

echo
echo "=========================================================="
echo "Verifikasi Keterjangkauan Gateway OPNsense dari Tiap Workload:"
echo "=========================================================="

test_gw_ping() {
  local vm="$1"
  local mgmt_ip="$2"
  local gw_ip="$3"
  echo -n ">>> [$vm -> Gateway $gw_ip]: "
  if ssh $SSH_OPTS "dcadmin@$mgmt_ip" "ping -c 2 -W 2 $gw_ip >/dev/null 2>&1"; then
    echo "SUCCESS (0% Loss)"
  else
    echo "FAIL"
  fi
}

test_gw_ping "web1" "192.168.122.41" "10.10.10.1"
test_gw_ping "web2" "192.168.122.42" "10.10.10.1"
test_gw_ping "app1" "192.168.122.51" "10.10.20.1"
test_gw_ping "app2" "192.168.122.52" "10.10.20.1"
test_gw_ping "db1"  "192.168.122.61" "10.10.30.1"
test_gw_ping "canary1" "192.168.122.71" "10.10.50.1"
test_gw_ping "secops"  "192.168.122.81" "10.10.40.1"
test_gw_ping "attacker" "192.168.122.91" "203.0.113.1"

echo
echo "=========================================================="
echo "Verifikasi Konektivitas Intra-Zona & Inter-Zona:"
echo "=========================================================="
echo -n ">>> [Intra-Zone Web: web1 -> web2 (10.10.10.12)]: "
if ssh $SSH_OPTS "dcadmin@192.168.122.41" "ping -c 2 -W 2 10.10.10.12 >/dev/null 2>&1"; then
  echo "SUCCESS (L2 Bridge Lokal Leaf1)"
else
  echo "FAIL"
fi

echo -n ">>> [Intra-Zone App: app1 -> app2 (10.10.20.12)]: "
if ssh $SSH_OPTS "dcadmin@192.168.122.51" "ping -c 2 -W 2 10.10.20.12 >/dev/null 2>&1"; then
  echo "SUCCESS (L2 Bridge Lokal Leaf2)"
else
  echo "FAIL"
fi

echo -n ">>> [Inter-Zone: web1 -> app1 (10.10.20.11 via OPNsense)]: "
if ssh $SSH_OPTS "dcadmin@192.168.122.41" "ping -c 2 -W 2 10.10.20.11 >/dev/null 2>&1"; then
  echo "SUCCESS (Melintasi OPNsense Stateful Firewall)"
else
  echo "FAIL"
fi

echo -n ">>> [Inter-Zone: app1 -> db1 (10.10.30.11 via OPNsense)]: "
if ssh $SSH_OPTS "dcadmin@192.168.122.51" "ping -c 2 -W 2 10.10.30.11 >/dev/null 2>&1"; then
  echo "SUCCESS (Melintasi OPNsense Stateful Firewall)"
else
  echo "FAIL"
fi

echo
echo "=========================================================="
echo "Seluruh 8 VM Workload Berhasil Dideploy & Terverifikasi!"
echo "=========================================================="
