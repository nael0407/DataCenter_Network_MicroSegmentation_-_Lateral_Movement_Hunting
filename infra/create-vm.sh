#!/usr/bin/env bash
# infra/create-vm.sh: Membuat VM multi-NIC dari base image Ubuntu + overlay qcow2 + cloud-init Netplan v2
set -euo pipefail

NAME="${1:?Pemakaian: $0 <nama_node> [override_vcpu] [override_ram_mb] [override_disk_gb]}"
OVERRIDE_VCPU="${2:-}"
OVERRIDE_RAM="${3:-}"
OVERRIDE_DISK="${4:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="$SCRIPT_DIR/nodes.conf"
CI_DIR="$SCRIPT_DIR/cloud-init"
POOL_DIR="/var/lib/libvirt/images"
BASE_IMG="$POOL_DIR/ubuntu-24.04-noble-20260926-base.img"
DISK="$POOL_DIR/$NAME.qcow2"
SEED="$POOL_DIR/$NAME-seed.iso"
VIRSH="virsh --connect qemu:///system"

[ -f "$CONF_FILE" ] || { echo "ERROR: $CONF_FILE tidak ditemukan!"; exit 1; }
[ -f "$CI_DIR/user-data" ] || { echo "ERROR: $CI_DIR/user-data tidak ditemukan!"; exit 1; }
[ -f "$BASE_IMG" ] || { echo "ERROR: Base image tidak ditemukan di $BASE_IMG!"; exit 1; }

# 1. Baca konfigurasi node dari nodes.conf
NODE_LINE="$(grep -E "^[[:space:]]*${NAME}\|" "$CONF_FILE" || true)"
if [ -z "$NODE_LINE" ]; then
  echo "ERROR: Node '$NAME' tidak terdaftar di $CONF_FILE!" >&2
  exit 1
fi

IFS='|' read -r _ vcpu ram disk mgmt_ip mgmt_mac additional_nics <<< "$NODE_LINE"

VCPU="${OVERRIDE_VCPU:-$(echo "$vcpu" | xargs)}"
RAM_MB="${OVERRIDE_RAM:-$(echo "$ram" | xargs)}"
DISK_GB="${OVERRIDE_DISK:-$(echo "$disk" | xargs)}"
MGMT_IP="$(echo "$mgmt_ip" | xargs)"
MGMT_MAC="$(echo "$mgmt_mac" | xargs)"
ADDITIONAL_NICS="$(echo "$additional_nics" | xargs)"

echo "=== Konfigurasi Pembuatan VM: $NAME ==="
echo "vCPU       : $VCPU"
echo "RAM        : ${RAM_MB} MB"
echo "Disk       : ${DISK_GB} GB (Overlay qcow2)"
echo "Mgmt IP    : $MGMT_IP"
echo "Mgmt MAC   : $MGMT_MAC (network: default)"
echo "Extra NICs : $ADDITIONAL_NICS"

# 2. Pemeriksaan awal: pastikan VM dan disk belum ada
if $VIRSH dominfo "$NAME" >/dev/null 2>&1; then
  echo "ERROR: VM '$NAME' sudah ada di libvirt. Hapus dulu jika ingin membuat ulang." >&2
  exit 1
fi
if [ -e "$DISK" ] || [ -e "$SEED" ]; then
  echo "ERROR: Berkas disk atau seed untuk '$NAME' sudah ada di $POOL_DIR." >&2
  exit 1
fi

# 3. Pastikan reservasi DHCP ada di network default
if ! $VIRSH net-dumpxml default | grep -qi "mac=['\"]$MGMT_MAC['\"]"; then
  echo "[DHCP] Menambahkan reservasi DHCP untuk $NAME ($MGMT_MAC -> $MGMT_IP)..."
  $VIRSH net-update default add ip-dhcp-host "<host mac='$MGMT_MAC' name='$NAME' ip='$MGMT_IP'/>" --live --config >/dev/null
fi

WORK="$(mktemp -d)"
cleanup() {
  local exit_code=$?
  rm -rf "$WORK"
  if [ $exit_code -ne 0 ]; then
    if ! $VIRSH dominfo "$NAME" >/dev/null 2>&1; then
      echo "[CLEANUP] Terjadi error. Membersihkan disk/seed yang belum terpasang untuk '$NAME'..."
      sudo rm -f "$DISK" "$SEED" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

# 4. Buat disk overlay qcow2 tipis di atas base image
echo "[DISK] Membuat overlay qcow2 ${DISK_GB}G..."
sudo qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$DISK" "${DISK_GB}G" >/dev/null

# 5. Susun Netplan v2 network-config untuk cloud-init
cat > "$WORK/meta-data" <<EOF
instance-id: $NAME
local-hostname: $NAME
EOF

cat > "$WORK/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match:
      macaddress: "$MGMT_MAC"
    set-name: eth0
    dhcp4: true
    dhcp4-overrides:
      route-metric: 100
EOF

# Parse additional NICs (format: net:mac:ifname)
VIRT_NET_ARGS=("--network" "network=default,model=virtio,mac=$MGMT_MAC")

if [ -n "$ADDITIONAL_NICS" ]; then
  IFS=',' read -ra NIC_ARR <<< "$ADDITIONAL_NICS"
  for nic_item in "${NIC_ARR[@]}"; do
    # Ekstraksi string: net_name di awal, if_name di akhir, nic_mac di tengah (mengandung titik dua)
    net_name="${nic_item%%:*}"
    rest="${nic_item#*:}"
    if_name="${rest##*:}"
    nic_mac="${rest%:*}"

    cat >> "$WORK/network-config" <<EOF
  $if_name:
    match:
      macaddress: "$nic_mac"
    set-name: $if_name
    dhcp4: false
    optional: true
EOF
    VIRT_NET_ARGS+=("--network" "network=$net_name,model=virtio,mac=$nic_mac")
  done
fi

# 6. Buat seed ISO menggunakan cloud-localds dengan opsi -N (network-config)
cloud-localds -N "$WORK/network-config" "$WORK/seed.iso" "$CI_DIR/user-data" "$WORK/meta-data"
sudo install -m 0644 "$WORK/seed.iso" "$SEED"

# 7. Eksekusi virt-install
echo "[VIRT-INSTALL] Meluncurkan VM '$NAME'..."
virt-install --connect qemu:///system \
  --name "$NAME" \
  --memory "$RAM_MB" --vcpus "$VCPU" \
  --cpu host-passthrough \
  --os-variant ubuntu24.04 \
  --boot uefi \
  --disk path="$DISK",format=qcow2,bus=virtio \
  --disk path="$SEED",device=cdrom \
  "${VIRT_NET_ARGS[@]}" \
  --graphics none \
  --import --noautoconsole

echo
echo "VM '$NAME' berhasil dibuat dan dinyalakan!"
echo "IP Manajemen : $MGMT_IP"
echo "Login SSH    : ssh -i ~/.ssh/k8s-lab dcadmin@$MGMT_IP"
echo "Konsol Serial: virsh console $NAME (Keluar: Ctrl + ])"
