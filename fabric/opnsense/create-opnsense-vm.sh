#!/usr/bin/env bash
# fabric/opnsense/create-opnsense-vm.sh
# Membuat dan meluncurkan VM OPNsense 24.7 di KVM/libvirt dengan 3 NIC VirtIO
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POOL_DIR="/var/lib/libvirt/images"
ISO_SOURCE="$SCRIPT_DIR/iso/OPNsense-24.7-dvd-amd64.iso"
ISO_DEST="$POOL_DIR/OPNsense-24.7-dvd-amd64.iso"
DISK="$POOL_DIR/opnsense.qcow2"
NAME="opnsense"
VIRSH="virsh --connect qemu:///system"

echo "=========================================================="
echo "Pembuatan Virtual Machine: $NAME (OPNsense 24.7)"
echo "=========================================================="

# 1. Validasi prasyarat berkas ISO
if [ ! -f "$ISO_SOURCE" ] && [ ! -f "$ISO_DEST" ]; then
  echo "ERROR: Berkas ISO OPNsense tidak ditemukan!" >&2
  echo "Jalankan './fabric/opnsense/download-opnsense.sh' terlebih dahulu." >&2
  exit 1
fi

# 2. Pindahkan atau salin ISO ke storage pool libvirt jika belum ada
if [ ! -f "$ISO_DEST" ]; then
  echo "--- Menempatkan ISO di $POOL_DIR ---"
  sudo cp "$ISO_SOURCE" "$ISO_DEST"
  sudo chmod 0644 "$ISO_DEST"
fi

# 3. Pemeriksaan keberadaan domain VM di libvirt
if $VIRSH dominfo "$NAME" >/dev/null 2>&1; then
  echo "ERROR: VM '$NAME' sudah ada di libvirt!" >&2
  echo "Hapus terlebih dahulu jika ingin membuat ulang: virsh destroy $NAME && virsh undefine $NAME --remove-all-storage" >&2
  exit 1
fi

if [ -f "$DISK" ]; then
  echo "WARNING: Berkas disk $DISK sudah ada. Menghapus disk lama..."
  sudo rm -f "$DISK"
fi

# 4. Verifikasi reservasi DHCP di network default
MGMT_MAC="52:54:00:04:00:20"
MGMT_IP="192.168.122.20"
if ! $VIRSH net-dumpxml default | grep -qi "mac=['\"]$MGMT_MAC['\"]"; then
  echo "[DHCP] Mendaftarkan reservasi DHCP untuk $NAME ($MGMT_MAC -> $MGMT_IP)..."
  $VIRSH net-update default add ip-dhcp-host "<host mac='$MGMT_MAC' name='$NAME' ip='$MGMT_IP'/>" --live --config >/dev/null
fi

# 5. Meluncurkan virt-install untuk VM OPNsense
echo "--- Menjalankan virt-install untuk VM '$NAME' ---"
virt-install --connect qemu:///system \
  --name "$NAME" \
  --memory 2048 \
  --vcpus 2 \
  --cpu host-passthrough \
  --os-variant freebsd14.1 \
  --disk path="$DISK",size=20,format=qcow2,bus=virtio \
  --cdrom "$ISO_DEST" \
  --network network=default,model=virtio,mac=52:54:00:04:00:20 \
  --network network=trunk-fw,model=virtio,mac=52:54:00:04:36:20 \
  --network network=ext-sim,model=virtio,mac=52:54:00:04:91:20 \
  --graphics vnc,listen=0.0.0.0 \
  --serial pty --console pty,target_type=serial \
  --boot hd,cdrom \
  --noautoconsole

echo
echo "=========================================================="
echo "VM '$NAME' Berhasil Dibuat dan Sedang Berjalan!"
echo "=========================================================="
VNC_PORT="$($VIRSH vncdisplay $NAME 2>/dev/null || echo 'N/A')"
echo "Alokasi Antarmuka VirtIO:"
echo "  1. vtnet0 (MAC 52:54:00:04:00:20) -> libvirt 'default' (Mgmt/LAN GUI: 192.168.122.20)"
echo "  2. vtnet1 (MAC 52:54:00:04:36:20) -> libvirt 'trunk-fw' (802.1Q Trunk ke leaf3 eth6)"
echo "  3. vtnet2 (MAC 52:54:00:04:91:20) -> libvirt 'ext-sim' (WAN Simulator: 203.0.113.1)"
echo
echo "Display VNC: $VNC_PORT"
echo
echo "Cara Mengakses Pemasangan OPNsense:"
echo "  [OPSI A - Antarmuka Grafis (Disarankan)]:"
echo "    virt-viewer --connect qemu:///system $NAME &"
echo
echo "  [OPSI B - Konsol Teks/Serial]:"
echo "    virsh --connect qemu:///system console $NAME"
echo "    (Tekan Ctrl + ] untuk keluar dari konsol virsh)"
echo "=========================================================="
