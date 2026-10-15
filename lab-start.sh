#!/usr/bin/env bash
# lab-start.sh
# Menyalakan seluruh Virtual Machine lab Proyek 4 secara bertahap dan teratur
set -euo pipefail

VIRSH="virsh --connect qemu:///system"

echo "=========================================================="
echo "Menyalakan Seluruh Virtual Machine Lab DC Microsegmentation"
echo "=========================================================="

# Daftar VM berdasarkan urutan dependensi
VMS=("spine1" "spine2" "leaf1" "leaf2" "leaf3" "opnsense" "web1" "web2" "app1" "app2" "db1" "canary1" "secops" "attacker")

for vm in "${VMS[@]}"; do
  # Cek apakah domain VM sudah terdefinisi di libvirt
  if $VIRSH dominfo "$vm" >/dev/null 2>&1; then
    state=$($VIRSH domstate "$vm" 2>/dev/null || echo "unknown")
    if [ "$state" = "running" ]; then
      echo "[RUNNING] VM '$vm' sudah menyala."
    else
      echo "[START]   Menyalakan VM '$vm'..."
      $VIRSH start "$vm" >/dev/null
    fi
  fi
done

echo
echo "Menunggu stabilisasi inisialisasi jaringan (8 detik)..."
sleep 8

echo
echo "=========================================================="
echo "Status Seluruh VM Lab Saat Ini:"
$VIRSH list --all | grep -E "(spine|leaf|opnsense|web|app|db|canary|secops|attacker)" || true
echo "=========================================================="
echo "Lab siap digunakan!"
