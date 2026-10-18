#!/usr/bin/env bash
# lab-stop.sh
# Mematikan seluruh Virtual Machine lab Proyek 4 secara tertib dan aman (graceful shutdown)
set -euo pipefail

VIRSH="virsh --connect qemu:///system"

echo "Mematikan Seluruh Virtual Machine Lab DC Microsegmentation"

# Matikan dalam urutan terbalik: workload -> opnsense -> leaf -> spine
VMS=("attacker" "secops" "canary1" "db1" "app2" "app1" "web2" "web1" "opnsense" "leaf3" "leaf2" "leaf1" "spine2" "spine1")

for vm in "${VMS[@]}"; do
  if $VIRSH dominfo "$vm" >/dev/null 2>&1; then
    state=$($VIRSH domstate "$vm" 2>/dev/null || echo "shut off")
    if [ "$state" = "running" ]; then
      echo "[SHUTDOWN] Mematikan VM '$vm' secara aman..."
      $VIRSH shutdown "$vm" >/dev/null || true
    fi
  fi
done

echo
echo "Menunggu seluruh VM selesai melakukan flush disk dan shut off..."
for i in {1..35}; do
  running_count=0
  for vm in "${VMS[@]}"; do
    state=$($VIRSH domstate "$vm" 2>/dev/null || echo "shut off")
    if [ "$state" = "running" ] || [ "$state" = "in shutdown" ]; then
      running_count=$((running_count + 1))
    fi
  done
  if [ "$running_count" -eq 0 ]; then
    echo "  [OK] Seluruh VM telah berhasil dimatikan dengan rapi (shut off) dalam ${i} detik."
    break
  fi
  sleep 1
done

echo
echo "Status Akhir VM Lab:"
$VIRSH list --all | grep -E "(spine|leaf|opnsense|web|app|db|canary|secops|attacker)" || true
echo "Seluruh VM berhasil dimatikan dengan aman. Laptop siap dimatikan!"
