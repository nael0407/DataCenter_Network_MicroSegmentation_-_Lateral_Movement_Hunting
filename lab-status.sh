#!/usr/bin/env bash
# lab-status.sh
# Menampilkan ringkasan status kesehatan seluruh VM dan konektivitas fabric lab
set -euo pipefail

VIRSH="virsh --connect qemu:///system"

echo "=========================================================="
echo "Kesehatan Infrastruktur Lab DC Microsegmentation"
echo "=========================================================="

echo "--- 1. Status Domain VM di Libvirt ---"
$VIRSH list --all | grep -E "(spine|leaf|opnsense|web|app|db|canary|secops|attacker)" || true

echo
echo "--- 2. Penggunaan Memori Host ---"
free -h | grep -E "(Mem:|Swap:)"

echo
echo "--- 3. Pemeriksaan Singkat Gateway OPNsense (10.10.10.1 - 10.10.50.1) ---"
if $VIRSH domstate opnsense 2>/dev/null | grep -q "running"; then
  echo "VM 'opnsense' aktif. Menguji respon ping Web GUI (192.168.122.20):"
  if ping -c 1 -W 2 192.168.122.20 >/dev/null 2>&1; then
    echo "[OK] OPNsense Web GUI / SSH terjangkau di 192.168.122.20"
  else
    echo "[WARN] OPNsense belum merespons di 192.168.122.20 (sedang booting)"
  fi
else
  echo "[INFO] VM 'opnsense' sedang mati (shut off)."
fi

echo "=========================================================="
