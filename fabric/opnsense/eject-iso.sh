#!/usr/bin/env bash
# fabric/opnsense/eject-iso.sh
# Melepas media ISO dari VM OPNsense pasca-instalasi agar booting langsung dari disk utama
set -euo pipefail

VIRSH="virsh --connect qemu:///system"
NAME="opnsense"

echo "Melepas Media ISO dari VM: $NAME"

TARGET_DEV=$($VIRSH domblklist "$NAME" | grep -i "\.iso" | awk '{print $1}' || true)

if [ -n "$TARGET_DEV" ]; then
  echo "Menemukan perangkat CD-ROM pada target: $TARGET_DEV"
  $VIRSH change-media "$NAME" "$TARGET_DEV" --eject --config
  echo "[OK] Media ISO berhasil dilepas secara permanen dari konfigurasi VM."
else
  echo "[INFO] Tidak ditemukan media ISO terpasang pada VM '$NAME'."
fi

echo "Status blok disk saat ini:"
$VIRSH domblklist "$NAME"
