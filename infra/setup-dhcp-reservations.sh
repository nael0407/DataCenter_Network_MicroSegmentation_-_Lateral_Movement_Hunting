#!/usr/bin/env bash
# infra/setup-dhcp-reservations.sh
# Mendaftarkan reservasi DHCP untuk seluruh node lab di jaringan libvirt "default"
set -euo pipefail

VIRSH="virsh --connect qemu:///system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="$SCRIPT_DIR/nodes.conf"

[ -f "$CONF_FILE" ] || { echo "ERROR: $CONF_FILE tidak ditemukan!"; exit 1; }

echo "=========================================================="
echo "Memeriksa dan mendaftarkan reservasi DHCP di network 'default'..."
echo "=========================================================="

CURRENT_XML="$($VIRSH net-dumpxml default)"

# Baca nodes.conf (abaikan komentar dan baris kosong)
grep -v '^[[:space:]]*#' "$CONF_FILE" | grep -v '^[[:space:]]*$' | while IFS='|' read -r name vcpu ram disk ip mac nics; do
  name="$(echo "$name" | xargs)"
  ip="$(echo "$ip" | xargs)"
  mac="$(echo "$mac" | xargs)"

  # Cek apakah MAC atau IP sudah terdaftar
  if echo "$CURRENT_XML" | grep -qi "mac=['\"]$mac['\"]"; then
    echo "[EXISTS] Reservasi untuk $name ($mac -> $ip) sudah ada."
  else
    echo "[ADD]    Mendaftarkan $name ($mac -> $ip)..."
    XML_ENTRY="<host mac='$mac' name='$name' ip='$ip'/>"
    $VIRSH net-update default add ip-dhcp-host "$XML_ENTRY" --live --config >/dev/null
  fi
done

echo
echo "Verifikasi entri DHCP Proyek 4 di network 'default':"
$VIRSH net-dumpxml default | grep -E "52:54:00:04" || true
echo
echo "Pendaftaran reservasi DHCP selesai!"
