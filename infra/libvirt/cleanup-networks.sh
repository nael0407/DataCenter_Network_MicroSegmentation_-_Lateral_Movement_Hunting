#!/usr/bin/env bash
# infra/libvirt/cleanup-networks.sh
# Mematikan dan menghapus 16 jaringan libvirt isolated
set -euo pipefail

VIRSH="virsh --connect qemu:///system"

NETWORKS=(
  "lnk-s1-l1" "lnk-s1-l2" "lnk-s1-l3"
  "lnk-s2-l1" "lnk-s2-l2" "lnk-s2-l3"
  "acc-l1" "acc-l2"
  "acc-l3-db" "acc-l3-dec" "acc-l3-mgmt"
  "trunk-fw" "ext-sim"
  "mirror-l1" "mirror-l2" "mirror-l3"
)

echo "Mematikan dan menghapus jaringan lab libvirt..."

for net in "${NETWORKS[@]}"; do
  if $VIRSH net-info "$net" >/dev/null 2>&1; then
    if $VIRSH net-list | grep -qw "$net"; then
      echo "Stopping $net..."
      $VIRSH net-destroy "$net" >/dev/null || true
    fi
    echo "Undefining $net..."
    $VIRSH net-undefine "$net" >/dev/null || true
  fi
done

echo "Seluruh jaringan lab libvirt telah dihapus."
