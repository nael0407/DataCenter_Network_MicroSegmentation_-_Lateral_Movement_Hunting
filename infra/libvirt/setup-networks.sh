#!/usr/bin/env bash
# infra/libvirt/setup-networks.sh
# Mendefinisikan dan menyalakan 16 jaringan libvirt isolated (L2 murni, MTU 9000, tanpa forward, tanpa DHCP)
set -euo pipefail

VIRSH="virsh --connect qemu:///system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Daftar jaringan: "nama_network:nama_bridge:deskripsi"
# Catatan: Nama bridge maksimal 15 karakter (batasan Linux IFNAMSIZ)
NETWORKS=(
  # Underlay Point-to-Point (P2P) antar Spine dan Leaf
  "lnk-s1-l1:br-s1-l1:Underlay P2P Spine1 ke Leaf1"
  "lnk-s1-l2:br-s1-l2:Underlay P2P Spine1 ke Leaf2"
  "lnk-s1-l3:br-s1-l3:Underlay P2P Spine1 ke Leaf3"
  "lnk-s2-l1:br-s2-l1:Underlay P2P Spine2 ke Leaf1"
  "lnk-s2-l2:br-s2-l2:Underlay P2P Spine2 ke Leaf2"
  "lnk-s2-l3:br-s2-l3:Underlay P2P Spine2 ke Leaf3"

  # Akses segmen Leaf1 dan Leaf2
  "acc-l1:br-acc-l1:Segmen Akses Leaf1 (Zona Web)"
  "acc-l2:br-acc-l2:Segmen Akses Leaf2 (Zona App)"

  # Akses segmen Leaf3 per zona (terisolasi penuh di level host)
  "acc-l3-db:br-acc-l3-db:Segmen Akses Leaf3 (Zona DB)"
  "acc-l3-dec:br-acc-l3-dec:Segmen Akses Leaf3 (Zona Decoy)"
  "acc-l3-mgmt:br-acc-l3-mgmt:Segmen Akses Leaf3 (Zona SecOps)"

  # Trunk ke Firewall OPNsense & Eksternal Internet Simulasi
  "trunk-fw:br-trunk-fw:Trunk 802.1Q Leaf3 ke OPNsense"
  "ext-sim:br-ext-sim:Jaringan Simulasi Publik/Internet (OPNsense - Attacker)"

  # Jaringan Port Mirroring ke SecOps (Zeek)
  "mirror-l1:br-mir-l1:Mirror Trafik Ingress Leaf1 ke SecOps"
  "mirror-l2:br-mir-l2:Mirror Trafik Ingress Leaf2 ke SecOps"
  "mirror-l3:br-mir-l3:Mirror Trafik Ingress Leaf3 ke SecOps"
)

echo "=========================================================="
echo "Membuat dan mengaktifkan 16 jaringan libvirt isolated..."
echo "=========================================================="

for item in "${NETWORKS[@]}"; do
  IFS=":" read -r net_name br_name desc <<< "$item"
  xml_file="$WORK_DIR/$net_name.xml"

  # Validasi panjang nama bridge
  if [ "${#br_name}" -gt 15 ]; then
    echo "ERROR: Nama bridge '$br_name' melebihi 15 karakter!" >&2
    exit 1
  fi

  cat > "$xml_file" <<EOF
<network>
  <name>$net_name</name>
  <bridge name='$br_name' stp='off' delay='0'/>
  <mtu size='9000'/>
</network>
EOF

  # Cek apakah network sudah ada
  if $VIRSH net-info "$net_name" >/dev/null 2>&1; then
    echo "[EXISTS] Jaringan '$net_name' sudah terdefinisi."
  else
    echo "[DEFINE] Mendefinisikan '$net_name' (bridge: $br_name, MTU: 9000) - $desc"
    $VIRSH net-define "$xml_file" >/dev/null
  fi

  # Pastikan autostart aktif
  $VIRSH net-autostart "$net_name" >/dev/null

  # Nyalakan jika belum aktif
  if ! $VIRSH net-list | grep -qw "$net_name"; then
    echo "[START]  Menyalakan jaringan '$net_name'..."
    $VIRSH net-start "$net_name" >/dev/null
  fi
done

echo
echo "=========================================================="
echo "Verifikasi status seluruh jaringan libvirt:"
echo "=========================================================="
$VIRSH net-list --all

echo
echo "Setup jaringan selesai dengan sukses!"
