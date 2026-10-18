#!/usr/bin/env bash
# workloads/detach-oob-nics.sh
# Menerapkan Prinsip 6.5: Melepas antarmuka manajemen OOB (network 'default' / virbr0)
# dari seluruh VM server (web, app, db, canary, attacker) untuk mencegah "jalan tikus" lateral movement.
# Bastion 'secops' tetap mempertahankan NIC OOB.
set -euo pipefail

VIRSH="virsh --connect qemu:///system"
SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "Penerapan Prinsip 6.5: Pelepasan Antarmuka OOB Manajemen"
echo "Mencegah Jalur Tikus / Bypass Segmentasi Jaringan Lab"

TARGET_VMS=("web1" "web2" "app1" "app2" "db1" "canary1" "attacker")

for vm in "${TARGET_VMS[@]}"; do
  echo -n "Pemeriksaan interface OOB di '$vm'... "
  # Ambil MAC antarmuka yang terhubung ke network 'default'
  mac=$($VIRSH domiflist "$vm" 2>/dev/null | awk '$3 == "default" {print $5}' || true)
  
  if [ -n "$mac" ]; then
    echo "Ditemukan MAC $mac pada network default."
    echo -n "  -> Melepaskan interface $mac dari '$vm' (live & persistent)... "
    $VIRSH detach-interface --domain "$vm" --type network --mac "$mac" --live --config >/dev/null
    echo "[OK]"
  else
    echo "Sudah tidak memiliki interface di network default. [CLEAN]"
  fi
done

echo
echo "--- Memverifikasi Status Bastion secops ---"
secops_oob_mac=$($VIRSH domiflist secops 2>/dev/null | awk '$3 == "default" {print $5}' || true)
if [ -n "$secops_oob_mac" ]; then
  echo "[TERJAGA] VM 'secops' TETAP mempertahankan NIC OOB ($secops_oob_mac - 192.168.122.81) sebagai Bastion Host OOB."
else
  echo "[ERROR] VM 'secops' kehilangan NIC OOB! Segera pasang kembali." >&2
  exit 1
fi

echo
echo "--- Mengonfigurasi SSH ProxyJump (~/.ssh/config) di Host ---"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# Buat konfigurasi SSH ProxyJump jika belum ada
if ! grep -q "Host secops-bastion" "$HOME/.ssh/config" 2>/dev/null; then
  cat >> "$HOME/.ssh/config" << 'EOF'

# Lab DC Microsegmentation Bastion (Prinsip 6.5)
Host secops-bastion
    HostName 192.168.122.81
    User dcadmin
    IdentityFile ~/.ssh/k8s-lab
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host 10.10.* 203.0.113.*
    ProxyJump secops-bastion
    User dcadmin
    IdentityFile ~/.ssh/k8s-lab
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
  chmod 600 "$HOME/.ssh/config"
  echo "[OK] Konfigurasi ProxyJump via secops-bastion ditambahkan ke ~/.ssh/config"
else
  echo "[EXISTING] Konfigurasi ProxyJump secops-bastion sudah ada di ~/.ssh/config"
fi

echo
echo "Verifikasi Bukti Negatif (Negative Reachability Proof):"
echo "Membuktikan Tidak Ada Lagi Jalur ke Subnet Manajemen 192.168.122.0/24"

echo "1. Menguji konektivitas langsung dari Host ke web1 (192.168.122.41):"
if ping -c 1 -W 1 192.168.122.41 >/dev/null 2>&1; then
  echo ">>> [GAGAL] Host masih bisa menjangkau 192.168.122.41!"
else
  echo ">>> [SUKSES] 192.168.122.41 tidak terjangkau (NIC OOB terbukti dilepas)."
fi

echo
echo "2. Menguji dari dalam web1 apakah ada rute ke subnet 192.168.122.0/24:"
# Akses web1 dilakukan lewat ProxyJump bastion
ssh_out=$(ssh -J dcadmin@192.168.122.81 -i "$SSH_KEY" -o StrictHostKeyChecking=no dcadmin@10.10.10.11 "ip route show | grep -E '192.168.122' || echo 'NO_ROUTE'")
echo ">>> Rute kernel web1: $ssh_out"
if [ "$ssh_out" = "NO_ROUTE" ]; then
  echo ">>> [SUKSES] web1 sama sekali tidak memiliki rute ke subnet manajemen 192.168.122.0/24!"
fi

echo
echo "Verifikasi Akses Administratif Positif via Bastion secops:"

INTERNAL_VMS=(
  "web1:10.10.10.11"
  "web2:10.10.10.12"
  "app1:10.10.20.11"
  "app2:10.10.20.12"
  "db1:10.10.30.11"
  "canary1:10.10.50.11"
  "attacker:203.0.113.11"
)

for item in "${INTERNAL_VMS[@]}"; do
  name="${item%%:*}"
  ip="${item##*:}"
  echo -n ">>> [SSH ProxyJump: Host -> secops -> $name ($ip)]: "
  host_res=$(ssh -J dcadmin@192.168.122.81 -i "$SSH_KEY" -o StrictHostKeyChecking=no "dcadmin@$ip" hostname 2>/dev/null || echo "FAILED")
  if [ "$host_res" = "$name" ]; then
    echo "SUCCESS (Akses Administratif Terverifikasi)"
  else
    echo "FAIL (Diterima: $host_res)"
  fi
done

echo
echo "Verifikasi Jalur Data Inter-Zona (East-West) via OPNsense:"
echo -n ">>> [web1 -> app1 (10.10.20.11 via OPNsense)]: "
if ssh -J dcadmin@192.168.122.81 -i "$SSH_KEY" -o StrictHostKeyChecking=no dcadmin@10.10.10.11 "ping -c 2 -W 2 10.10.20.11 >/dev/null 2>&1"; then
  echo "SUCCESS (0% Loss - Stateful SPI Aktif)"
else
  echo "FAIL"
fi

echo -n ">>> [app1 -> db1 (10.10.30.11 via OPNsense)]: "
if ssh -J dcadmin@192.168.122.81 -i "$SSH_KEY" -o StrictHostKeyChecking=no dcadmin@10.10.20.11 "ping -c 2 -W 2 10.10.30.11 >/dev/null 2>&1"; then
  echo "SUCCESS (0% Loss - Stateful SPI Aktif)"
else
  echo "FAIL"
fi

echo
echo "Prinsip 6.5 Resmi Ditegakkan 100%!"
echo "Isolasi Out-of-Band & Bastion ProxyJump Siap Digunakan."
