#!/usr/bin/env bash
# attack-tests/setup-attack-tools.sh
# Mempersiapkan utilitas pengujian serangan (nmap, netcat, curl) pada node penguji (web1 & attacker)
# secara offline melalui cache .deb lokal (tanpa melanggar Prinsip 6.5 isolasi OOB)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"
DEB_CACHE="/tmp/nmap-debs"

echo "Penyiapan Perangkat Uji Serangan Lab (Langkah 6.1)"
echo "Target Node: web1 (10.10.10.11) & attacker (203.0.113.11)"

# 1. Pastikan paket .deb nmap lengkap ada di host
if [ ! -d "$DEB_CACHE" ] || [ ! -f "$DEB_CACHE/nmap-common_"* ]; then
    echo "--- [1/3] Mengunduh paket .deb nmap & dependensi di host ---"
    mkdir -p "$DEB_CACHE"
    (
        cd "$DEB_CACHE"
        apt-get download nmap nmap-common liblinear4 liblua5.4-0 libpcap0.8t64 libssh2-1t64 libblas3 libgfortran5 gcc-14-base
    )
else
    echo "--- [1/3] Cache paket nmap sudah tersedia di host ($DEB_CACHE) ---"
fi

# 2. Pasang nmap di web1 dan attacker
for target_ip in "10.10.10.11" "203.0.113.11"; do
    echo "--- [2/3] Memasang nmap di $target_ip via Bastion ProxyJump ---"
    scp $SSH_OPTS -r "$DEB_CACHE" dcadmin@$target_ip:/tmp/nmap-debs
    ssh $SSH_OPTS dcadmin@$target_ip 'sudo bash -s' << 'EOF'
set -euo pipefail
dpkg -i /tmp/nmap-debs/*.deb >/dev/null 2>&1 || true
# Pastikan semua paket terkonfigurasi
dpkg --configure -a >/dev/null 2>&1 || true
EOF
    ver=$(ssh $SSH_OPTS dcadmin@$target_ip "nmap --version | head -n 1")
    echo "  [OK] $target_ip: $ver"
done

echo
echo "Perangkat Uji Serangan Siap Digunakan!"
