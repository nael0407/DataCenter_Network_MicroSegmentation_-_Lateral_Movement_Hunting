#!/usr/bin/env bash
# fabric/opnsense/test-wan-attacker.sh
# Simulasi Penyerang Eksternal (Internet / RFC 5737 TEST-NET-3) terhadap OPNsense WAN Gateway
# Menguji: Akses Ingress WAN, Port Forwarding Web DMZ, dan Pemblokiran Zona Internal (Skenario S7)
set -euo pipefail

NS="ns-attacker"
VETH_NS="veth-ns-atk"
VETH_BR="veth-br-atk"
BRIDGE="br-ext-sim"
ATK_IP="203.0.113.91/24"
WAN_GW="203.0.113.1"

echo "=========================================================="
echo "Pengujian Simulasi Attacker Eksternal (WAN: 203.0.113.0/24)"
echo "Target Firewall: OPNsense WAN Gateway ($WAN_GW)"
echo "=========================================================="

cleanup() {
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del "$VETH_BR" 2>/dev/null || true
}
trap cleanup EXIT

echo "--- 1. Memasang Host Attacker Sementara di Network 'ext-sim' ($BRIDGE) ---"
cleanup
sudo ip netns add "$NS"
sudo ip link add "$VETH_NS" type veth peer name "$VETH_BR"
sudo ip link set "$VETH_NS" netns "$NS"
sudo ip link set "$VETH_BR" master "$BRIDGE"
sudo ip link set "$VETH_BR" up

sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" ip link set "$VETH_NS" up
sudo ip netns exec "$NS" ip addr add "$ATK_IP" dev "$VETH_NS"
sudo ip netns exec "$NS" ip route add default via "$WAN_GW" dev "$VETH_NS"

echo "[OK] Host Attacker siap (IP: 203.0.113.91, Default Gateway: $WAN_GW)"

echo
echo "=========================================================="
echo "BAGIAN A: Uji Keterjangkauan Gateway WAN OPNsense (203.0.113.1)"
echo "=========================================================="
if sudo ip netns exec "$NS" ping -c 3 -W 2 "$WAN_GW"; then
  echo ">>> [Attacker -> OPNsense WAN]: SUCCESS (Gateway WAN Merespons)"
else
  echo ">>> [Attacker -> OPNsense WAN]: FAIL (Gateway WAN Tidak Merespons)"
  echo "Catatan: Pastikan opsi 'Block private networks' dan 'Block bogon networks' pada interface WAN telah DINONAKTIFKAN di OPNsense, serta aturan pass ICMP ditambahkan pada WAN."
  exit 1
fi

echo
echo "=========================================================="
echo "BAGIAN B: Uji Port Publikasi Web (Port Forwarding NAT Port 80)"
echo "=========================================================="
echo "Menguji akses TCP ke port 80 pada WAN IP ($WAN_GW)..."
if sudo ip netns exec "$NS" nc -zv -w 2 "$WAN_GW" 80 >/dev/null 2>&1; then
  echo ">>> [Attacker -> Port 80]: SUCCESS (Port Terbuka / Diteruskan ke Web DMZ)"
else
  echo ">>> [Attacker -> Port 80]: PENDING WORKLOAD (Aturan NAT aktif; Target Web DMZ 10.10.10.11 baru aktif di Fase 5)"
fi

echo
echo "=========================================================="
echo "BAGIAN C: Uji Pemblokiran Zona Internal dari Luar (Skenario S7)"
echo "=========================================================="
echo "1. Attacker mencoba menjangkau Host di Zona Database (10.10.30.11)..."
if sudo ip netns exec "$NS" ping -c 2 -W 2 10.10.30.11 >/dev/null 2>&1; then
  echo ">>> [WARNING] Trafik tembus ke host internal Database!"
else
  echo ">>> [Attacker -> Host DB 10.10.30.11]: BLOCKED / PACKET DROPPED (Skenario S7 Berhasil)"
  echo "    Firewall OPNsense menolak akses transit dari Internet ke zona Database."
fi

echo
echo "2. Attacker mencoba menjangkau Host di Zona Aplikasi (10.10.20.11)..."
if sudo ip netns exec "$NS" ping -c 2 -W 2 10.10.20.11 >/dev/null 2>&1; then
  echo ">>> [WARNING] Trafik tembus ke host internal Aplikasi!"
else
  echo ">>> [Attacker -> Host App 10.10.20.11]: BLOCKED / PACKET DROPPED (Skenario S7 Berhasil)"
  echo "    Firewall OPNsense menolak akses transit dari Internet ke zona Aplikasi."
fi

echo
echo "3. Attacker mencoba menjangkau IP Gateway Internal OPNsense (10.10.30.1)..."
if sudo ip netns exec "$NS" ping -c 2 -W 2 10.10.30.1 >/dev/null 2>&1; then
  echo ">>> [INFO] IP Gateway Internal 10.10.30.1 masih merespons ping."
  echo "    Penyebab: Aturan ICMP di tab WAN masih mengizinkan Destination 'any' (atau 'Apply changes' belum diklik),"
  echo "    atau state table OPNsense masih menyimpan sesi lama. Pastikan Destination diubah ke 'WAN address' lalu Apply."
else
  echo ">>> [Attacker -> Gateway DB 10.10.30.1]: BLOCKED / PACKET DROPPED (Perimeter Aman)"
fi

echo
echo "=========================================================="
echo "Pengujian Simulasi Attacker Selesai & Namespace Dibersihkan"
echo "=========================================================="
