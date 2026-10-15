# Dokumen 01: Infrastruktur Virtualisasi Libvirt dan Fabrikasi Node Fabric

> **Proyek 4: Data Center Network Micro-segmentation dan Lateral Movement Hunting**  
> Penulis: Natanael  
> Tanggal: 15 Oktober 2026  
> Status: Selesai (Fase 1)

---

## 1. Tujuan Fase 1

Fase 1 meletakkan fondasi infrastruktur fisik (virtual) untuk data center fabric:
1. Membangun 16 segmen jaringan libvirt isolated (L2 murni tanpa DHCP/NAT, MTU 9000, STP off).
2. Memperluas skrip otomasi `create-vm.sh` dari Proyek 3 agar mendukung arsitektur *multi-NIC* dengan MAC address deterministik dan Netplan v2 via cloud-init.
3. Meluncurkan dan mem-bootstrap 5 VM jaringan (**`spine1`**, **`spine2`**, **`leaf1`**, **`leaf2`**, **`leaf3`**) menggunakan overlay disk QCOW2 tipis di atas base image Ubuntu 24.04.
4. Menyiapkan kernel Linux pada kelima node agar siap untuk perutean BGP underlay, enkapsulasi VXLAN, VRF, dan telemetri *packet mirroring* (`tc`).
5. Mengonfigurasi skema pengalamatan underlay: IP link point-to-point **/31** (RFC 3021) dan IP Loopback **/32**, serta membuktikan integritas transmisi paket standar maupun **Jumbo Frame MTU 9000** tanpa fragmentasi.

---

## 2. Jaringan Libvirt Isolated (Langkah 1.1)

Sebanyak 16 jaringan virtual murni Layer 2 didefinisikan menggunakan template XML tanpa tag `<forward>` dan tanpa tag `<ip>`:

```xml
<network>
  <name>lnk-s1-l1</name>
  <bridge name='br-s1-l1' stp='off' delay='0'/>
  <mtu size='9000'/>
</network>
```

### Tabel Status 16 Jaringan Libvirt:
| Nama Jaringan | Bridge Linux | MTU | Fungsi Topologi | Status |
|---|---|---|---|---|
| `lnk-s1-l1` s/d `lnk-s1-l3` | `br-s1-l1` s/d `br-s1-l3` | 9000 | Underlay P2P Spine1 ke Leaf1-3 | Active (yes) |
| `lnk-s2-l1` s/d `lnk-s2-l3` | `br-s2-l1` s/d `br-s2-l3` | 9000 | Underlay P2P Spine2 ke Leaf1-3 | Active (yes) |
| `acc-l1` | `br-acc-l1` | 9000 | Akses Zona Web di Leaf1 | Active (yes) |
| `acc-l2` | `br-acc-l2` | 9000 | Akses Zona App di Leaf2 | Active (yes) |
| `acc-l3-db` | `br-acc-l3-db` | 9000 | Akses Zona DB di Leaf3 | Active (yes) |
| `acc-l3-dec` | `br-acc-l3-dec` | 9000 | Akses Zona Decoy di Leaf3 | Active (yes) |
| `acc-l3-mgmt` | `br-acc-l3-mgmt` | 9000 | Akses Zona SecOps di Leaf3 | Active (yes) |
| `trunk-fw` | `br-trunk-fw` | 9000 | Trunk 802.1Q Leaf3 ke OPNsense | Active (yes) |
| `ext-sim` | `br-ext-sim` | 9000 | Simulasi Publik OPNsense ke Attacker | Active (yes) |
| `mirror-l1` s/d `mirror-l3` | `br-mir-l1` s/d `br-mir-l3` | 9000 | Port Mirroring Ingress Leaf1-3 ke SecOps | Active (yes) |

---

## 3. Otomasi Multi-NIC & Cloud-Init Netplan (Langkah 1.2)

Dibuat berkas deklaratif [`infra/nodes.conf`](file:///home/lavvvet/dc-microseg-lab/infra/nodes.conf) dan skrip [`infra/create-vm.sh`](file:///home/lavvvet/dc-microseg-lab/infra/create-vm.sh).

### Poin Desain Penting:
1. **Penamaan Interface Deterministik**: Menggunakan Netplan v2 dengan pencocokan hardware address (`match: macaddress`) dan penamaan manual (`set-name: eth0`, `eth1`, dst.). Ini mencegah acaknya urutan interface bus PCI di Linux.
2. **Eliminasi Boot Delay (`optional: true`)**: Interface non-manajemen (`eth1` s/d `eth7`) ditandai `optional: true` dan `dhcp4: false`, sehingga `systemd-networkd-wait-online` tidak menahan waktu boot sistem.
3. **Reservasi DHCP Persisten**: Skrip [`infra/setup-dhcp-reservations.sh`](file:///home/lavvvet/dc-microseg-lab/infra/setup-dhcp-reservations.sh) mendaftarkan MAC deterministik `52:54:00:04:xx:yy` ke jaringan `default` libvirt menggunakan `virsh net-update` on-the-fly.

---

## 4. Peluncuran Node & Hasil Pemetaan Interface (Langkah 1.3)

Kelima node fabric berhasil dibuat dan diuji secara non-interaktif dari host:

```text
=== spine1 (192.168.122.21) ===
eth0 : 52:54:00:04:00:01 (mgmt)
eth1 : 52:54:00:04:11:01 (lnk-s1-l1)
eth2 : 52:54:00:04:12:01 (lnk-s1-l2)
eth3 : 52:54:00:04:13:01 (lnk-s1-l3)

=== spine2 (192.168.122.22) ===
eth0 : 52:54:00:04:00:02 (mgmt)
eth1 : 52:54:00:04:21:02 (lnk-s2-l1)
eth2 : 52:54:00:04:22:02 (lnk-s2-l2)
eth3 : 52:54:00:04:23:02 (lnk-s2-l3)

=== leaf1 (192.168.122.31) ===
eth0 : 52:54:00:04:00:11 (mgmt)
eth1 : 52:54:00:04:11:11 (lnk-s1-l1)
eth2 : 52:54:00:04:21:11 (lnk-s2-l1)
eth3 : 52:54:00:04:31:11 (acc-l1)
eth4 : 52:54:00:04:91:11 (mirror-l1)

=== leaf2 (192.168.122.32) ===
eth0 : 52:54:00:04:00:12 (mgmt)
eth1 : 52:54:00:04:12:12 (lnk-s1-l2)
eth2 : 52:54:00:04:22:12 (lnk-s2-l2)
eth3 : 52:54:00:04:32:12 (acc-l2)
eth4 : 52:54:00:04:92:12 (mirror-l2)

=== leaf3 (192.168.122.33) ===
eth0 : 52:54:00:04:00:13 (mgmt)
eth1 : 52:54:00:04:13:13 (lnk-s1-l3)
eth2 : 52:54:00:04:23:13 (lnk-s2-l3)
eth3 : 52:54:00:04:33:13 (acc-l3-db)
eth4 : 52:54:00:04:34:13 (acc-l3-dec)
eth5 : 52:54:00:04:35:13 (acc-l3-mgmt)
eth6 : 52:54:00:04:36:13 (trunk-fw)
eth7 : 52:54:00:04:93:13 (mirror-l3)
```

### Masalah dan Keputusan (Troubleshooting Log):
- **Kendala**: Parsing string interface `lnk-s1-l1:52:54:00:04:11:01:eth1` menggunakan `IFS=':' read` menyebabkan alamat MAC terpotong pada tanda titik dua pertama (`52`), memicu pesan error `XML error: unable to parse mac address '52'`.
- **Solusi**: Mengganti `IFS` dengan *parameter expansion* bash:
  `net_name="${nic_item%%:*}"`, `if_name="${rest##*:}"`, `nic_mac="${rest%:*}"`.
- Menambahkan fungsi pembersihan otomatis (*auto-cleanup trap*) pada `create-vm.sh` jika pembuatan domain libvirt gagal.

---

## 5. Konfigurasi Kernel Node Jaringan (Langkah 1.4)

Diterapkan via [`infra/setup-node-kernel.sh`](file:///home/lavvvet/dc-microseg-lab/infra/setup-node-kernel.sh):
- **Modul Kernel Aktif**: `vrf`, `vxlan`, `bridge`, `sch_ingress`, `cls_flower`, `cls_u32`, `act_mirred`.
- **Parameter Sysctl**:
  - `net.ipv4.ip_forward = 1`: Mode router diaktifkan.
  - `net.ipv4.conf.all.rp_filter = 0`: Mencegah *silent drop* paket pada routing asimetris ECMP/multi-path.
  - `net.ipv4.tcp_l3mdev_accept = 1` & `udp_l3mdev_accept = 1`: Mengizinkan soket sistem menerima koneksi lintas VRF domain.

### Masalah dan Keputusan:
- **Kendala**: Modul `vrf` tidak ditemukan di `/lib/modules/6.8.0-142-generic/` pada instalasi awal Ubuntu Cloud Image.
- **Solusi**: Ubuntu Cloud Image hanya menyertakan modul dasar untuk menghemat ukuran image. Modul VRF dikemas terpisah di paket `linux-modules-extra-$(uname -r)`. Skrip otomatis mendeteksi ketiadaan modul dan memasang paket tersebut secara terisolasi tanpa melakukan `apt upgrade`.

---

## 6. Alokasi IP Underlay & Verifikasi MTU 9000 (Langkah 1.5)

Diterapkan melalui berkas Netplan persisten `/etc/netplan/60-underlay.yaml` di seluruh node menggunakan skrip [`infra/setup-underlay-ips.sh`](file:///home/lavvvet/dc-microseg-lab/infra/setup-underlay-ips.sh).

### 6.1 Tabel Alokasi IP Underlay
| Node | Interface | IP / Prefix | Keterangan Link |
|---|---|---|---|
| `spine1` | `lo` | `10.255.0.1/32` | BGP Router-ID / Loopback |
| `spine1` | `eth1` | `10.254.0.0/31` | Link L1 ke leaf1 (peer: `10.254.0.1`) |
| `spine1` | `eth2` | `10.254.0.2/31` | Link L2 ke leaf2 (peer: `10.254.0.3`) |
| `spine1` | `eth3` | `10.254.0.4/31` | Link L3 ke leaf3 (peer: `10.254.0.5`) |
| `spine2` | `lo` | `10.255.0.2/32` | BGP Router-ID / Loopback |
| `spine2` | `eth1` | `10.254.0.6/31` | Link L4 ke leaf1 (peer: `10.254.0.7`) |
| `spine2` | `eth2` | `10.254.0.8/31` | Link L5 ke leaf2 (peer: `10.254.0.9`) |
| `spine2` | `eth3` | `10.254.0.10/31`| Link L6 ke leaf3 (peer: `10.254.0.11`) |
| `leaf1`  | `lo` | `10.255.0.11/32`| BGP Router-ID / VTEP Endpoint |
| `leaf1`  | `eth1` | `10.254.0.1/31` | Link L1 ke spine1 (peer: `10.254.0.0`) |
| `leaf1`  | `eth2` | `10.254.0.7/31` | Link L4 ke spine2 (peer: `10.254.0.6`) |
| `leaf2`  | `lo` | `10.255.0.12/32`| BGP Router-ID / VTEP Endpoint |
| `leaf2`  | `eth1` | `10.254.0.3/31` | Link L2 ke spine1 (peer: `10.254.0.2`) |
| `leaf2`  | `eth2` | `10.254.0.9/31` | Link L5 ke spine2 (peer: `10.254.0.8`) |
| `leaf3`  | `lo` | `10.255.0.13/32`| BGP Router-ID / VTEP Endpoint |
| `leaf3`  | `eth1` | `10.254.0.5/31` | Link L3 ke spine1 (peer: `10.254.0.4`) |
| `leaf3`  | `eth2` | `10.254.0.11/31`| Link L6 ke spine2 (peer: `10.254.0.10`) |

### 6.2 Hasil Pengujian Ping L3 & Uji Jumbo Frame MTU 9000
Uji transmisi dieksekusi dengan dua metode:
1. Ping standar (paket ICMP kecil).
2. Ping Jumbo Frame berukuran tepat **9000 bytes** dengan bit *Don't Fragment* (DF) aktif:
   `ping -c 2 -W 2 -M do -s 8972 <peer_ip>`

```text
[TEST] Ping lnk-s1-l1 (spine1 -> leaf1): OK (L3 Reachable) | OK (Jumbo 9000B No Fragmentation)
[TEST] Ping lnk-s1-l2 (spine1 -> leaf2): OK (L3 Reachable) | OK (Jumbo 9000B No Fragmentation)
[TEST] Ping lnk-s1-l3 (spine1 -> leaf3): OK (L3 Reachable) | OK (Jumbo 9000B No Fragmentation)
[TEST] Ping lnk-s2-l1 (spine2 -> leaf1): OK (L3 Reachable) | OK (Jumbo 9000B No Fragmentation)
[TEST] Ping lnk-s2-l2 (spine2 -> leaf2): OK (L3 Reachable) | OK (Jumbo 9000B No Fragmentation)
[TEST] Ping lnk-s2-l3 (spine2 -> leaf3): OK (L3 Reachable) | OK (Jumbo 9000B No Fragmentation)
```

**Kesimpulan Pengujian:**
Seluruh 6 link underlay point-to-point terbukti saling terhubung di Layer 3, dan **Risiko R4 (MTU/VXLAN Silent Drop) resmi tereliminasi** karena seluruh jalur dapat melewatkan frame jumbo 9000 bytes tanpa fragmentasi.
