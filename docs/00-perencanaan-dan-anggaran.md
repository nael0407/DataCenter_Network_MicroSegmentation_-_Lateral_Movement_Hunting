# Dokumen 00: Perencanaan, Anggaran Sumber Daya, dan Keputusan Arsitektur

> **Proyek 4: Data Center Network Micro-segmentation dan Lateral Movement Hunting**  
> Penulis: Natanael  
> Tanggal: 15 Oktober 2026  
> Status: Selesai (Fase 0)

---

## 1. Tujuan dan Ruang Lingkup Proyek

Proyek ini adalah kelanjutan strategis dari **Proyek 3 (Hardened Kubernetes Platform)**. Jika Proyek 3 berfokus pada pertahanan lapis *workload* dan kontainer (Cilium eBPF, Kyverno admission control, runtime security), maka Proyek 4 melengkapi pertahanan data center dari lapis **jaringan (*fabric*)**:
- Merancang fabric **Spine-Leaf** modern menggunakan **FRRouting (FRR)** dengan underlay eBGP + ECMP + BFD dan overlay VXLAN/EVPN.
- Menerapkan **segmentasi antar-zona** berbasis firewall terpusat (**OPNsense**) dengan kebijakan *default-deny* dan pencatatan log lengkap.
- Mengimplementasikan **micro-segmentation intra-zona** pada host menggunakan **nftables** yang dikelola sebagai kode melalui Ansible.
- Memasang sistem telemetri jaringan pasif menggunakan port mirroring **`tc mirred`** ke sensor **Zeek**, decoy **OpenCanary**, serta sentral log **Loki + Grafana + Grafana Alloy**.
- Membuktikan secara **kuantitatif dan terukur** efektivitas pertahanan: membandingkan kondisi *baseline* (fabric datar/permisif) dengan *hardened* (tersegmentasi), mengukur reduksi *blast radius*, waktu deteksi ancaman, dan ketahanan konvergensi saat kegagalan link.

---

## 2. Hasil Pemeriksaan Lingkungan Host (Langkah 0.1 – 0.3)

Pemeriksaan aktual telah dieksekusi di host pada 15 Oktober 2026:

### 2.1 Sumber Daya Komputasi Host
- **Host**: Lenovo Legion Pro 5 16IRX9 (Intel Core i9-14900HX 32 threads, RAM 31 GiB + Swap 8 GiB).
- **RAM Aktual**: Terpakai 7.1 GiB, **Tersedia (available) 23 GiB**, Swap 8.0 GiB (0B terpakai).
- **Disk Root (`/dev/nvme0n1p4`)**: Total 460 GB, Terpakai 111 GB (26%), **Tersisa 327 GB**.
- **Status VM Proyek 3**: Tiga node (`k3s-server`, `k3s-agent1`, `k3s-agent2`) dalam status **`shut off`** dengan rapi. Sumber daya CPU dan RAM 100% bebas untuk Proyek 4.

### 2.2 Evaluasi Risiko Docker / Bridge (Risiko R1)
- **Modul `br_netfilter`**: **TIDAK termuat** di kernel.
- **Sysctl `net.bridge.bridge-nf-call-iptables`**: Berkas belum ada / parameter tidak aktif.
- **Kebijakan Rantai `FORWARD`**: `-P FORWARD ACCEPT`.
- **Kesimpulan**: Risiko R1 saat ini **aman (clear)**. Linux bridge libvirt yang akan kita buat murni bekerja pada Layer 2 dan tidak akan dijatuhkan secara sepihak oleh iptables host.

### 2.3 Evaluasi Tabrakan Rute Host
Pemeriksaan rute host (`ip route get`) terhadap rencana subnet lab:
- `10.10.10.1` (Zona Web) -> rute default WiFi
- `10.254.0.1` (Underlay P2P) -> rute default WiFi
- `10.255.0.1` (Underlay Loopback) -> rute default WiFi
- `203.0.113.1` (Simulasi Eksternal) -> rute default WiFi
- **Kesimpulan**: Tidak ada bentrok rute lokal pada host.

---

## 3. Anggaran Sumber Daya (Resource Budget)

Total terdapat **14 VM** dengan estimasi kebutuhan RAM **~18,5 GB** dan Disk Overlay **~150 GB**. Kapasitas ini sangat aman terhadap ketersediaan RAM host (23 GiB).

| VM | Peran | vCPU | RAM | Disk Overlay | Subtotal RAM |
|---|---|---|---|---|---|
| `spine1`, `spine2` | Spine Router (FRR) | 1 | 1 GB | 10 GB | 2 GB |
| `leaf1`, `leaf2` | Leaf Router (FRR) | 2 | 1 GB | 10 GB | 2 GB |
| `leaf3` | Border Leaf (FRR) ke OPNsense | 2 | 1 GB | 10 GB | 1 GB |
| `opnsense` | Stateful Firewall Antar-Zona | 2 | 2 GB | 20 GB | 2 GB |
| `web1`, `web2` | Workload Zona Web (DMZ) | 1 | 1 GB | 10 GB | 2 GB |
| `app1`, `app2` | Workload Zona Aplikasi | 1 | 1 GB | 10 GB | 2 GB |
| `db1` | Workload Zona Database | 2 | 1,5 GB | 12 GB | 1,5 GB |
| `canary1` | Decoy OpenCanary | 1 | 1 GB | 8 GB | 1 GB |
| `secops` | Bastion Ansible, Zeek, Loki, Alloy, Grafana | 4 | 4 GB | 30 GB | 4 GB |
| `attacker` | Penyerang Sisi Internet (Simulasi) | 1 | 1 GB | 8 GB | 1 GB |
| **Total** | **14 VM** | **23 vCPU** | **18,5 GB** | **Sekitar 150 GB** | **18,5 GB** |

> **Strategi Manajemen Beban:** VM dinyalakan bertahap per fase. Pada Fase 1-3, hanya 5 VM jaringan (spine & leaf) yang menyala (~5 GB RAM). Workload server baru dinyalakan pada Fase 5.

---

## 4. Keputusan Desain yang Dikunci (D1 – D5)

| Kode | Aspek | Pilihan Terkunci | Rationale & Trade-off |
|---|---|---|---|
| **D1** | Sistem Router Spine-Leaf | **Ubuntu 24.04 + FRR dari paket resmi** | Menggunakan pipeline `create-vm.sh` dan cloud-init dari Proyek 3. Akses kernel penuh untuk pengujian modul Linux (VRF, VXLAN, `tc`). Konfigurasi FRR murni memberikan nilai edukatif portofolio yang lebih tinggi dibandingkan abstraksi vendor. |
| **D2** | Model Overlay EVPN/VXLAN | **Opsi A: Bridged Overlay (L2 EVPN per zona)** | **Keputusan Kunci Arsitektur**: OPNsense adalah *stateful firewall*. Menggunakan L2 EVPN menjamin bahwa seluruh trafik antar-zona secara konsisten diarahkan ke gateway OPNsense dan kembali lewat jalur simetris (mencegah *broken state table*). Opsi B (*Symmetric IRB / L3 VNI*) dialihkan ke riset opsional pasca-Fase 9. Fallback ke VLAN routed biasa disiapkan jika terjadi kendala kernel fatal. |
| **D3** | Ukuran Topologi | **2 Spine + 3 Leaf** | Topologi standar Clos Spine-Leaf minimum yang memenuhi syarat pengujian ECMP 2 jalur, simulasi kegagalan link/spine (failover BFD), dan pemisahan border leaf. |
| **D4** | Stack Telemetri & Log | **Loki + Grafana + Grafana Alloy** | Grafana Alloy digunakan di `secops` sebagai pengumpul sentral (menerima syslog OPNsense via `loki.source.syslog`, membaca file log Zeek, dan log OpenCanary) lalu mem-push ke Loki. Promtail ditandai *deprecated*. |
| **D5** | Sensor Pemantauan Jaringan | **Zeek (Multi-interface Sniffing)** | Zeek menghasilkan log analitis terstruktur (`conn.log`, `ssh.log`, `http.log`, `notice.log`) yang sangat ideal untuk kueri perburuan ancaman (hunting) berbasis graf dan analitik data. |

---

## 5. Topologi Jaringan & Link Virtual Libvirt

```
                         [ attacker ] (203.0.113.0/24)
                              |
                       [ OPNsense ] (FW Antar-Zona)
                              | trunk-fw (802.1Q tagged)
      spine1 ---------------- leaf3 (border) ---------------- spine2
        |  \                  /    |     \                  /   |
        |   \________________/     |      \________________/    |
        |    ________________      |       ________________     |
        |   /                \     |      /                \    |
      leaf1                   leaf2 (uplink ke kedua spine)    |
   web1, web2              app1, app2       leaf3: db1, canary1, secops
```

### 5.1 Rincian Jaringan Libvirt Isolated (`<forward mode='none'/>`)

| ID Link | Perangkat yang Terhubung | Nama Jaringan Libvirt | Keterangan |
|---|---|---|---|
| L1 | spine1 (eth1) - leaf1 (eth1) | `lnk-s1-l1` | P2P Underlay (`10.254.0.0/31`) |
| L2 | spine1 (eth2) - leaf2 (eth1) | `lnk-s1-l2` | P2P Underlay (`10.254.0.2/31`) |
| L3 | spine1 (eth3) - leaf3 (eth1) | `lnk-s1-l3` | P2P Underlay (`10.254.0.4/31`) |
| L4 | spine2 (eth1) - leaf1 (eth2) | `lnk-s2-l1` | P2P Underlay (`10.254.0.6/31`) |
| L5 | spine2 (eth2) - leaf2 (eth2) | `lnk-s2-l2` | P2P Underlay (`10.254.0.8/31`) |
| L6 | spine2 (eth3) - leaf3 (eth2) | `lnk-s2-l3` | P2P Underlay (`10.254.0.10/31`) |
| A1 | leaf1 - web1, web2 | `acc-l1` | Akses Zona Web di Leaf1 |
| A2 | leaf2 - app1, app2 | `acc-l2` | Akses Zona App di Leaf2 |
| A3-db | leaf3 - db1 | `acc-l3-db` | Akses Zona DB di Leaf3 (libvirt network terpisah) |
| A3-dec | leaf3 - canary1 | `acc-l3-dec` | Akses Zona Decoy di Leaf3 (libvirt network terpisah) |
| A3-mgmt| leaf3 - secops | `acc-l3-mgmt` | Akses Zona SecOps di Leaf3 (libvirt network terpisah) |
| T1 | leaf3 - opnsense | `trunk-fw` | Trunk 802.1Q (VLAN 10, 20, 30, 40, 50) |
| X1 | opnsense - attacker | `ext-sim` | Jaringan simulasi publik/internet |
| M | Semua node + FW + secops | `default` | Jaringan NAT libvirt (hanya OOB / bootstrap) |
| MIR-1 | leaf1 (mirror) - secops (eth1) | `mirror-l1` | Port mirror ingress Leaf1 |
| MIR-2 | leaf2 (mirror) - secops (eth2) | `mirror-l2` | Port mirror ingress Leaf2 |
| MIR-3 | leaf3 (mirror) - secops (eth3) | `mirror-l3` | Port mirror ingress Leaf3 |

> **Catatan Keputusan Desain Akses Leaf3:**  
> Bridge Linux tanpa `vlan_filtering` tidak menegakkan pemisahan VLAN di level host. Oleh karena itu, zona berbeda pada Leaf3 (`db1`, `canary1`, `secops`) wajib menggunakan jaringan libvirt terpisah (`acc-l3-db`, `acc-l3-dec`, `acc-l3-mgmt`) guna mencegah kebocoran L2 di host. Sebaliknya, `trunk-fw` tetap menggunakan tag 802.1Q karena bridge tersebut adalah link point-to-point antara Leaf3 dan OPNsense.

---

## 6. Rencana Pengalamatan (IP, ASN, VNI)

### 6.1 Underlay Network (Routing Fisik)
- **ASN BGP**:
  - `spine1`, `spine2`: **65000** (Spine ASN bersama)
  - `leaf1`: **65001**
  - `leaf2`: **65002**
  - `leaf3`: **65003**
- **Loopback Router (`/32`)**:
  - `spine1`: `10.255.0.1/32`
  - `spine2`: `10.255.0.2/32`
  - `leaf1`: `10.255.0.11/32`
  - `leaf2`: `10.255.0.12/32`
  - `leaf3`: `10.255.0.13/32`
- **Interkoneksi P2P (`/31`)**:
  - `lnk-s1-l1`: `10.254.0.0/31` (spine1 `.0`, leaf1 `.1`)
  - `lnk-s1-l2`: `10.254.0.2/31` (spine1 `.2`, leaf2 `.3`)
  - `lnk-s1-l3`: `10.254.0.4/31` (spine1 `.4`, leaf3 `.5`)
  - `lnk-s2-l1`: `10.254.0.6/31` (spine2 `.6`, leaf1 `.7`)
  - `lnk-s2-l2`: `10.254.0.8/31` (spine2 `.8`, leaf2 `.9`)
  - `lnk-s2-l3`: `10.254.0.10/31` (spine2 `.10`, leaf3 `.11`)

### 6.2 Overlay Network (L2 EVPN Bridged Overlay)
Seluruh host mengarahkan default gateway ke IP `.1` yang berada di antarmuka VLAN OPNsense:

| Zona | Subnet | Gateway OPNsense | Alokasi Host | L2 VNI | VLAN Trunk ID |
|---|---|---|---|---|---|
| **Web** (DMZ) | `10.10.10.0/24` | `10.10.10.1` | `web1` (.11), `web2` (.12) | 10010 | VLAN 10 |
| **App** | `10.10.20.0/24` | `10.10.20.1` | `app1` (.11), `app2` (.12) | 10020 | VLAN 20 |
| **Database** | `10.10.30.0/24` | `10.10.30.1` | `db1` (.11) | 10030 | VLAN 30 |
| **SecOps / Mgmt** | `10.10.40.0/24` | `10.10.40.1` | `secops` (.11) | 10040 | VLAN 40 |
| **Decoy** | `10.10.50.0/24` | `10.10.50.1` | `canary1` (.11) | 10050 | VLAN 50 |
| **Eksternal** | `203.0.113.0/24` | `203.0.113.1` | `attacker` (.11) | - | Native / Direct |

---

## 7. Keamanan Jalur Manajemen & Prinsip Bastion

1. **Pencegahan Jalan Tikus Lateral (Bypass)**:
   - Interface jaringan `default` (192.168.122.0/24) pada seluruh VM server (`web`, `app`, `db`, `canary`, `attacker`) hanya digunakan saat instalasi awal (cloud-init bootstrap).
   - Setelah sistem siap di Fase 5, NIC tersebut **dilepas permanen** (`virsh detach-interface`). Tidak ada rute langsung antar-server di luar fabric.
2. **Akses Ansible via SSH `ProxyJump` (`-J`)**:
   - Operator host mengakses server menggunakan SSH `ProxyJump` melewati VM `secops` (`ssh -J secops@10.10.40.11 target`).
   - **Dilarang menggunakan SSH Agent Forwarding (`-A`)**: Kunci privat tetap tersimpan di host guna mencegah serangan pembajakan agen SSH (*SSH Agent Hijacking*, MITRE ATT&CK T1563.001) yang diuji pada skenario S3.
3. **Identitas Bastion dalam Baseline Hunting**:
   - Lalu lintas SSH dari `secops` ke server-server adalah trafik administratif yang sah.
   - Aturan OPNsense mengizinkan SSH port 22 hanya dari `secops`.
   - Aturan deteksi *threat hunting* wajib menyertakan *allowlist* identitas bastion `secops` agar aktivitas Ansible rutin tidak memicu alarm palsu (*False Positive*).
   - *Trade-off:* `secops` menjadi *High-Value Target* (HVT).

---

## 8. Desain Telemetri Jaringan & Analisis

1. **Port Mirroring `tc mirred`**:
   - Dikonfigurasi pada port akses Leaf1, Leaf2, dan Leaf3 khusus untuk arah **`ingress`** saja.
   - Paket diteruskan ke 3 antarmuka sensor terpisah di `secops` (`eth1`, `eth2`, `eth3`) melalui jaringan libvirt terisolasi.
   - **Penanganan Ingress-Only**: Request dan reply dari koneksi lintas-leaf akan masuk dari interface monitor yang berbeda di `secops`. Zeek dijalankan sebagai **satu proses tunggal** yang menginspeksi ketiga interface secara terintegrasi agar tidak terjadi pemotongan sesi (*half-connection*) di `conn.log`.
2. **Koleksi Log Terpusat**:
   - OPNsense mengirimkan syslog audit filter firewall (RFC 3164) ke Grafana Alloy UDP 1514.
   - OpenCanary mencatat percobaan login ke syslog/file.
   - Zeek menghasilkan log JSON per protokol.
   - Seluruh data diagregasi oleh Grafana Alloy dan dikirim ke Loki untuk divisualisasikan di Grafana dashboard.
3. **Generator Beban Kerja & Baseline**:
   - Direktori `workloads/` memuat layanan mock 3-tier (Web -> API App -> Database dummy).
   - Skrip generator trafik menambahkan **jitter acak** pada interval panggilan API dan menyisipkan aktivitas administratif reguler untuk menghasilkan baseline realistis bagi evaluasi TP/FP.
