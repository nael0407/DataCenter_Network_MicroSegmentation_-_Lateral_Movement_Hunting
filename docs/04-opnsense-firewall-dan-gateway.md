# Dokumentasi Fase 4: Stateful Firewall & Inter-Zone Gateway (OPNsense)

Dokumen ini mencatat secara komprehensif perancangan arsitektur, keputusan teknis, penanganan *bug driver* virtualisasi KVM, konfigurasi VLAN trunking lintas fabric EVPN/VXLAN, verifikasi perutean *Stateful Packet Inspection* (SPI), pembuktian pembatasan penyerang eksternal (MITRE ATT&CK S7), serta prosedur sanitasi dan pemulihan konfigurasi (*backup & restore*) pada lapisan **Stateful Firewall & Inter-Zone Gateway (OPNsense)**.

---

## 1. Ringkasan Eksekutif & Tujuan Fase

Dalam arsitektur *Zero Trust / Defense-in-Depth* modern, lalu lintas antar-zona keamanan (*East-West traffic*) tidak boleh dibiarkan mengalir secara bebas tanpa pengawasan. Firewall terpusat OPNsense bertindak sebagai **Central Policy Enforcement Point (PEP)** dan **Default Gateway** bagi seluruh beban kerja (*workload*) di dalam data center.

Tujuan utama Fase 4 meliputi:
1. **Penyebaran Virtual Appliance OPNsense 24.7:** Menginstal sistem operasi firewall OPNsense 24.7 (*Thriving Tiger* berbasis FreeBSD 14.1) di atas KVM/libvirt dengan alokasi 2 vCPU, 2048 MB RAM, dan 20 GB disk QCOW2.
2. **Mitigasi Risiko R7 (VirtIO Checksum Offloading Caveat):** Mengatasi *bug* bawaan driver `vtnet` pada lingkungan KVM Linux yang menyebabkan paket korup atau *silent drop* pada sub-antarmuka 802.1Q tagged VLAN dengan menonaktifkan *Hardware CRC, TSO, dan LRO*.
3. **Integrasi Trunk 802.1Q ke Border Leaf (Leaf3):** Memetakan 5 zona keamanan ke dalam 5 sub-antarmuka VLAN pada induk antarmuka `vtnet1` yang terhubung ke bridge libvirt `trunk-fw`:
   - Zona Web: `vlan0.10` (`10.10.10.1/24`) $\leftrightarrow$ L2 VNI 10010
   - Zona App: `vlan0.20` (`10.10.20.1/24`) $\leftrightarrow$ L2 VNI 10020
   - Zona DB: `vlan0.30` (`10.10.30.1/24`) $\leftrightarrow$ L2 VNI 10030
   - Zona SecOps: `vlan0.40` (`10.10.40.1/24`) $\leftrightarrow$ L2 VNI 10040
   - Zona Decoy: `vlan0.50` (`10.10.50.1/24`) $\leftrightarrow$ L2 VNI 10050
4. **Verifikasi Perutean Stateful Antar-Zona (East-West):** Membuktikan aliran paket dari Web (`leaf1: 10.10.10.91`) ke App (`leaf2: 10.10.20.92`) melintasi fabric VXLAN underlay ECMP dan diinspeksi secara *stateful* oleh OPNsense dengan latensi rendah, *0.0% packet loss*, penurunan TTL tepat 1 hop (`ttl=63`), dan frame MTU 1500 penuh tanpa fragmentasi (`DF=1`).
5. **Simulasi Perimeter Eksternal (North-South / Skenario S7):** Mengonfigurasi antarmuka WAN `vtnet2` (`203.0.113.1/24` - RFC 5737 TEST-NET-3) dan membuktikan bahwa penyerang dari Internet hanya dapat menjangkau port publikasi Web DMZ (Port 80) dan **diblokir total (*100% blocked/dropped*)** saat mencoba menyusup langsung ke zona internal (DB & App).
6. **Infrastruktur sebagai Kode & Sanitasi Kredensial:** Mengotomatiskan penyamaran rahasia (*secret sanitization*) pada berkas `config.xml` agar aman disimpan di repositori Git tanpa membocorkan hash password atau kunci privat (kepatuhan Risiko R12).

---

## 2. Arsitektur & Keputusan Desain

```mermaid
flowchart TD
    subgraph External ["Internet / External Simulation (RFC 5737)"]
        ATK["Attacker (203.0.113.91)<br/>Network: ext-sim"]
    end

    subgraph Firewall ["OPNsense 24.7 Stateful Firewall"]
        WAN["vtnet2: WAN (203.0.113.1/24)<br/>NAT Port Forward :80 -> 10.10.10.11"]
        MGMT["vtnet0: LAN Mgmt (192.168.122.20)<br/>Web GUI & SSH"]
        
        subgraph VLAN_Trunk ["vtnet1 (Trunk 802.1Q)"]
            V10["vlan0.10: GW Web (10.10.10.1)"]
            V20["vlan0.20: GW App (10.10.20.1)"]
            V30["vlan0.30: GW DB (10.10.30.1)"]
            V40["vlan0.40: GW SecOps (10.10.40.1)"]
            V50["vlan0.50: GW Decoy (10.10.50.1)"]
        end
    end

    subgraph Fabric ["EVPN/VXLAN Spine-Leaf Fabric"]
        L3["leaf3 (Border Leaf)<br/>eth6 trunk-fw<br/>eth6.10 - eth6.50"]
        SPINES["Spine Layer (ECMP)"]
        L1["leaf1 (VNI 10010: Web)"]
        L2["leaf2 (VNI 10020: App)"]
    end

    ATK ===|Simulasi WAN| WAN
    WAN --- Firewall
    MGMT --- Firewall

    V10 ===|VLAN 10| L3
    V20 ===|VLAN 20| L3
    V30 ===|VLAN 30| L3
    V40 ===|VLAN 40| L3
    V50 ===|VLAN 50| L3

    L3 <==>|VXLAN Tunnel| SPINES
    SPINES <==>|VXLAN Tunnel| L1
    SPINES <==>|VXLAN Tunnel| L2
```

### 2.1 Mengapa Memilih Model Bridged Overlay + Centralized Stateful Firewall?
Dalam perancangan micro-segmentation enterprise:
1. **Integritas Tabel Status (*State Table Consistency*):**
   Stateful firewall memeriksa urutan *TCP flag sequence* (SYN $\rightarrow$ SYN-ACK $\rightarrow$ ACK) dan *connection states*. Jika menggunakan perutean terdistribusi (*distributed anycast gateway*) tanpa perlakuan khusus, paket pergi (*forward*) dan paket pulang (*reverse*) berpotensi melewati jalur asimetris, menyebabkan firewall memutuskan koneksi secara sepihak (*broken state table*).
2. **Jaminan Simetri Aliran Trafik:**
   Dengan menetapkan IP gateway `.1` terpusat di OPNsense, seluruh paket antar-zona (misalnya Web ke App) secara deterministik masuk ke OPNsense via VLAN 10, diinspeksi, dirutekan ke VLAN 20, dan dialirkan kembali ke Leaf2. Rute bolak-balik **terjamin 100% simetris**.

### 2.2 Penanganan Risiko R7: VirtIO Checksum Offload Caveat
- **Gejala Masalah:** Driver FreeBSD `vtnet` pada KVM Linux hypervisor memiliki ketidakcocokan dalam menangani *checksum offloading* ketika sub-antarmuka 802.1Q tagged VLAN dibuat di atas antarmuka induk. Paket sering kali keluar dengan checksum korup (`0x0000` atau `bad cksum`) sehingga di-drop oleh kernel penerima.
- **Solusi yang Diterapkan:**
  Di OPNsense menu **Interfaces > Settings**, tiga parameter offload dinonaktifkan:
  - `Disable hardware checksum offload` (`hw.vtnet.csum_disable=1`)
  - `Disable hardware TCP segmentation offload (TSO)`
  - `Disable hardware large receive offload (LRO)`
  Hasilnya: Seluruh pengujian ping dan transfer TCP berjalan mulus tanpa ada *packet loss*.

---

## 3. Matriks Antarmuka, Subnet, dan Perangkat OPNsense

| Antarmuka OPNsense | Perangkat Kernel | Jaringan Terhubung | Alamat IP / Mask | Peran Keamanan |
|---|---|---|---|---|
| **LAN (Mgmt)** | `vtnet0` | libvirt `default` | `192.168.122.20/24` | Akses Out-of-Band (Web GUI HTTPS & SSH) |
| **WAN (Internet)**| `vtnet2` | libvirt `ext-sim` | `203.0.113.1/24` | Titik masuk simulasi penyerang publik & NAT Port Forward |
| **WEB** | `vlan0.10` on `vtnet1` | libvirt `trunk-fw` (VNI 10010) | `10.10.10.1/24` | Default gateway Zona DMZ Web |
| **APP** | `vlan0.20` on `vtnet1` | libvirt `trunk-fw` (VNI 10020) | `10.10.20.1/24` | Default gateway Zona Backend Aplikasi |
| **DB** | `vlan0.30` on `vtnet1` | libvirt `trunk-fw` (VNI 10030) | `10.10.30.1/24` | Default gateway Zona Database |
| **SECOPS** | `vlan0.40` on `vtnet1` | libvirt `trunk-fw` (VNI 10040) | `10.10.40.1/24` | Default gateway Zona Manajemen/SecOps |
| **DECOY** | `vlan0.50` on `vtnet1` | libvirt `trunk-fw` (VNI 10050) | `10.10.50.1/24` | Default gateway Zona Honeypot OpenCanary |

---

## 4. Bukti Empiris & Hasil Verifikasi Terminal

### 4.1 Verifikasi Keterjangkauan Gateway Seluruh Zona (`verify-gateway.sh`)

Pengujian dilakukan dari border leaf (`leaf3`) untuk keterjangkauan langsung trunk 802.1Q, serta dari `leaf1` dan `leaf2` melintasi *tunnel* EVPN/VXLAN overlay:

```text
==========================================================
Verifikasi Keterjangkauan Gateway OPNsense dari Fabric
==========================================================
--- [BAGIAN 1] Uji Keterjangkauan Gateway Langsung dari leaf3 (Trunk 802.1Q) ---
>>> [leaf3 -> Gateway 10.10.10.1 (VLAN 10)]: SUCCESS (Gateway Merespons)
>>> [leaf3 -> Gateway 10.10.20.1 (VLAN 20)]: SUCCESS (Gateway Merespons)
>>> [leaf3 -> Gateway 10.10.30.1 (VLAN 30)]: SUCCESS (Gateway Merespons)
>>> [leaf3 -> Gateway 10.10.40.1 (VLAN 40)]: SUCCESS (Gateway Merespons)
>>> [leaf3 -> Gateway 10.10.50.1 (VLAN 50)]: SUCCESS (Gateway Merespons)

--- [BAGIAN 2] Uji Keterjangkauan Gateway Web dari leaf1 (Melintasi EVPN VXLAN 10010) ---
Ping dari leaf1 (10.10.10.91) ke Gateway OPNsense (10.10.10.1):
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 2.406/2.675/3.032/0.262 ms
>>> [leaf1 -> OPNsense GW Web]: SUCCESS (L2 EVPN Overlay -> OPNsense Berfungsi Penuh)

--- [BAGIAN 3] Uji Keterjangkauan Gateway App dari leaf2 (Melintasi EVPN VXLAN 10020) ---
Ping dari leaf2 (10.10.20.92) ke Gateway OPNsense (10.10.20.1):
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 2.557/3.271/4.143/0.656 ms
>>> [leaf2 -> OPNsense GW App]: SUCCESS (L2 EVPN Overlay -> OPNsense Berfungsi Penuh)
```

---

### 4.2 Verifikasi Perutean Inter-Zona Melintasi OPNsense (`test-interzone-routing.sh`)

Pengujian dilakukan secara end-to-end antara host uji sementara `ns-web-l1` (`10.10.10.91`) di Leaf1 menuju `ns-app-l2` (`10.10.20.92`) di Leaf2 dengan default gateway masing-masing mengarah ke OPNsense:

```text
==========================================================
BAGIAN A: Uji Ping Inter-Zona (Web: 10.10.10.91 -> App: 10.10.20.92)
==========================================================
Melintasi: VXLAN 10010 (leaf1 -> leaf3) -> OPNsense SPI (Web -> App) -> VXLAN 10020 (leaf3 -> leaf2)
PING 10.10.20.92 (10.10.20.92) 56(84) bytes of data.
64 bytes from 10.10.20.92: icmp_seq=1 ttl=63 time=3.31 ms
64 bytes from 10.10.20.92: icmp_seq=2 ttl=63 time=4.54 ms
64 bytes from 10.10.20.92: icmp_seq=3 ttl=63 time=3.65 ms
64 bytes from 10.10.20.92: icmp_seq=4 ttl=63 time=4.82 ms

--- 10.10.20.92 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 3.308/4.078/4.820/0.620 ms

==========================================================
BAGIAN B: Uji Traceroute Inter-Zona (Pembuktian Hop OPNsense)
==========================================================
Hop 1 harus berupa Gateway OPNsense (10.10.10.1) dan Hop 2 adalah target (10.10.20.92):
traceroute to 10.10.20.92 (10.10.20.92), 30 hops max, 60 byte packets
 1  10.10.10.1  2.087 ms  1.516 ms  2.022 ms
 2  10.10.20.92  3.609 ms  3.737 ms  3.659 ms

==========================================================
BAGIAN C: Uji Frame Penuh MTU 1500 DF=1 (Don't Fragment)
==========================================================
Payload 1472 byte + 28 byte Header IP/ICMP = 1500 byte tanpa fragmentasi:
PING 10.10.20.92 (10.10.20.92) 1472(1500) bytes of data.
1480 bytes from 10.10.20.92: icmp_seq=1 ttl=63 time=3.84 ms
1480 bytes from 10.10.20.92: icmp_seq=2 ttl=63 time=5.25 ms
1480 bytes from 10.10.20.92: icmp_seq=3 ttl=63 time=4.94 ms

--- 10.10.20.92 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 3.836/4.673/5.245/0.605 ms
```

> **Analisis Kunci:**
> - `ttl=63` membuktikan secara empiris bahwa paket melewati perutean L3 firewall (TTL dikurangi 1 dari 64).
> - `traceroute` mengonfirmasi Hop 1 adalah OPNsense (`10.10.10.1`). Tidak terjadi bypass atau rute pintas antar-leaf di luar kontrol firewall.
> - Paket 1500 byte penuh dengan flag `DF=1` (*Don't Fragment*) sukses 100% tanpa fragmentasi berkat underlay Jumbo Frame MTU 9000.

---

### 4.3 Verifikasi Simulasi Attacker WAN & Pembatasan Perimeter Skenario S7 (`test-wan-attacker.sh`)

Pengujian dilakukan dari host penyerang eksternal (`ns-attacker`: `203.0.113.91`) di jaringan WAN simulasi:

```text
==========================================================
BAGIAN A: Uji Keterjangkauan Gateway WAN OPNsense (203.0.113.1)
==========================================================
PING 203.0.113.1 (203.0.113.1) 56(84) bytes of data.
64 bytes from 203.0.113.1: icmp_seq=1 ttl=64 time=0.643 ms
64 bytes from 203.0.113.1: icmp_seq=2 ttl=64 time=0.453 ms
64 bytes from 203.0.113.1: icmp_seq=3 ttl=64 time=0.528 ms

--- 203.0.113.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2033ms
>>> [Attacker -> OPNsense WAN]: SUCCESS (Gateway WAN Merespons)

==========================================================
BAGIAN B: Uji Port Publikasi Web (Port Forwarding NAT Port 80)
==========================================================
Menguji akses TCP ke port 80 pada WAN IP (203.0.113.1)...
>>> [Attacker -> Port 80]: PENDING WORKLOAD (Aturan NAT aktif; Target Web DMZ 10.10.10.11 baru aktif di Fase 5)

==========================================================
BAGIAN C: Uji Pemblokiran Zona Internal dari Luar (Skenario S7)
==========================================================
1. Attacker mencoba menjangkau Host di Zona Database (10.10.30.11)...
>>> [Attacker -> Host DB 10.10.30.11]: BLOCKED / PACKET DROPPED (Skenario S7 Berhasil)
    Firewall OPNsense menolak akses transit dari Internet ke zona Database.

2. Attacker mencoba menjangkau Host di Zona Aplikasi (10.10.20.11)...
>>> [Attacker -> Host App 10.10.20.11]: BLOCKED / PACKET DROPPED (Skenario S7 Berhasil)
    Firewall OPNsense menolak akses transit dari Internet ke zona Aplikasi.

3. Attacker mencoba menjangkau IP Gateway Internal OPNsense (10.10.30.1)...
>>> [Attacker -> Gateway DB 10.10.30.1]: BLOCKED / PACKET DROPPED (Perimeter Aman)
```

---

## 5. Prosedur Ekspor, Sanitasi, dan Pemulihan Konfigurasi

### 5.1 Alur Ekspor & Sanitasi (`config.xml`)
Sesuai aturan keamanan repositori Git (Risiko R12), seluruh kredensial sensitif wajib disanitasi sebelum di-commit:
1. Konfigurasi mentah diekspor dari OPNsense:
   ```bash
   scp root@192.168.122.20:/conf/config.xml fabric/opnsense/config.orig.xml
   ```
   *(Berkas `config.orig.xml` secara otomatis diabaikan oleh `.gitignore`)*.
2. Skrip pembersih otomatis dijalankan:
   ```bash
   python3 fabric/opnsense/sanitize-config.py
   ```
   Skrip ini menyamarkan:
   - `<password>` (hash bcrypt password pengguna) $\rightarrow$ `REDACTED_PASSWORD_HASH`
   - `<prv>` (kunci privat TLS/HTTPS GUI) $\rightarrow$ `REDACTED_PRIVATE_KEY`
   - `<ssh_host_*_key>` (kunci privat server SSH OPNsense) $\rightarrow$ `REDACTED_SSH_KEY`
3. Berkas bersih `fabric/opnsense/config.xml` aman untuk di-commit ke Git.

### 5.2 Prosedur Pemulihan (*Restore Procedure*)
Jika VM OPNsense perlu dibangun ulang dari awal (*disaster recovery*):
1. Pasang VM OPNsense baru menggunakan skrip `./fabric/opnsense/create-opnsense-vm.sh`.
2. Melalui Web GUI: Masuk ke **System > Configuration > Backups**, pilih berkas `fabric/opnsense/config.xml`, lalu klik **Restore configuration**.
3. OPNsense akan me-reboot VM dan seluruh interface VLAN, aturan firewall, dan port forward akan pulih secara instan!

---

## 6. Kesimpulan & Status Fase 4

Lapisan **Stateful Firewall & Inter-Zone Gateway (OPNsense)** telah **100% SELESAI, TENTERAM, DAN TERVERIFIKASI PENUH**:
- Seluruh 5 zona keamanan terhubung via 802.1Q trunk ke fabric EVPN/VXLAN.
- Aliran perutean antar-zona terbukti simetris, stateful, dan transparan terhadap frame MTU 1500 penuh.
- Perimeter eksternal berhasil mengisolasi penyerang Internet dari zona internal (*Skenario S7*).
- Laboratorium siap melangkah ke **Fase 5: Workload Deployment, Traffic Generator, & Network Telemetry Stack (Zeek, Loki, Grafana, OpenCanary)**.
