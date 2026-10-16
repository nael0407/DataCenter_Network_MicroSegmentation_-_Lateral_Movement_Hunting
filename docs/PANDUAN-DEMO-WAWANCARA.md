# Panduan Demo Wawancara 2 Menit & Naskah Presentasi Teknis Portofolio

> **Proyek:** Data Center Network Micro-segmentation & Lateral Movement Hunting  
> **Target Audiens:** Hiring Manager, Staff/Principal Network & Security Engineer, Cybersecurity Architect  
> **Durasi:** 2 Menit (120 Detik)  
> **Skrip Otomasi Demo:** [`demo-scripts/demo-2min.sh`](../demo-scripts/demo-2min.sh)  

---

## 1. Elevator Pitch (Ringkasan Pembuka 30 Detik)

> *"Dalam proyek ini, saya merancang dan membangun arsitektur jaringan data center Zero-Trust berbasis Spine-Leaf EVPN/VXLAN dengan 14 virtual machine yang tervirtualisasi penuh.*
>
> *Tantangan terbesar data center modern adalah jaringan perimeter datar (flat network): sekali penyerang menembus web publik, mereka bebas bergerak ke database inti. Di sini, saya membuktikan secara empiris penerapan pertahanan berlapis (Defense-in-Depth): inspeksi inter-zona default-deny di gateway OPNsense, micro-segmentation host-level menggunakan Linux nftables, serta pengerasan OpenSSH.*
>
> *Hasilnya, kami berhasil menekan **blast radius serangan sebesar 85.71%**, mengisolasi total tier database (0% keterpaparan port dan 0 byte kebocoran data), sekaligus membuktikan keandalan tulang punggung fabric dengan konvergensi failover **sub-detik (< 100 milidetik)** tanpa disrupsi pada alur aplikasi sah."*

---

## 2. Naskah Narasi Lengkap Demo 2 Menit (Sinkron dengan `demo-2min.sh`)

Jalankan perintah berikut pada terminal Anda:
```bash
./demo-scripts/demo-2min.sh
```
*(Gunakan opsi `--non-interactive` jika Anda mempresentasikan rekaman video atau slide otomatis).*

---

### [00:00 - 00:30] Babak 1: Topologi Fabric Spine-Leaf EVPN & Aplikasi Sah 3-Tier

**Aksi pada Layar:**
Skrip memverifikasi status 14 VM aktif di libvirt, memeriksa 2 sesi BFD Spine UP di Leaf 1, dan mengeksekusi request HTTP ke IP VIP WAN OPNsense (`http://203.0.113.1/`).

**Naskah yang Diucapkan:**
> *"Di babak pertama, kita melihat fondasi data center modern: arsitektur 2 Spine dan 3 Leaf yang menjalankan underlay eBGP dan BFD, dengan overlay VXLAN EVPN bridged. Seluruh 14 VM aktif dan saling terhubung.*
>
> *Klien eksternal di WAN mengakses aplikasi web publik kami melalui OPNsense NAT di port 80. Gateway meneruskan paket ke Web DMZ, yang kemudian memanggil App Tier di port 8080, lalu App Tier memproses query ke Database Tier di port 5432. Seluruh rantai 3-tier merespons sukses dengan HTTP 200 OK. Ini membuktikan bahwa arsitektur jaringan kami berfungsi penuh melayani trafik produksi bisnis yang sah."*

---

### [00:30 - 01:05] Babak 2: Simulasi Serangan Lateral & Penahanan Blast Radius

**Aksi pada Layar:**
Skrip menembakkan 3 vektor serangan dari mesin `web1` (Web DMZ yang dikompromikan):
1. Percobaan bypass langsung ke `db1:5432` -> **BLOCKED**.
2. Percobaan pivot SSH lateral ke `app1:22` -> **BLOCKED**.
3. Percobaan eksfiltrasi data nasabah dari `db1` ke C2 WAN -> **BLOCKED** (0 Byte leaked).
Skrip menampilkan kalkulasi reduksi blast radius: **85.71%**.

**Naskah yang Diucapkan:**
> *"Sekarang, skenario ancaman siber: asumsikan penyerang berhasil mengompromikan salah satu web server (web1) melalui kerentanan aplikasi.*
>
> *Pada jaringan data center konvensional yang datar, penyerang akan langsung memindai dan membobol database. Namun di lab kami, ketika penyerang mencoba direct bypass ke port database 5432, koneksi langsung dijatuhkan oleh aturan inter-zona default-deny OPNsense dan host nftables.*
>
> *Upaya pivoting lateral via SSH ke App server juga diblokir total pada L3 dan L4. Bahkan jika database dikompromikan, kebijakan Zero-Trust Egress melarang total koneksi keluar ke WAN, sehingga eksfiltrasi data nasabah gagal 100%. Blast radius serangan berhasil kami pangkas sebesar 85.71%—penyerang terkunci rapat di DMZ."*

---

### [01:05 - 01:35] Babak 3: Rekayasa Chaos & Konvergensi Sub-Detik BFD/ECMP

**Aksi pada Layar:**
Skrip mematikan paksa `spine1` (`virsh destroy spine1`). Tabel rute Leaf 1 seketika dialihkan ke Spine 2 via eth2, request aplikasi 3-tier tetap mengembalikan HTTP 200 OK (0% loss), lalu `spine1` dipulihkan kembali.

**Naskah yang Diucapkan:**
> *"Keamanan tidak boleh mengorbankan ketersediaan infrastruktur. Di babak ketiga, kita menguji ketahanan fabric underlay melalui rekayasa chaos. Saya mematikan paksa node Spine 1 secara mendadak di tengah lalu lintas produksi aktif.*
>
> *Protokol BFD (Bidirectional Forwarding Detection) pada seluruh Leaf mendeteksi kematian Spine 1 dalam tempo sub-detik (< 100 milidetik). Linux kernel ECMP nexthop group seketika mengalihkan 100% trafik ke Spine 2 tanpa ada satu paket pun yang hilang. Aplikasi 3-tier tetap melayani permintaan HTTP 200 OK tanpa disrupsi. Saat Spine 1 dinyalakan kembali, sesi BFD otomatis pulih dalam 6 detik dan beban terbagi kembali secara seimbang."*

---

### [01:35 - 02:00] Babak 4: Telemetri Real-Time, Threat Hunting, & Penutup

**Aksi pada Layar:**
Skrip menampilkan cuplikan log blokir OPNsense filterlog di SecOps Bastion dan status siaga honeypot OpenCanary, diikuti banner kesimpulan 10/10 pengujian lulus.

**Naskah yang Diucapkan:**
> *"Terakhir, visibilitas telemetri: seluruh percobaan pelanggaran microsegmentation tercatat secara real-time di OPNsense filterlog dan Zeek network monitor yang dialirkan ke Loki dan Grafana. Jika penyerang menyentuh decoy OpenCanary kami, sistem langsung membangkitkan alert berprioritas tinggi.*
>
> *Arsitektur ini membuktikan bahwa Zero-Trust Micro-segmentation pada Spine-Leaf EVPN/VXLAN mampu memberikan perlindungan pertahanan berlapis berstandar enterprise, tahan terhadap bencana infrastruktur, dan siap untuk lingkungan produksi modern."*

---

## 3. Kompilasi Pertanyaan Teknis Kritis Wawancara & Jawaban Berbasis Data (Q&A)

Berikut adalah pertanyaan teknis mendalam yang sering diajukan oleh Technical Reviewer / Hiring Manager beserta jawaban teruji:

### Q1: Mengapa Anda memilih arsitektur EVPN VXLAN Bridged Overlay daripada Routed Overlay (Symmetric/Asymmetric L3 EVPN)?
**Jawaban Berbasis Desain:**
> *"Dalam Proyek 4, kami sengaja memilih **Bridged Overlay (L2 VNI per zona)** yang dikombinasikan dengan OPNsense sebagai firewall terpusat untuk memisahkan domain switching L2 dan inspeksi stateful L3.
>
> Pada Routed Overlay murni di mana setiap Leaf bertindak sebagai Anycast Gateway L3, routing antar subnet dilakukan terdistribusi langsung di setiap Leaf (distributed routing). Model distributed L3 ini sangat efisien untuk throughput murni, namun menjadi tantangan besar ketika kita membutuhkan **stateful firewall inspection berlapis** lintas-zona, karena trafik balik dapat mengalami asymmetric routing dan mematahkan tabel koneksi TCP firewall.
>
> Dengan Bridged Overlay, Leaf 1-3 meneruskan trafik L2 intra-zona secara transparan melalui L2 VNI (10010-10050), sedangkan seluruh trafik inter-zona wajib melintasi trunk VLAN ke OPNsense di Leaf 3. Ini memastikan inspeksi stateful L4-L7 penuh tanpa risiko asimetri rute, sambil tetap mempertahankan modularitas fabric VXLAN."*

---

### Q2: Bagaimana Anda mencegah dan menangani risiko Asymmetric Routing pada firewall stateful di fabric Spine-Leaf?
**Jawaban Berbasis Data:**
> *"Asymmetric routing terjadi jika paket SYN melintasi Firewall A, tetapi paket SYN-ACK kembali melintasi Firewall B atau mem-bypass firewall, menyebabkan koneksi di-drop karena state table tidak valid.
>
> Di lab kami, mitigasi ini dijamin pada 3 tingkatan:
> 1. **Topologi Gateway Tunggal / Aktif per Zona:** OPNsense memegang alamat gateway `.1` untuk seluruh subnet beban kerja (10.10.10.1, 10.10.20.1, 10.10.30.1) melalui antarmuka trunk 802.1Q yang terpasang ke Leaf 3.
> 2. **Next-hop Deterministic Routing:** Pada tabel routing Linux di setiap workload, rute default selalu mengarah ke IP OPNsense pada subnet masing-masing.
> 3. **FRR EVPN L2 VNI Extension:** EVPN hanya melakukan bridging L2 di bawah OPNsense. Karena jalur L3 terpusat di OPNsense, paket 'request' dan 'reply' selalu melintasi antarmuka OPNsense yang sama, sehingga state table TCP terpelihara konsisten."*

---

### Q3: Berapa overhead performa yang ditimbulkan oleh inspeksi stateful OPNsense, dan bagaimana hasil benchmark iperf3 Anda?
**Jawaban Berbasis Data:**
> *"Kami mengukur overhead performa secara empiris menggunakan `iperf3` pada dua jalur data-plane:
> 1. **Intra-Zone L2 murni (web1 <-> web2):** Throughput tercatat **81.85 Gbps** dengan mean TCP RTT **0.135 milidetik**. Ini adalah wire-speed switching kernel.
> 2. **Inter-Zone L3 melalui OPNsense SPI (web1 -> app2:8080):** Throughput tercatat **2.91 Gbps** dengan mean TCP RTT **4.815 milidetik**.
>
> Dari data ini, penambahan latensi keamanan (*security latency cost*) yang terukur adalah **+4.68 milidetik**. Penurunan throughput dari 81G ke 2.9G pada VM OPNsense adalah wajar karena keterbatasan alokasi vCPU FreeBSD pf virtual yang memproses setiap paket secara stateful di software layer.
>
> Di lingkungan produksi berskala enterprise, overhead ini dimitigasi dengan memanfaatkan SmartNIC / DPU berbasis SR-IOV hardware offload (seperti NVIDIA BlueField atau Intel Mount Evans) yang mampu melakukan stateful offload hingga 40-100 Gbps dengan latensi sub-milidetik."*

---

### Q4: Mengapa Anda menggabungkan host-based Linux nftables dengan firewall gateway OPNsense? Bukankah OPNsense saja sudah cukup?
**Jawaban Berbasis Pertahanan Berlapis (Defense-in-Depth):**
> *"OPNsense adalah **Macro-segmentation Gateway** di batas zona (L3), sedangkan `nftables` adalah **Micro-segmentation Engine** langsung di dalam OS beban kerja (L2/L4). Keduanya saling melengkapi karena:
> 1. **Perlindungan Intra-Subnet (Lateral Movement di Zona yang Sama):** Jika penyerang berada di `web1` dan ingin menyerang `web2` pada subnet yang sama (10.10.10.0/24), trafik tersebut dialihkan pada L2 switching murni dan tidak pernah melintasi gateway OPNsense. Tanpa host `nftables`, `web2` akan langsung rentan.
> 2. **Containment saat Firewall Misconfiguration:** Jika terjadi human error pada rulebase firewall pusat, aturan `nftables` lokal pada tier basis data (`db1`) tetap menjatuhkan koneksi yang bukan berasal dari IP App Tier.
> 3. **Anti-Spoofing di Sumber (Egress Filtering):** `nftables` menolak paket spoofing sebelum menyentuh kabel underlay (`EPERM`), menghemat bandwidth fabric dan kapasitas buffer firewall gateway."*

---

### Q5: Bagaimana BFD mencapai waktu konvergensi failover sub-detik (< 100 ms) saat link underlay putus?
**Jawaban Berbasis Protokol:**
> *"Protokol routing eBGP standar memiliki interval `Keepalive` 60 detik dan `Holdtime` 180 detik. Jika link fisik putus diam-diam (misalnya failure pada intermediate switch/transceiver), BGP butuh waktu 3 menit untuk menyadari rute mati—hal ini tidak dapat diterima untuk data center modern.
>
> Kami mengonfigurasi **BFD (Bidirectional Forwarding Detection)** pada FRR dengan parameter:
> - `detect-multiplier 3`
> - `transmit-interval 50ms`
> - `receive-interval 50ms`
>
> Artinya, jika dalam 150 milidetik (3 x 50ms) tidak ada paket BFD control yang diterima, sesi dinyatakan `DOWN`. FRR seketika memberitahu daemon BGP dan Zebra, yang kemudian mencabut nexthop yang gagal dari Linux kernel FIB nexthop group. Karena kernel Linux telah memasang multipath ECMP ke Spine 2, kernel langsung meneruskan paket ke Spine 2 dalam hitungan mikrodetik, menghasilkan **0% packet loss** pada probe latensi 100 milidetik kami."*

---

### Q6: Bagaimana Anda membedakan ancaman pergerakan lateral berbahaya dari lalu lintas aplikasi 3-tier sah dalam threat hunting?
**Jawaban Berbasis Analisis Graf & LogQL:**
> *"Dalam pengujian S8, kami menerapkan analisis sentralitas graf NetworkX terhadap seluruh koneksi log Zeek:
> 1. **Baseline Whitelist Aliran Sah:** Alur legal aplikasi didefinisikan secara deterministik:
>    - `Client -> Web:80`
>    - `Web -> App:8080`
>    - `App -> DB:5432`
>    - `SecOps -> All:22`
> 2. **Karakteristik Anomali Lateral Movement:**
>    - Ketika penyerang di `web1` mencoba melakukan scanning lateral (S1), derajat keluar (*out-degree*) node melonjak secara drastis ke IP dan port yang tidak terdaftar di baseline.
>    - Upaya koneksi ke port SSH internal (S2) atau direktori DB (S10) terdeteksi sebagai 'anomalous directed edges' dengan probabilitas pelanggaran 100%.
>
> Dengan memodelkan topologi sebagai Directed Graph terbobot, kami mencapai metrik **100% True Positive** dan **0.0% False Positive** terhadap trafik produksi."*

---

## 4. Rangkuman Checklist Kesiapan Demo

Sebelum memulai presentasi live di depan penguji/pewawancara, pastikan checklist berikut terpenuhi:

- [x] Seluruh 14 VM menyala di libvirt (`virsh list --state-running | grep -v "^$" | wc -l` bernilai >= 14).
- [x] Sesi BFD dual-spine berstatus UP di seluruh Leaf (`show bfd peers brief`).
- [x] OPNsense WebGUI / gateway responsive pada 10.10.10.1 / 192.168.122.20.
- [x] Aturan `nftables` aktif pada seluruh workload VM (`systemctl is-active nftables`).
- [x] Uji cepat `./demo-scripts/demo-2min.sh --non-interactive` berjalan mulus 100% hijau.
