# Proyek 4: Data Center Network Micro-segmentation dan Lateral Movement Hunting

> File konteks untuk Claude. Baca seluruh file ini di awal percakapan baru agar kerja bisa dilanjutkan tanpa mengulang diskusi. Perbarui bagian "Status dan log progres" (bagian 16) setiap kali satu langkah selesai.

## 1. Tentang pengguna dan tujuan

- Pengguna: Natanael, mahasiswa di Indonesia (jaringan komputer, dll.).
- **Tujuan: portofolio untuk melamar magang.** Yang dinilai adalah kedalaman satu proyek yang rapi, terdokumentasi, dan **terukur**, bukan banyaknya fitur.
- Bahasa: **Indonesia** (boleh formal maupun santai). README akhir dibuat dwibahasa (Inggris sebagai utama, Indonesia sebagai pendamping), seperti proyek 3.
- Cara kerja yang diinginkan:
  - Kerjakan **satu komponen/langkah sekali**, jangan melompat ke depan.
  - Penjelasan **lengkap dan menyeluruh**, jangan ada langkah yang dilewati atau disederhanakan.
  - Pengguna kritis dan akan menanyakan hal yang janggal. Akui kesalahan secara jujur dan koreksi, jangan berkelit.
  - Jika sebuah klaim bergantung pada versi/dokumentasi resmi, **verifikasi ke dokumentasi** (jangan dari ingatan). Dokumen ini sengaja **tidak mengunci nomor versi apa pun**; semua versi diverifikasi dan dikunci saat fasenya (lihat bagian 14).
  - Di setiap langkah, **ingatkan pengguna untuk mendokumentasikannya**: bagian mana yang didokumentasikan, apa isinya, dan apakah screenshot saja cukup. Prinsip: output terminal disimpan sebagai teks, screenshot hanya untuk hal visual (dashboard Grafana, GUI OPNsense, grafik), dan setiap langkah punya bagian tujuan, perintah, output penting, versi, serta masalah dan keputusan.
  - Pelajaran dari proyek 3 yang dibawa ke sini: periksa skrip unduhan sebelum dijalankan; jangan `apt upgrade` di node setelah versi dikunci; catat kesalahan dan koreksinya di dokumentasi (bagian "masalah dan keputusan" justru nilai tambah); jangan simpan kunci/token/password di repo.

## 2. Konteks proyek

Dari empat ide portofolio awal, urutan yang diputuskan: **proyek 3 (selesai penuh)**, lalu **proyek 4 (dokumen ini, versi ringan)**. Proyek 1 (Zero Trust hybrid backbone) dan proyek 2 (SOAR/DFIR) ditunda. Simulasi Active Directory **ditunda dan opsional** (lihat bagian 13).

Proyek 3 membuktikan pertahanan di lapisan **workload/kontainer** (Kubernetes, eBPF, admission control). Proyek 4 melengkapi dari sisi **jaringan data center**: bagaimana fabric Spine-Leaf dirancang, bagaimana trafik antar zona dipaksa lewat titik kontrol, dan bagaimana penyerang yang sudah di dalam (lateral movement) **dideteksi dan dibatasi**. Dua proyek ini bersama menceritakan pertahanan berlapis dari jaringan sampai workload.

### Brief proyek 4

- **Domain:** Data Center Networking, Network Security, Threat Hunting.
- **Tantangan teknis:** pada jaringan data center, trafik east-west (antar server) umumnya jauh lebih besar dan lebih jarang diawasi dibanding trafik north-south. Penyerang yang menguasai satu server dapat berpindah ke server lain. Proyek ini membangun fabric yang tersegmentasi dan menunjukkan secara terukur bahwa segmentasi mengecilkan *blast radius*, serta bahwa pergerakan lateral tetap bisa diburu lewat telemetri jaringan dan umpan (decoy).
- **Implementasi:**
  - Fabric **Spine-Leaf** dengan **FRRouting**: underlay eBGP + ECMP (+ BFD), overlay VXLAN/EVPN (Bridged Overlay / L2 VNI per zona; centralized L3 gateway di OPNsense).
  - **OPNsense** sebagai titik penegakan kebijakan antar zona (default deny, logging).
  - **Micro-segmentation** di dalam zona memakai firewall host (nftables) yang dikelola Ansible.
  - **OpenCanary** sebagai honeypot/decoy.
  - **Zeek** (di VM sensor) menganalisis trafik hasil mirroring; log dikumpulkan ke **Loki + Grafana** untuk *hunting*.
  - Simulasi serangan lateral movement di lab sendiri, dengan skema **sebelum** (fabric datar/permisif) dan **sesudah** (tersegmentasi).
- **Bukti portofolio:** repo IaC (libvirt, cloud-init, Ansible, konfigurasi FRR), kebijakan firewall dan nftables, aturan/ kueri hunting, matriks keterjangkauan sebelum/sesudah, laporan pengujian dengan pemetaan MITRE ATT&CK, angka terukur (waktu deteksi, konvergensi failover, pengurangan blast radius), demo 1-2 menit.

## 3. Keputusan yang sudah diambil dan yang masih terbuka

### Sudah diputuskan (dari percakapan sebelumnya)

| Keputusan | Pilihan |
|---|---|
| Urutan proyek | 3 selesai, 4 sekarang |
| Cakupan | Versi ringan: Spine-Leaf FRR/VyOS, segmentasi OPNsense, OpenCanary, analisis dengan Zeek/Wireshark. Active Directory ditunda |
| Virtualisasi | KVM/libvirt di host yang sama dengan proyek 3 |
| Biaya | **Tanpa biaya**, semua tool open source |

### Usulan yang perlu dikonfirmasi pengguna sebelum Fase 0 selesai

| # | Pertanyaan | Opsi | Usulan | Alasan singkat |
|---|---|---|---|---|
| D1 | Apa yang dijadikan router spine/leaf? | (a) Ubuntu 24.04 + FRR dari paket; (b) VyOS; (c) Containerlab dengan kontainer FRR | **(a)** | Memakai ulang pipeline `create-vm.sh` + cloud-init + overlay qcow2 dari proyek 3; semua kontrol atas kernel (VRF, VXLAN, `tc`) tersedia; konfigurasi FRR murni (bukan abstraksi vendor) lebih bernilai untuk dipelajari. VyOS: ketersediaan image gratis stabil perlu diperiksa (jangan diasumsikan). Containerlab: jauh lebih hemat RAM dan topologinya deklaratif (YAML), tetapi OPNsense tetap butuh VM sehingga jadi hibrida yang lebih rumit. Boleh dibahas ulang jika RAM jadi masalah |
| D2 | Apakah overlay EVPN/VXLAN termasuk inti? | Ya: Opsi A (Bridged Overlay / L2 VNI per zona) / Opsi B (Symmetric IRB / L3 VNI) / Fabric routed biasa tanpa overlay | **Ya, Opsi A (Bridged Overlay)** | Opsi A membuktikan L2 EVPN fabric (BGP control plane, VNI per zona) sekaligus menjamin seluruh inspeksi inter-zona 100% simetris lewat OPNsense. Opsi B (Symmetric IRB) dialihkan ke pengembangan opsional (Bagian 13). Fallback ke routed biasa tetap disiapkan jika ada kendala fatal (bagian 6.4) |
| D3 | Ukuran topologi | 2 spine + 3 leaf (usulan) / lebih besar | 2 spine + 3 leaf | Cukup untuk ECMP, failover, dan lintas-leaf; RAM aman |
| D4 | Stack log dan hunting | Loki+Grafana / Elastic / berkas + `jq` saja | Loki + Grafana | Lebih ringan dari Elastic; Grafana bagus untuk screenshot |
| D5 | Sensor jaringan | Zeek / Suricata / keduanya | Zeek dulu; Suricata opsional | Zeek menghasilkan log terstruktur ideal untuk hunting dan analisis (cocok dengan latar ML pengguna) |

## 4. Lingkungan pengguna (host)

Sama dengan proyek 3 (Lenovo Legion Pro 5 16IRX9, i9-14900HX 32 thread, RAM 31 GiB + swap 8 GiB, disk root 460 GB dengan sekitar 348 GB kosong sebelum proyek 3, host Ubuntu 24.04.5, kernel 7.0.0-34, KVM/libvirt, Docker terpasang, repo proyek 3 di `~/k8s-hardened-platform`). Pengguna terbiasa dengan Linux dan terminal. **Cek ulang sisa disk dan RAM di Fase 0** (jangan memakai angka lama).

Hal dari proyek 3 yang berlaku di sini:

- Image dasar Ubuntu cloud `release-20260926` di `/var/lib/libvirt/images/` **tetap dipakai** (tidak dipindah/diubah); VM baru memakai overlay qcow2.
- `infra/create-vm.sh` dari proyek 3 dijadikan titik awal, diperluas untuk **banyak NIC** dan parameter RAM/vCPU per peran.
- Jaringan libvirt `default` (NAT `192.168.122.0/24`, reservation `.10-.12` sudah dipakai proyek 3) dipakai hanya sebagai jaringan **manajemen/bootstrap** (lihat 6.5).
- Pengguna ada di grup `docker`: Docker memuat `br_netfilter` dan mengatur aturan iptables, yang berpotensi memengaruhi trafik antar VM pada bridge libvirt (lihat risiko R1).
- Subnet yang **sudah terpakai dan tidak boleh bentrok**: `192.168.122.0/24` (libvirt default), `192.168.1.0/24` (WiFi host), `172.17.0.0/16` (Docker), `10.42.0.0/16` dan `10.43.0.0/16` (pod/service k3s proyek 3, hanya dalam klaster tetapi dihindari agar tidak membingungkan).

## 5. Anggaran sumber daya

Prinsip: **VM proyek 3 dimatikan (`virsh shutdown`, bukan dihapus)** selama proyek 4 berjalan, karena dipertahankan untuk demo portofolio proyek 3. Nyalakan kembali bila perlu.

| VM | Peran | vCPU | RAM | Disk (overlay) | Jumlah | Subtotal RAM |
|---|---|---|---|---|---|---|
| spine1, spine2 | Spine (FRR) | 1 | 1 GB | 8-10 GB | 2 | 2 GB |
| leaf1, leaf2, leaf3 | Leaf (FRR); leaf3 juga *border leaf* | 2 | 1 GB | 8-10 GB | 3 | 3 GB |
| opnsense | Firewall segmentasi | 2 | 2 GB (cek minimum di dokumentasi OPNsense) | 16-20 GB | 1 | 2 GB |
| web1, web2 | Zona web | 1 | 1 GB | 10 GB | 2 | 2 GB |
| app1, app2 | Zona aplikasi | 1 | 1 GB | 10 GB | 2 | 2 GB |
| db1 | Zona database | 1-2 | 1,5 GB | 12 GB | 1 | 1,5 GB |
| canary1 | Decoy OpenCanary | 1 | 1 GB | 8 GB | 1 | 1 GB |
| secops | Zeek + Loki + Grafana + bastion Ansible | 2-4 | 4 GB | 30 GB | 1 | 4 GB |
| attacker | Penyerang eksternal (sisi "internet") | 1 | 1 GB | 8 GB | 1 | 1 GB |
| **Total** | | | **sekitar 18,5 GB** | **sekitar 150 GB** | 14 VM | |

Catatan: ini estimasi awal. Dengan pemakaian dasar host sekitar 5,5 GiB, total sekitar 24 GiB dari 31 GiB; swap 8 GiB sebagai cadangan. Strategi jika sempit: nyalakan VM bertahap per fase (misalnya workload belum perlu menyala saat Fase 2), kurangi RAM spine/leaf setelah diukur pemakaian nyatanya. Keputusan akhir diambil di Fase 0 setelah mengukur.

## 6. Arsitektur target

### 6.1 Topologi logis

```
                     [ attacker ]  (jaringan "ext-sim", 203.0.113.0/24)
                           |
                     [ OPNsense ]  --- (jaringan manajemen/update lewat NAT libvirt default)
                           |  trunk 802.1Q, satu VLAN per zona
   spine1 ---------------- leaf3 (border) ---------------- spine2
     |  \                  /    |     \                  /   |
     |   \________________/     |      \________________/    |
     |    ________________      |       ________________     |
     |   /                \     |      /                \    |
   leaf1                   leaf2 (terhubung ke KEDUA spine; digambar disederhanakan)
   web1, web2              app1, app2       leaf3: db1, canary1, secops

Setiap leaf punya 2 uplink (satu ke tiap spine) -> 6 link spine-leaf, ECMP 2 jalur.
```

Hubungan fisik (virtual) sesungguhnya:

| Link | Antara | Jaringan libvirt (isolated, tanpa forward) |
|---|---|---|
| L1 | spine1 - leaf1 | `lnk-s1-l1` |
| L2 | spine1 - leaf2 | `lnk-s1-l2` |
| L3 | spine1 - leaf3 | `lnk-s1-l3` |
| L4 | spine2 - leaf1 | `lnk-s2-l1` |
| L5 | spine2 - leaf2 | `lnk-s2-l2` |
| L6 | spine2 - leaf3 | `lnk-s2-l3` |
| A1 | leaf1 - web1, web2 | `acc-l1` (segmen akses leaf1) |
| A2 | leaf2 - app1, app2 | `acc-l2` |
| A3 | leaf3 - db1, canary1, secops | `acc-l3-db`, `acc-l3-dec`, `acc-l3-mgmt` (jaringan libvirt terpisah per zona, lihat catatan) |
| T1 | leaf3 - opnsense (trunk VLAN) | `trunk-fw` |
| X1 | opnsense - attacker | `ext-sim` |
| M | semua VM jaringan + opnsense + secops (bootstrap/OOB) | `default` (NAT, sudah ada) |
| MIR | leaf1/2/3 -> secops (mirror) | `mirror-l1`, `mirror-l2`, `mirror-l3` (tiga jaringan terpisah, 3 NIC sensor di secops; lihat 6.6) |

Catatan A3: karena db1, canary1, dan secops berada di zona berbeda tetapi di leaf yang sama, diputuskan menggunakan jaringan libvirt terpisah per zona (`acc-l3-db`, `acc-l3-dec`, `acc-l3-mgmt`). Alasan: bridge Linux tanpa `vlan_filtering` tidak menegakkan pemisahan VLAN di level host, sehingga pembagian bridge bersama dengan tag VLAN tidak memberi isolasi nyata. Sebaliknya, trunk `trunk-fw` (leaf3 ke OPNsense) tetap bertag 802.1Q karena bridge tersebut hanya memiliki dua port point-to-point.

### 6.2 Zona dan rencana alamat (usulan, dikunci di Fase 0)

Model yang digunakan adalah **Bridged Overlay (L2 EVPN)** dengan gateway terpusat di OPNsense:

| Zona | Subnet | Gateway (OPNsense) | Host | L2 VNI | Keterangan |
|---|---|---|---|---|---|
| Web (DMZ internal) | 10.10.10.0/24 | 10.10.10.1 | web1 (.11), web2 (.12) | 10010 | Port publikasi ke attacker lewat OPNsense |
| Aplikasi | 10.10.20.0/24 | 10.10.20.1 | app1 (.11), app2 (.12) | 10020 | Backend layanan aplikasi |
| Database | 10.10.30.0/24 | 10.10.30.1 | db1 (.11) | 10030 | Layanan data, hanya boleh diakses App & SecOps |
| Manajemen/SecOps | 10.10.40.0/24 | 10.10.40.1 | secops (.11) | 10040 | Bastion SSH, collector log Loki, Zeek |
| Decoy | 10.10.50.0/24 | 10.10.50.1 | canary1 (.11) | 10050 | Honeypot OpenCanary |
| Eksternal (simulasi) | 203.0.113.0/24 | 203.0.113.1 | attacker (.11) | - | Rentang TEST-NET-3 (RFC 5737), terhubung langsung ke OPNsense WAN |

Underlay:

| Item | Rencana |
|---|---|
| Loopback router | `10.255.0.0/24`: spine1 .1, spine2 .2, leaf1 .11, leaf2 .12, leaf3 .13 |
| Link point-to-point | `/31` dari `10.254.0.0/24` (satu /31 per link) |
| ASN | Spine berbagi satu ASN privat (misalnya 65000); tiap leaf ASN privat unik (65001, 65002, 65003) |
| Routing | eBGP spine-leaf, `maximum-paths` untuk ECMP, BFD untuk deteksi cepat |
| MTU | Underlay lebih besar (misal 9000, **jika bridge libvirt mendukung**) agar VXLAN tidak memecah paket; jika tidak, turunkan MTU overlay. Diverifikasi di Fase 1 |

### 6.3 Aliran trafik antar zona (Opsi A: Bridged Overlay + Centralized FW)

- **Dalam satu zona, satu leaf:** tetap lokal di leaf (bridge). Dikendalikan oleh **firewall host (nftables)**.
- **Dalam satu zona, lintas leaf:** L2 VNI (EVPN) membawa frame Ethernet melintasi fabric underlay eBGP; tetap dibatasi nftables di host target.
- **Antar zona:** Default gateway seluruh host berada di OPNsense (`.1`). Ketika host di Zona Web mengirim paket ke Zona App, paket diarahkan ke MAC gateway OPNsense, dibawa via L2 VNI Web (10010) ke Leaf3, lalu di-trunk ke interface OPNsense (VLAN 10). OPNsense memeriksa kebijakan (stateful inspection, default deny, logging), melakukan routing ke interface Zona App (VLAN 20), lalu Leaf3 membungkusnya ke L2 VNI App (10020) menuju Leaf2. Rute bolak-balik **terjamin 100% simetris** sehingga *state table* OPNsense bekerja konsisten.
- **Utara-selatan:** Zona ke "internet" (termasuk `apt` dari server setelah jalur OOB dilepas) lewat OPNsense dengan NAT dan aturan egress ketat. Penyerang eksternal masuk lewat interface WAN OPNsense menuju web (sesuai aturan port forward/publikasi).

### 6.4 Fallback jika EVPN terlalu berat (gerbang keputusan akhir Fase 3)

Jika EVPN/VXLAN pada FRR mengalami kendala stabilitas atau kompatibilitas kernel yang memakan waktu berlebih, fabric diturunkan ke **VLAN trunking L2 tradisional atau fabric routed biasa tanpa overlay**: segmentasi inter-zona tetap ditegakkan oleh OPNsense dan intra-zona oleh nftables. Cerita *micro-segmentation*, *hunting*, dan matriks keterjangkauan tetap utuh. Perubahan rencana ini dicatat di bagian keputusan desain dokumentasi.

### 6.5 Prinsip jalur manajemen (penting: cegah "jalan tikus" lateral)

Masalah desain yang harus dihindari: jika semua VM punya NIC di jaringan `default` (NAT libvirt), maka **semua server bisa saling mencapai lewat jaringan itu**, melewati seluruh segmentasi. Solusi:

1. NIC `default` dipakai **hanya untuk bootstrap** (cloud-init, `apt`, SSH awal) dan **tetap untuk perangkat jaringan, OPNsense, dan secops** (jalur OOB yang memang realistis di data center).
2. Untuk **VM server (web, app, db, canary, attacker)**: setelah bootstrap selesai, NIC `default` **dilepas** (`virsh detach-interface` dan dihapus dari XML domain).
3. **Akses administratif Ansible selanjutnya:**
   - Dijalankan dari host menggunakan **`ssh -J` (ProxyJump)** melewati `secops` (bastion), **BUKAN SSH agent forwarding (`-A`)**. Alasan: skenario S3 secara spesifik menguji pembajakan SSH agent, sehingga alur admin sendiri tidak boleh membuka celah tersebut (kunci privat tetap tersimpan aman di host).
   - Aliran koneksi SSH dari bastion `secops` ke server lain adalah **trafik east-west yang sah**. Akses ini dibuat eksplisit pada aturan OPNsense (SSH ke zona lain hanya diizinkan dari `secops`) dan dimasukkan ke dalam **baseline hunting**. Pola "satu host membuka SSH ke banyak host" mirip dengan perilaku penyerang, sehingga aturan hunting harus mampu membedakan berdasarkan identitas sumber (*allowlist bastion*). Ini menjadi tolok ukur kualitas aturan hunting.
   - *Trade-off tercatat:* VM `secops` menjadi titik bernilai tinggi (*High-Value Target / HVT*).
4. Akses internet server selanjutnya (jika perlu) lewat OPNsense dengan NAT/egress terkontrol.
5. Setelah pelepasan, **dibuktikan** dengan uji: dari web1 tidak ada jalur ke `192.168.122.0/24`.

### 6.6 Desain telemetri jaringan

| Sumber | Mekanisme | Tujuan |
|---|---|---|
| Trafik antar server | **Port mirroring di leaf** memakai `tc` (aksi `mirred`) pada port akses leaf, **ingress saja** | 3 NIC sensor terpisah di `secops` (`eth1` mirror leaf1, `eth2` mirror leaf2, `eth3` mirror leaf3) dipantau oleh Zeek |
| Log firewall OPNsense | Remote syslog (RFC 3164) ke listener Alloy di `secops` | `secops` (Loki via Alloy) |
| Log nftables host | Aturan `log` dengan prefix, dikirim lewat syslog | `secops` (Loki via Alloy) |
| Log OpenCanary | JSON ke berkas / syslog | `secops` (Loki via Alloy) |
| Log FRR/sistem leaf | syslog (opsional) | `secops` (Loki via Alloy) |

Catatan teknis port mirroring & Zeek (diverifikasi di Fase 5):
- Menggunakan 3 jaringan libvirt isolated terpisah (`mirror-l1`, `mirror-l2`, `mirror-l3`) ke 3 NIC di `secops` untuk menghindari masalah *MAC learning* pada bridge host.
- Konsekuensi *ingress-only mirror*: paket request dan reply dari suatu koneksi antar-leaf akan masuk melalui dua NIC mirror yang berbeda. Oleh karena itu, Zeek harus berjalan sebagai **satu proses tunggal** yang memantau ketiga antarmuka sekaligus agar tidak menghasilkan *half-connection* yang menyesatkan di `conn.log`.
- Dukungan *multi-interface sniffing* native pada Zeek dan pencatatan interface asal diuji di Fase 5.

## 7. Komponen dan peran (apa yang dipakai)

| Komponen | Fungsi dalam proyek | Lisensi/biaya | Catatan verifikasi |
|---|---|---|---|
| **KVM/libvirt** | Menjalankan semua VM, jaringan isolated per link | Gratis | Sudah terpasang dari proyek 3 |
| **Ubuntu 24.04 cloud image** | OS untuk spine, leaf, server, secops | Gratis | Memakai base image yang sama |
| **cloud-init** | Provisioning awal (user, SSH key, hostname, paket) | Gratis | Diperluas: multi-NIC (network-config) |
| **FRRouting (FRR)** | BGP, BFD, EVPN, VRF pada spine/leaf | Gratis (GPL) | Pilih sumber paket (repo Ubuntu vs repo resmi FRR), kunci versi |
| **Kernel Linux: VRF, VXLAN, bridge, `tc`** | Data plane leaf, mirroring | Bagian OS | Verifikasi dukungan modul di kernel node (seperti 1.1 proyek 3) |
| **OPNsense** | Firewall antar zona, NAT, log | Gratis (BSD) | Unduh ISO/image, instalasi semi-otomatis lewat serial console/VNC, ekspor `config.xml` (disanitasi), prosedur restore terdokumentasi (diakui sebagai satu-satunya bagian non-IaC murni); cek minimum RAM; cek catatan NIC virtio |
| **nftables + Ansible** | Micro-segmentation host-based, dikelola sebagai kode | Gratis | Verifikasi sintaks `nft -c` sebelum terapkan |
| **OpenCanary** | Honeypot/decoy (SSH, HTTP, dan modul lain yang tersedia) | Gratis (BSD) | Cek daftar modul dan cara instal di dokumentasi |
| **Zeek** | Analisis trafik, log `conn`, `ssh`, `dns`, `notice` | Gratis (BSD) | Sumber paket, mode JSON, dukungan sniffing multi-antarmuka |
| **Loki + Grafana + Grafana Alloy** | Pengumpulan (Alloy: syslog OPNsense, log Zeek, OpenCanary), penyimpanan & kueri (Loki), dan visualisasi (Grafana) | Gratis (AGPL/Apache) | Promtail resmi deprecated; Alloy sebagai sentral pengumpul log di `secops` (verifikasi di Fase 5) |
| **Workloads & Traffic Gen** | Aplikasi 3-tier dummy (web->app->db) + skrip generator trafik normal | Gratis | Generator diberi *random jitter* dan trafik admin berkala (Ansible/SSH) agar baseline realistis untuk uji TP/FP |
| **Python (pandas, networkx)** | Membangun graf baseline trafik east-west dan mendeteksi tepi baru | Gratis | Memanfaatkan latar ML pengguna |
| **nmap, ssh/ssh-agent, netcat, curl, iperf3** | Alat uji dan simulasi serangan standar di lab sendiri | Gratis | Hanya alat standar, tanpa malware |
| **Wireshark/tshark** | Analisis pcap manual, tangkapan layar | Gratis | Di host atau secops |
| **Git + GitHub (+ Actions untuk lint)** | Repo IaC, riwayat commit bertahap | Gratis | Lint: yamllint, ansible-lint, `nft -c` |

## 8. Struktur repo yang direncanakan

Repo baru terpisah dari proyek 3, misalnya `~/dc-microseg-lab`.

```
dc-microseg-lab/
├── README.md              (Inggris, etalase)
├── README.id.md           (Indonesia)
├── docs/                  (00-..nn, diagram, laporan, panduan demo)
│   └── images/
├── infra/
│   ├── libvirt/           (XML jaringan isolated per link)
│   ├── create-vm.sh       (turunan proyek 3, multi-NIC)
│   └── cloud-init/        (user-data, network-config per peran)
├── fabric/
│   ├── ansible/           (inventory, playbook, role: frr, vrf-evpn, nftables, zeek, loki)
│   ├── frr/               (templat frr.conf per node, atau dihasilkan Ansible)
│   └── opnsense/          (config.xml hasil ekspor, SUDAH disanitasi dari rahasia)
├── policies/
│   ├── opnsense/          (deskripsi aturan per zona, tabel matriks izin)
│   └── nftables/          (templat kebijakan host per peran)
├── workloads/             (aplikasi dummy 3-tier: web, app, db, skrip generator trafik dengan jitter)
├── telemetry/
│   ├── zeek/              (konfigurasi, skrip kustom)
│   ├── opencanary/        (opencanary.conf)
│   ├── loki-grafana/      (konfigurasi, dashboard JSON)
│   └── hunting/           (kueri LogQL, skrip Python graf baseline)
├── attack-tests/          (skenario + hasil + skrip pengukuran, harness otomatis)
└── .gitignore             (kunci, token, password, config rahasia)
```

Aturan repo: tidak ada rahasia (kunci SSH, password OPNsense, token) yang masuk Git; `config.xml` OPNsense disanitasi sebelum commit.

## 9. Skenario pengujian (bagian demo)

Dijalankan **hanya di lab milik pengguna sendiri**, bertujuan membuktikan pertahanan dan kemampuan deteksi. Alat: hanya utilitas standar (nmap, ssh, netcat, curl). Tidak ada pembuatan malware. Setiap skenario dijalankan **dua kali**: sebelum segmentasi (baseline permisif) dan sesudah.

Asumsi awal serangan: penyerang sudah mengendalikan satu server web (misalnya web1) atau datang dari sisi eksternal lewat OPNsense; tahap eksploitasi awal tidak disimulasikan.

| ID | Skenario | Teknik (ATT&CK, **verifikasi ke attack.mitre.org**) | Kontrol yang diuji | Hasil diharapkan sesudah |
|---|---|---|---|---|
| S1 | Pemindaian jaringan dari web1 ke zona lain | T1046 Network Service Discovery, T1018 Remote System Discovery | OPNsense + nftables + decoy | Dibatasi/diblokir; terdeteksi oleh Zeek (fan-out) dan menyentuh decoy |
| S2 | Pergerakan SSH berantai web1 -> app1 -> db1 dengan kredensial/kunci yang ditemukan | T1021.004 SSH, T1078 Valid Accounts | Segmentasi zona (web tidak boleh ke db) | Lompatan kedua/ketiga diblokir; rantai terlihat di hunting pada baseline |
| S3 | Pembajakan agen SSH (agent forwarding) | T1563.001 SSH Hijacking | Kebijakan SSH (nonaktifkan agent forwarding), segmentasi | Dicegah/dideteksi |
| S4 | Tunneling/pivot lewat SSH (`-L`/`-D`) | T1572 Protocol Tunneling, T1090 Proxy | Aturan egress, Zeek (sesi SSH lama dengan pola aneh) | Terdeteksi; akses lanjutan diblokir |
| S5 | Menyentuh decoy | (deteksi) | OpenCanary | Alert muncul dalam hitungan detik; **ukur waktu deteksi** |
| S6 | Eksfiltrasi dari db1 ke luar | T1041/T1048 (verifikasi) | Aturan egress OPNsense | Diblokir dan tercatat |
| S7 | Penyerang eksternal mencoba menjangkau zona selain web | (north-south) | OPNsense (hanya publikasi web yang diizinkan) | Diblokir |
| S8 | Mode deteksi saja: kebijakan permisif, buru serangan hanya dari telemetri | (hunting) | Zeek + Loki + graf baseline | Serangan S1-S4 teridentifikasi dari log; ukur true/false positive |
| S9 | Kegagalan link/spine | (ketahanan) | ECMP + BFD | Tidak ada pelanggaran segmentasi; **ukur waktu konvergensi** |
| S10 | (Opsional) Mencoba spoofing IP/zona dari server | T1036-ish (verifikasi) | rp_filter/antispoof di leaf, aturan nftables | Dicegah |

## 10. Metrik yang diukur (pembeda dari sekadar mengikuti tutorial)

| Metrik | Cara ukur | Mengapa penting |
|---|---|---|
| **Matriks keterjangkauan east-west** (N x N host x port) sebelum vs sesudah | Skrip otomatis (nmap/`nc`) dari tiap host ke tiap host | Angka inti: persentase pasangan yang bisa saling menjangkau turun dari X% ke Y% |
| **Blast radius**: jumlah host/layanan yang dapat dicapai dari web1 yang "dikompromikan" | Dari matriks di atas | Ringkasan satu angka untuk wawancara |
| **Waktu deteksi** decoy (S5) | Selisih stempel waktu serangan vs waktu muncul di Grafana | Seberapa cepat SOC tahu |
| **Waktu deteksi hunting** (S1-S4) | Dari kueri/skrip pada log Zeek | Kualitas aturan hunting |
| **True positive / false positive** aturan hunting terhadap trafik baseline | Hitung terhadap generator trafik normal | Aturan yang bising tidak berguna |
| **Waktu konvergensi** saat link/spine mati (S9) | Matikan link (`virsh domif-setlink`), ukur loss/latensi dengan ping/iperf3 | Bukti desain fabric tahan gangguan |
| **Overhead** (opsional) | iperf3 melewati/ tidak melewati firewall | Biaya keamanan terhadap throughput |

Semua pengukuran **diotomasi** dalam harness `attack-tests/run-all-verifications.sh` (gaya sama dengan proyek 3), dijalankan ulang sebelum dan sesudah segmentasi.

## 11. Fase pengerjaan

| Fase | Isi | Selesai jika |
|---|---|---|
| 0 | Perencanaan, anggaran sumber daya, rencana IP/ASN/VNI, pengecekan host (disk, RAM, Docker `br_netfilter`), repo baru, VM proyek 3 dimatikan | Rencana terkunci, repo siap, risiko R1 diperiksa |
| 1 | Jaringan libvirt isolated per link, perluas `create-vm.sh` untuk multi-NIC, buat VM jaringan (2 spine + 3 leaf), cek kernel (VRF, VXLAN, `tc`) | Semua VM jaringan menyala; link point-to-point saling ping di L2/L3 |
| 2 | FRR: underlay eBGP + ECMP + BFD, loopback saling terjangkau | Semua loopback terjangkau via 2 jalur ECMP; BFD session up |
| 3 | Overlay VXLAN/EVPN (Bridged Overlay / L2 VNI per zona); workload dummy untuk uji; **gerbang keputusan EVPN vs fallback** | Dua host di leaf berbeda, zona sama, saling ping lewat L2 VNI; trunk ke Leaf3/OPNsense siap (atau fallback aktif) |
| 4 | OPNsense: instal, trunk VLAN ke border leaf, antarmuka per zona, alur antar zona via firewall (awalnya izinkan semua + log), NAT, jaringan ext-sim | Antar zona lewat OPNsense terbukti (log firewall); attacker menjangkau web sesuai publikasi |
| 5 | Workload nyata (web, app, db), generator trafik normal, pelepasan NIC OOB server, telemetri: mirror `tc`, Zeek, Loki+Grafana, syslog, OpenCanary | Dashboard Grafana menampilkan log Zeek/OPNsense/OpenCanary; baseline trafik terekam |
| 6 | **Serangan baseline** (S1-S4, S6, S7 pada kondisi permisif) + pengembangan aturan hunting dan graf baseline (S8) | Serangan berhasil dan terlihat di telemetri; aturan hunting terukur TP/FP |
| 7 | **Penegakan segmentasi**: aturan OPNsense default-deny per zona, nftables via Ansible (micro-seg), egress ketat, antispoof; ulangi seluruh skenario + decoy (S5) | Matriks keterjangkauan turun; serangan gagal; alert tetap muncul |
| 8 | Uji ketahanan fabric (S9, S10), ukur konvergensi dan overhead | Angka terdokumentasi |
| 9 | Harness otomatis, laporan pengujian dengan pemetaan MITRE ATT&CK, README dwibahasa, diagram, panduan demo, rekaman demo, write-up | Semua artefak portofolio siap |
| Opsional | Simulasi Active Directory (lihat 13); Suricata; Wazuh; versi VyOS atau Containerlab sebagai pembanding; ekspor konfigurasi OPNsense via API | Hanya jika fase 0-9 selesai |

### Rincian Fase 0

| Langkah | Isi |
|---|---|
| 0.1 | Ukur kondisi host: sisa disk, RAM bebas, `virsh list --all` (pastikan VM proyek 3 dalam keadaan dimatikan dengan rapi), `virsh net-list --all` |
| 0.2 | Periksa risiko Docker/bridge: apakah `br_netfilter` termuat dan `net.bridge.bridge-nf-call-iptables` bernilai 1; catat kebijakan rantai `FORWARD` (lihat R1). Putuskan mitigasi hanya jika terbukti bermasalah |
| 0.3 | Konfirmasi keputusan terbuka D1-D5 (bagian 3) dan kunci rencana alamat/ASN/VNI (bagian 6.2) |
| 0.4 | Buat repo `dc-microseg-lab`, struktur direktori, `.gitignore` (kunci, token, password), commit awal |
| 0.5 | Tulis `docs/00-perencanaan-dan-anggaran.md` (anggaran RAM, topologi, tabel alamat, keputusan dan alasannya) |

### Rincian Fase 1

| Langkah | Isi |
|---|---|
| 1.1 | Rancang dan definisikan jaringan libvirt isolated (tanpa forward, tanpa DHCP) per link (bagian 6.1); atur MTU yang diperlukan; verifikasi dengan `virsh net-list` dan `bridge`/`ip link` di host |
| 1.2 | Perluas `create-vm.sh`: parameter RAM/vCPU, daftar NIC, MAC tetap, `network-config` cloud-init per peran; reservation DHCP di `default` untuk antarmuka manajemen |
| 1.3 | Buat spine1, spine2, leaf1, leaf2, leaf3; bootstrap lewat cloud-init; **tidak** menjalankan `apt upgrade` setelah versi dikunci |
| 1.4 | Verifikasi kernel node jaringan: modul VRF, VXLAN, bridge, `sch_ingress`/`cls_*`/`act_mirred` (untuk `tc`), forwarding IP aktif (`sysctl`), `rp_filter` |
| 1.5 | Beri IP link `/31` dan loopback; uji ping antar tetangga langsung; dokumentasikan topologi dan MAC |

### Rincian Fase 2

| Langkah | Isi |
|---|---|
| 2.1 | Pilih sumber paket FRR (repo Ubuntu vs repo resmi), **verifikasi versi dan fitur EVPN**, kunci versi, pasang di 5 node |
| 2.2 | Aktifkan daemon yang diperlukan (`bgpd`, `bfdd`), konfigurasi dasar tiap node (router-id = loopback) |
| 2.3 | eBGP spine-leaf (ASN sesuai 6.2), advertise loopback, `maximum-paths`; verifikasi sesi `Established` dan tabel rute |
| 2.4 | Aktifkan BFD untuk peer BGP; uji deteksi kegagalan |
| 2.5 | Verifikasi ECMP: dua jalur ke loopback leaf lain (`ip route`, `traceroute`); tangkap output sebagai teks |
| 2.6 | Jadikan konfigurasi sebagai kode: templat Ansible untuk `frr.conf`, commit; dokumentasi `docs/0x-underlay-bgp.md` |

### Rincian Fase 3 (ringkas, dirinci saat fasenya)

| Langkah | Isi |
|---|---|
| 3.1 | Verifikasi di dokumentasi FRR: model EVPN Bridged Overlay (L2 VNI), integrasi Linux bridge + VXLAN, prasyarat kernel |
| 3.2 | Perangkat VXLAN dan bridge per L2 VNI (10010-10050) di seluruh leaf sesuai zona yang dilayani |
| 3.3 | Aktifkan address-family `l2vpn evpn`, advertise VNI, uji penerimaan rute EVPN tipe-2 (MAC/IP) dan tipe-3 (IMET) |
| 3.4 | Pasang host uji sementara di zona yang sama pada leaf berbeda; uji ping L2 lintas leaf via VXLAN overlay |
| 3.5 | **Gerbang keputusan:** L2 EVPN stabil -> lanjut ke Fase 4; jika ada kendala fatal -> aktifkan fallback 6.4 dan catat alasannya |

### Rincian Fase 4-9

Dirinci langkah demi langkah saat memasuki fase tersebut (satu komponen sekali), dengan pola yang sama: verifikasi dokumentasi -> instal -> uji -> dokumentasi. Poin kunci tiap fase ada pada tabel fase di atas; hal-hal yang sudah diketahui perlu perhatian khusus tercantum di bagian 12 (risiko) dan bagian 14 (daftar verifikasi).

## 12. Risiko yang diwaspadai

| ID | Risiko | Mitigasi |
|---|---|---|
| R1 | Docker memuat `br_netfilter` dan mengatur iptables `FORWARD`; bisa menjatuhkan trafik antar VM pada bridge libvirt | Periksa di Fase 0 (0.2); jika bermasalah, atur sysctl/aturan secara terdokumentasi (bukan menonaktifkan Docker secara permanen tanpa dicatat) |
| R2 | RAM kurang saat semua VM menyala | Nyalakan bertahap; ukur pemakaian nyata; kurangi RAM node jaringan; VM proyek 3 tetap mati |
| R3 | Kompleksitas EVPN memakan waktu tanpa batas | Gerbang keputusan akhir Fase 3 dan fallback 6.4 |
| R4 | MTU/VXLAN: paket besar jatuh diam-diam | Atur MTU underlay atau turunkan MTU overlay; uji dengan ping `-M do -s` |
| R5 | Mirror `tc` tidak sampai ke sensor (pembelajaran MAC pada bridge) | Uji awal di Fase 5; opsi per-leaf NIC atau ageing bridge |
| R6 | Server masih punya jalur ke jaringan `default` sehingga segmentasi bocor | Prinsip 6.5; uji pembuktian "tidak ada jalur" |
| R7 | OPNsense di virtio: kemungkinan masalah offload checksum | Periksa catatan dokumentasi OPNsense; atur sesuai bila gejala muncul |
| R8 | Aturan terlalu ketat memutus manajemen sendiri | Mode "izinkan semua + log" dulu (audit), baru enforce; selalu sisakan jalur bastion yang diuji; simpan konsol serial/VNC VM sebagai jalan masuk darurat |
| R9 | Aturan hunting bising (false positive) | Ukur terhadap baseline; sederhanakan aturan sebelum menambah |
| R10 | Kompatibilitas versi | Catat dan kunci versi FRR, OPNsense, Zeek, OpenCanary, Loki, Grafana, Ansible; tidak upgrade di tengah jalan |
| R11 | Menambah fitur sebelum inti selesai (AD, Suricata, Wazuh) | Hanya setelah Fase 9 |
| R12 | Rahasia bocor ke Git | `.gitignore` ketat; sanitasi `config.xml`; periksa `git diff --staged` sebelum commit |

## 13. Opsional (hanya setelah Fase 9)

- **Pengembangan EVPN Opsi B:** Symmetric IRB dengan L3 VNI dan distributed anycast gateway (sebagai komparasi arsitektur di portofolio).
- **Simulasi Active Directory** (Windows Server evaluasi atau Samba AD): membuka skenario lateral movement khas AD. Berat di RAM dan lisensi evaluasi; sengaja ditunda.
- **Suricata** (di OPNsense atau sensor) sebagai pembanding Zeek.
- **Wazuh** untuk korelasi host.
- **VyOS atau Containerlab** sebagai implementasi pembanding fabric.
- **Integrasi dengan proyek 3:** mengirim log Hubble/Tetragon ke Loki yang sama untuk satu pandangan SOC ringan.

## 14. Daftar hal yang HARUS diverifikasi ke dokumentasi resmi saat fasenya (jangan dari ingatan)

| Hal | Fase |
|---|---|
| Versi terbaru stabil dan dukungan fitur EVPN pada FRR; cara instal resmi | 2-3 |
| Model EVPN bridged overlay (L2 VNI) di FRR, integrasi Linux bridge + VXLAN, prasyarat kernel | 3 |
| Dukungan kernel VRF/VXLAN pada kernel node, konfigurasi `tc mirred` | 1, 5 |
| Persyaratan minimum, cara unduh/verifikasi, dan penanganan NIC virtio pada OPNsense | 4 |
| Bagaimana OPNsense menangani VLAN, NAT, remote syslog, dan ekspor konfigurasi | 4 |
| Modul layanan OpenCanary yang tersedia dan format log | 5 |
| Cara instal Zeek, mode keluaran JSON, sniffing multi-antarmuka | 5 |
| Agen pengirim log yang direkomendasikan untuk Loki saat ini (Promtail vs Grafana Alloy), konfigurasi Loki/Grafana | 5 |
| ID teknik MITRE ATT&CK yang dipakai di laporan | 9 |
| Perilaku `virsh domif-setlink`/`detach-interface` untuk uji kegagalan dan pelepasan NIC | 5, 8 |

## 15. Bukti portofolio dan cara mengemasnya

- Repo IaC rapi dengan commit bertahap (libvirt, cloud-init, Ansible, FRR, kebijakan).
- Diagram topologi Spine-Leaf, zona, dan alur trafik antar zona (Mermaid di README).
- Matriks keterjangkauan sebelum/sesudah (tabel + heatmap) sebagai visual utama.
- Aturan hunting beserta penjelasan dan hasil TP/FP.
- Dashboard Grafana (screenshot) dan log Zeek/OpenCanary sebagai teks.
- Laporan pengujian dengan pemetaan MITRE ATT&CK dan analisis baseline vs hardened.
- Angka terukur: pengurangan blast radius, waktu deteksi, waktu konvergensi.
- README dwibahasa yang berdiri sendiri: masalah, diagram, hasil terukur, cara mereproduksi, keputusan desain (termasuk yang gagal dan diperbaiki).
- Panduan demo wawancara 2 menit dan rekaman 1-2 menit.
- Satu tulisan blog atau write-up.
- Tautan antar proyek: proyek 3 (workload) + proyek 4 (jaringan) = cerita pertahanan berlapis.

## 16. Status dan log progres

| Langkah | Tanggal | Status | Catatan / Hasil Ringkas |
|---|---|---|---|
| **0.1** | 2026-10-15 | Selesai | Pengukuran host: RAM available 23 GiB (used 7.1 GiB), disk free 327 GB, VM proyek 3 (`k3s-server`, `k3s-agent1`, `k3s-agent2`) dalam status shut off, network `default` aktif. |
| **0.2** | 2026-10-15 | Selesai | Pemeriksaan risiko Docker/bridge: `br_netfilter` tidak termuat, parameter `bridge-nf-call-iptables` belum aktif, rantai FORWARD bernilai ACCEPT. Risiko R1 saat ini aman (tidak perlu mitigasi). |
| **0.3** | 2026-10-15 | Selesai | Konfirmasi D1-D5 & rencana alamat/ASN/VNI terkunci. Verifikasi rute host: tidak ada overlap dengan subnet lab (10.10.x, 10.254.x, 10.255.x, 203.0.113.x aman). |
| **0.4** | 2026-10-15 | Selesai | Inisialisasi repo git `dc-microseg-lab`, kerangka direktori IaC lengkap, `.gitignore` ketat (anti kebocoran rahasia), dan commit awal (7c12e63). |
| **0.5** | 2026-10-15 | Selesai | Dokumen komprehensif `docs/00-perencanaan-dan-anggaran.md` selesai ditulis (mencakup hasil ukur host, anggaran 14 VM, keputusan D1-D5, topologi libvirt, IP/ASN/VNI, prinsip bastion & telemetri). Fase 0 resmi tuntas. |
| **1.1** | 2026-10-15 | Selesai | Perancangan & aktivasi 16 jaringan libvirt isolated (L2 murni, stp=off, delay=0, MTU 9000). Verifikasi host: seluruh bridge aktif di libvirt dan memiliki MTU 9000 di kernel Linux. |
| **1.2** | 2026-10-15 | Selesai | Otomasi IaC multi-NIC: `nodes.conf`, `setup-dhcp-reservations.sh`, cloud-init Netplan v2 dengan `optional: true` dan MAC matching, serta `create-vm.sh`. Seluruh 13 reservasi DHCP aktif di `default`. |
| **1.3** | 2026-10-15 | Selesai | Pembuatan 5 node fabric (`spine1-2`, `leaf1-3`). Seluruh VM aktif, cloud-init berhasil bootstrap `dcadmin`, SSH terverifikasi, seluruh MAC & penamaan interface (`eth0`-`eth7`) terbukti 100% konsisten. (Catatan: bug parsing MAC titik dua diperbaiki). |
| **1.4** | 2026-10-15 | Selesai | Konfigurasi & verifikasi kernel kelima node: modul `vrf`, `vxlan`, `bridge`, `sch_ingress`, `cls_flower`, `cls_u32`, `act_mirred` aktif. IP forwarding aktif (`net.ipv4.ip_forward = 1`), `rp_filter = 0`, `tcp_l3mdev_accept = 1`. (Catatan: instalasi `linux-modules-extra` untuk modul vrf). |
| **1.5** | 2026-10-15 | Selesai | Konfigurasi IP underlay P2P /31 dan loopback /32 via Netplan (`60-underlay.yaml`) pada 5 node. Pengujian ping L3 dan verifikasi Jumbo Frame MTU 9000 (`ping -M do -s 8972`) sukses 100% pada seluruh 6 link. Fase 1 resmi tuntas. |
| **2.1** | 2026-10-15 | Selesai | Pemasangan paket FRR resmi Ubuntu 24.04 di 5 node. Versi terpasang & terkunci (`apt-mark hold`): `frr 8.4.4-1.1ubuntu6.7` (fitur BGP EVPN L2/L3 VNI, BFD, dan ECMP terverifikasi penuh di dokumentasi resmi). |
| **2.2** | 2026-10-15 | Selesai | Aktivasi daemon `bgpd` & `bfdd` di `/etc/frr/daemons`, penambahan `dcadmin` ke grup `frr,frrvty`, serta penerapan konfigurasi basis `frr.conf` (hostname, ASN Spine 65000 / Leaf 65001-65003, router-id loopback /32, `no bgp default ipv4-unicast`) pada 5 node. Seluruh daemon terverifikasi aktif (`zebra bgpd watchfrr staticd bfdd`). |
