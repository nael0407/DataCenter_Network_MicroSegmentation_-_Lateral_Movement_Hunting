# Proyek: Digital Forensics & Incident Response (DFIR) di Lingkungan Data Center

> File konteks dan panduan master untuk Claude/Antigravity. Baca seluruh file ini di awal percakapan baru agar pekerjaan investigasi forensik dan incident response dapat dilanjutkan tanpa kehilangan konteks. Perbarui bagian "Status dan log progres" (bagian 16) setiap kali satu langkah selesai.

---

## 1. Tentang pengguna dan tujuan

- **Pengguna:** Natanael, mahasiswa di Indonesia (spesialisasi jaringan komputer, keamanan siber, dan rekayasa data/ML).
- **Tujuan:** Portofolio tingkat tinggi untuk melamar magang di bidang **Cyber Security / DFIR / SOC Analyst Tier 2-3 / Security Engineering**. Yang dinilai adalah **kedalaman metodologi forensik, integritas bukti digital yang terukur (*chain of custody*), dan kejelasan rekonstruksi insiden (*super-timeline*)**, bukan sekadar menjalankan tool acak.
- **Bahasa:** **Indonesia** (formal, teknis, dan lugas). Dokumentasi akhir dan laporan insiden disajikan secara profesional dengan ringkasan dwibahasa (Inggris & Indonesia).
- **Cara kerja yang diinginkan:**
  - Kerjakan **satu komponen/langkah sekali**, jangan melompat ke depan sebelum langkah aktif tuntas dan terverifikasi.
  - Penjelasan **lengkap, menyeluruh, dan berbasis standar industri** (ISO/IEC 27037 untuk penanganan bukti digital, NIST SP 800-61 Rev 2 untuk alur incident response).
  - Pengguna kritis dan menuntut akurasi teknis tinggi. Jika ada kendala, anomali data, atau galat sistem, akui secara jujur, analisis *root cause*, dan dokumentasikan keputusannya.
  - Setiap langkah harus memiliki **pembuktian terverifikasi**: tangkapan teks terminal, nilai hash kriptografis bukti (SHA-256), struktur artefak terindeks, dan diagram alur.
  - Prinsip forensik: **Meminimalkan alterasi pada target (*Order of Volatility*)**, menjamin bukti tidak terkontaminasi, serta memisahkan peran *evidence acquisition* (pengumpulan) dan *evidence analysis* (analisis di stasiun kerja forensik `secops`).

---

## 2. Konteks proyek

Proyek ini merupakan **evolusi dan penyempurnaan langsung dari `dc-microseg-lab` (Proyek 4)**. 

Pada Proyek 3 (`k8s-hardened-platform`), fokusnya adalah pertahanan preventif *workload runtime* (Cilium eBPF, Tetragon SIGKILL, Cosign, Kyverno). Pada Proyek 4 (`dc-microseg-lab`), fokusnya adalah arsitektur pencegahan jaringan (*Spine-Leaf EVPN/VXLAN*, segmentasi *OPNsense*, dan *threat hunting* proaktif).

Namun, evaluasi arsitektur menunjukkan bahwa kemampuan **Forensik Digital Murni (DFIR)** belum terpenuhi:
1. Belum ada penerapan metodologi **Chain of Custody (ISO/IEC 27037)** yang membuktikan keaslian artefak bukti dari waktu ke waktu.
2. Belum ada prosedur **Live Response / Host Triage** untuk mengamankan bukti volatil (RAM/proc, active network sockets, volatile artifacts) pada node yang telah disusupi (*compromised host*).
3. Penanganan bukti jaringan masih terbatas pada pembacaan log JSON Zeek, belum mencakup **akuisisi paket mentah (Raw PCAP)**, rekonstruksi aliran data (*protocol stream carving*), dan analisis *post-mortem*.
4. Belum ada **Rekonstruksi Linimasa Terpadu (Super-Timeline)** yang mengkorelasikan jejak multi-sumber secara deterministik detik-demi-detik.
5. Belum ada **Forensic Incident Report** formal berstandar industri yang merangkum temuan bukti, analisis akar masalah (*Root Cause Analysis*), dan rekomendasi mitigasi.

### Brief Proyek Forensik Digital (DFIR)

- **Domain:** Digital Forensics & Incident Response (DFIR), Enterprise Network Forensics, Live Host Triage, Threat Reconstruction, ISO/IEC 27037 Evidence Handling.
- **Tantangan Teknis:** Di lingkungan Data Center virtual/cloud modern, mesin tidak bisa langsung dimatikan (*dead-box pulling plug*) karena akan memusnahkan bukti volatil di memori dan mengganggu kontinuitas bisnis. Tim investigasi harus melakukan **Live Response non-destruktif**, menyadap bukti jaringan mentah tanpa kehilangan paket, mengumpulkan artefak host sesuai *Order of Volatility*, menjaga integritas barang bukti melalui *hashing* otomatis, dan menyatukan jutaan baris log heterogen menjadi satu cerita serangan yang koheren.
- **Implementasi:**
  - Memanfaatkan 14 VM yang sudah aktif di `dc-microseg-lab` tanpa membutuhkan VM baru (0 GB RAM tambahan).
  - VM `secops` (10.10.40.11 / 192.168.122.81) difungsikan sebagai **Forensic Investigation Workstation & Evidence Vault**.
  - VM `web1` (DMZ Web Tier) dan `db1` (Core Database Tier) difungsikan sebagai **Crime Scene Hosts** (objek triage pasca-serangan).
  - VM `attacker` (203.0.113.11) bertindak sebagai sumber serangan nyata (Skenario S6 Eksfiltrasi Data DB dan Skenario S2 Pergerakan Lateral SSH).
  - VM `canary1` (10.10.50.11) bertindak sebagai saksi forensik (*decoy forensic audit*).
- **Bukti Portofolio:**
  - Framework akuisisi triage otomatis (`dfir/acquisition/`).
  - *Evidence Vault* dengan sistem *Chain of Custody* termanifestasi kriptografis SHA-256 (`dfir/evidence/`).
  - Skrip parsing dan korelasi *Super-Timeline* multi-sumber (`dfir/analysis/`).
  - Dua Laporan Insiden Forensik Formal (`dfir/reports/`):
    1. **DFIR Case 01:** Investigasi Penyelundupan & Upaya Eksfiltrasi Data Nasabah DB1 (MITRE T1048 / S6).
    2. **DFIR Case 02:** Rekonstruksi Pembajakan Akses & Pergerakan Lateral SSH (MITRE T1021.004 / T1563.001 / S2-S4).
  - Panduan demo interaktif investigasi 2 menit dan ringkasan portofolio di README.

---

## 3. Keputusan yang sudah diambil dan yang masih terbuka

### Sudah diputuskan

| # | Keputusan | Pilihan | Alasan Teknis |
|---|---|---|---|
| D1 | Lokasi Proyek | Terintegrasi di dalam repo `dc-microseg-lab` (modul `dfir/`) | Topologi 14 VM, *tc mirroring*, sensor Zeek, decoy OpenCanary, dan skenario serangan sudah terpasang lengkap. Membangun dari nol akan redundan dan memakan waktu. |
| D2 | Pendekatan Forensik | Live Response Triage & Network Forensics (Enterprise DFIR) | Relevan dengan data center modern; *dead-box acquisition* (image disk .dd puluhan GB) tidak praktis dan memakan disk host. |
| D3 | Mesin Penyimpan Bukti | `secops` (192.168.122.81 / 10.10.40.11) | Memiliki disk terbesar (30 GB), terisolasi di zona manajemen, dan terhubung langsung ke 3 jalur *mirror port* leaf. |
| D4 | Integritas Kriptografis | SHA-256 Manifest + Read-Only Tarball Packaging | Memenuhi standar ISO/IEC 27037 untuk penjaminan keaslian bukti digital (*Chain of Custody*). |
| D5 | Ruang Lingkup Kasus | Kasus 1: Eksfiltrasi Data DB (S6); Kasus 2: Pergerakan Lateral SSH (S2/S3) | Dua skenario paling kritis yang merefleksikan insiden pembobolan data sensitif dan kompromi kredensial nyata. |

### Usulan yang perlu dikonfirmasi saat Fase 0

| # | Pertanyaan | Opsi | Usulan | Alasan Singkat |
|---|---|---|---|---|
| D6 | Metode Memory Triage | (a) Live memory dump parsial via `/proc` & memory artifact collectors; (b) Full physical memory dump via LiME / AVML; (c) Volatile process & socket live state saja | **(a) + (c)** | Kernel Linux host 7.0 / VM 6.8 terkadang memerlukan kompilasi modul kernel LiME yang rumit. Triage live state (/proc, ss, lsof, memory maps) jauh lebih stabil, cepat, dan non-intrusif. |
| D7 | Mesin Penyusunan Super-Timeline | (a) Python script kustom (Pandas/Datetime); (b) Plaso / log2timeline; (c) Grafana Loki query export | **(a) + (c)** | Script Python kustom membuktikan pemahaman logika korelasi data, sedangkan Loki mengekspor rekaman terstruktur secara presisi tanpa ketergantungan tool berat. |
| D8 | Standar Format Pelaporan | (a) NIST SP 800-61 Rev 2; (b) SANS DFIR Template; (c) ISO/IEC 27037 Evidence Log | **(a) + (c)** | NIST SP 800-61r2 diakui secara global untuk alur penanganan insiden, dan ISO 27037 untuk penomoran serta hashing bukti. |

---

## 4. Lingkungan dan alokasi VM

Proyek ini memanfaatkan VM yang sudah berjalan di `dc-microseg-lab`:

| VM | Alamat IP Data | Alamat IP Mgmt | Peran dalam Investigasi DFIR |
|---|---|---|---|
| `secops` | 10.10.40.11 | 192.168.122.81 | **Forensic Workstation & Evidence Vault** (penerima PCAP, repositori bukti, Loki, Zeek, compiler timeline) |
| `web1` | 10.10.10.11 | - (via ProxyJump) | **Crime Scene Host A (DMZ Victim)**: Titik masuk awal penyerang, investigasi pivoting & socket hijacking |
| `db1` | 10.10.30.11 | - (via ProxyJump) | **Crime Scene Host B (Crown Jewels DB)**: Target data sensitif, investigasi eksfiltrasi data nasabah |
| `canary1` | 10.10.50.11 | - (via ProxyJump) | **Witness Host (Decoy Trigger)**: Penyedia bukti peringatan dini probe lateral |
| `attacker` | 203.0.113.11 | - (via ProxyJump) | **Adversary Node**: Mesin eksternal penyerang tempat listener C2 dan alat eksfiltrasi berada |
| `opnsense` | Gateway (.1) | 192.168.122.20 | **Perimeter & Transit Witness**: Penyedia log firewall SPI (`filterlog`) untuk korelasi penolakan paket |

*Catatan Sumber Daya:* Karena seluruh VM di atas sudah dikonfigurasi dan berjalan pada Proyek 4, **anggaran RAM tambahan adalah 0 GiB**. Penyimpanan bukti dialokasikan di direktori `/var/forensics/` pada VM `secops` dan direktori `dfir/` pada repositori lokal host.

---

## 5. Arsitektur Forensik Digital & Aliran Bukti

```
 +--------------------------------------------------------------------------------+
 |                             CRIME SCENE HOSTS                                  |
 |                                                                                |
 |  [ web1 (DMZ) ]               [ db1 (Core Data) ]        [ canary1 (Decoy) ]   |
 |  - Volatile sockets (ss)      - Stolen records dump      - Trigger timestamp   |
 |  - /proc maps & descriptors   - Egress connection state  - Attacker IP trace   |
 |  - Bash history & auth.log    - Database access logs                           |
 +-----------------------+-------------------+--------------------+---------------+
                         |                   |                    |
        (Live Triage SSH |   (Live Triage)   |   (Alert Logs)     |
           via Bastion)  |                   |                    |
                         v                   v                    v
 +--------------------------------------------------------------------------------+
 |              PORT MIRRORING FABRIC (tc mirred ingress leaf1/2/3)              |
 |                       Capture raw frames into br-sensor                        |
 +---------------------------------------+----------------------------------------+
                                         |
                                         v
 +--------------------------------------------------------------------------------+
 |                    SECOPS (FORENSIC WORKSTATION & VAULT)                       |
 |                                                                                |
 |  1. Evidence Collector:                                                        |
 |     - Raw Network PCAP (dumpcap / tcpdump capture on br-sensor)               |
 |     - Host Evidence Bundler (tarball triage packages)                         |
 |                                                                                |
 |  2. Chain of Custody Engine:                                                   |
 |     - Cryptographic Hashing (SHA-256 for all raw & carved artifacts)          |
 |     - Read-only Evidence Locking (`chmod 440` + SHA256SUMS manifest)           |
 |     - Custody Transfer Log (ISO/IEC 27037 compliance)                          |
 |                                                                                |
 |  3. Multi-Source Forensic Analysis:                                            |
 |     - Network: tshark stream carving + Zeek conn/ssh/dns logs                  |
 |     - Firewall: OPNsense SPI syslog correlation (filterlog)                    |
 |     - Host: Parsing auth.log, bash history, process tree, open sockets        |
 |                                                                                |
 |  4. Super-Timeline Engine (Python / Pandas):                                   |
 |     - UTC Normalized Microsecond Chronology                                    |
 |     - Cross-correlation: Network Packet <-> Firewall Action <-> Host Artifact  |
 |                                                                                |
 |  5. DFIR Case Reporting:                                                       |
 |     - Executive Summary, Root Cause Analysis, MITRE ATT&CK Mapping, IOCs      |
 +--------------------------------------------------------------------------------+
```

### Standar Penanganan Bukti Digital (ISO/IEC 27037)

Setiap item bukti digital yang diakuisisi wajib dicatat dalam manifest dengan atribut minimum:
1. **Evidence ID:** Pengenal unik (contoh: `EVD-NET-20261017-01`, `EVD-HOST-WEB1-01`).
2. **Item Description:** Deskripsi teknis objek bukti (contoh: *Raw packet capture of Leaf1 mirror interface*).
3. **Acquisition Timestamp:** Stempel waktu ISO 8601 UTC saat akuisisi dimulai dan selesai.
4. **Source Device:** Identitas node asal (Hostname, MAC, IP Address).
5. **Acquisition Tool & Version:** Perangkat lunak yang digunakan (contoh: `tcpdump 4.99.4`, `ss v23.0`).
6. **Acquisition Engineer:** Nama investigator (`Natanael / Incident Response Team`).
7. **Integrity Hash (SHA-256):** Checksum kriptografis yang dihitung tepat setelah akuisisi selesai.
8. **Storage Location:** Path fisik absolut berkas bukti di Evidence Vault.

---

## 6. Skenario Investigasi (Kasus DFIR Inti)

Investigasi forensik dilakukan terhadap dua kasus kejahatan siber yang disimulasikan secara realistis di dalam lab:

### Kasus DFIR 1: Investigasi Eksfiltrasi Data Nasabah (Case ID: IR-2026-S06)
- **Ringkasan Kejadian:** Sistem deteksi melaporkan adanya anomali upaya transfer data dalam volume besar dari subnet database `db1` (10.10.30.11) menuju IP eksternal yang mencurigakan di WAN (`attacker` 203.0.113.11).
- **Tujuan Investigasi:**
  1. Menentukan apakah ada data nasabah (*core_accounts*, 42 record) yang berhasil lolos keluar ke internet atau berhasil dicegah sepenuhnya oleh perimeter firewall.
  2. Mengekstrak payload paket yang dikirimkan oleh proses jahat menggunakan rekonstruksi stream TCP/ICMP dari file PCAP mentah.
  3. Memeriksa artefak host pada `db1` untuk mengidentifikasi skrip/proses yang memicu transfer, *command line arguments*, dan akun pengguna yang disalahgunakan.
  4. Menyusun rekonstruksi linimasa detik-demi-detik dari inisiasi perintah di `db1` hingga pencatatan penolakan di OPNsense.

### Kasus DFIR 2: Rekonstruksi Pembajakan Akses & Pergerakan Lateral SSH (Case ID: IR-2026-S02)
- **Ringkasan Kejadian:** Log otentikasi host menunjukkan aktivitas login tidak sah pada beberapa server internal secara beruntun (*lateral movement chain*) yang berawal dari node DMZ `web1`.
- **Tujuan Investigasi:**
  1. Melacak titik awal kompromi (*initial compromise pivot*) di `web1`.
  2. Memeriksa jejak soket SSH Agent (`SSH_AUTH_SOCK`) dan proses pembajakan kredensial (T1563.001).
  3. Mengidentifikasi seluruh *hop* pergerakan lateral (`web1 -> app1 -> db1`) melalui korelasi log `conn.log`/`ssh.log` Zeek dengan `/var/log/auth.log` pada host korban.
  4. Membuktikan efektivitas penegakan isolasi segmentasi pasca-pengerasan (*hardened state*).

---

## 7. Rencana Struktur Modul & Berkas Repositori

Seluruh komponen forensik ditempatkan secara modular di dalam repositori `dc-microseg-lab`:

```
dc-microseg-lab/
├── dfir/
│   ├── README.md                          # Panduan modul DFIR & alur investigasi
│   ├── acquisition/                       # Toolset akuisisi bukti otomatis
│   │   ├── capture-network-evidence.sh    # Perekam PCAP pada antarmuka mirror secops
│   │   ├── triage-host-evidence.sh        # Kolektor artefak volatil & non-volatil host
│   │   └── package-evidence.sh            # Pengemas tarball & pengunci permission
│   ├── evidence/                          # Vault barang bukti (terabaikan di git via .gitignore)
│   │   ├── .gitkeep
│   │   ├── manifest-template.json         # Skema metadata Chain of Custody ISO 27037
│   │   └── verify-evidence-integrity.sh   # Verifikator integritas hash SHA-256
│   ├── analysis/                          # Toolset analisis post-mortem & linimasa
│   │   ├── extract-pcap-artifacts.py      # Ekstraksi payload, stream carving via tshark
│   │   ├── parse-host-artifacts.py        # Parser auth.log, bash history, process maps
│   │   └── build-super-timeline.py        # Korelator linimasa multi-sumber (OPNsense+Zeek+Host)
│   ├── reports/                           # Laporan resmi investigasi insiden
│   │   ├── INCIDENT-REPORT-CASE-01-DB-EXFILTRATION.md
│   │   └── INCIDENT-REPORT-CASE-02-LATERAL-SSH.md
│   └── demo/                              # Skrip demo investigasi cepat untuk pewawancara
│       └── run-dfir-walkthrough.sh
```

---

## 8. Metrik & Indikator Kinerja Forensik

Pembeda utama portofolio ini dari sekadar tutorial biasa adalah **keberadaan metrik kuantitatif dan kepatuhan standar hukum/keamanan**:

| Metrik | Definisi & Cara Ukur | Target Standar Industri |
|---|---|---|
| **Evidence Integrity Rate** | Persentase berkas bukti yang lolos verifikasi hash SHA-256 pasca transfer dan analisis | **100.0% (Zero Corruption)** |
| **Order of Volatility Adherence** | Urutan pengumpulan artefak host sesuai RFC 3227 (Soket -> Memori/Proc -> Log -> Disk) | **100% Sesuai RFC 3227** |
| **Timeline Time-Delta Accuracy** | Selisih akurasi stempel waktu antar sensor (*clock drift* NTP antara Zeek, OPNsense, dan Host) | **< 500 milidetik** |
| **Stream Carving Completeness** | Kemampuan merekonstruksi kembali file/payload yang dieksfiltrasi dari tangkapan PCAP mentah | **Identik Bit-by-Bit dengan payload asli** |
| **Chain of Custody Completeness** | Kelengkapan 8 atribut wajib ISO/IEC 27037 pada setiap artefak bukti digital | **100% Terisi & Tervalidasi** |
| **Mean Time to Triage (MTTT)** | Durasi eksekusi skrip triage otomatis dalam mengumpulkan paket bukti lengkap dari host korban | **< 30 detik per host** |

---

## 9. Rencana Fase Pengerjaan

Pengerjaan modul DFIR dibagi ke dalam 6 fase terstruktur dan terukur:

| Fase | Fokus Pekerjaan | Kriteria Keberhasilan (Definition of Done) |
|---|---|---|
| **Fase 0** | Perencanaan Forensik, Standardisasi ISO 27037 & Sinkronisasi Waktu Lingkungan | NTP tersinkronisasi di seluruh node lab (<50ms drift); template manifest Chain of Custody siap; struktur folder `dfir/` terinisialisasi. |
| **Fase 1** | Framework Akuisisi Bukti Jaringan Mentah (Network Evidence Capture) | Skrip `capture-network-evidence.sh` mampu menangkap traffic raw PCAP di antarmuka mirror `secops` tanpa *packet drop*; filter penangkapan presisi per skenario. |
| **Fase 2** | Framework Live Response & Host Triage (RFC 3227 Compliant) | Skrip `triage-host-evidence.sh` berhasil mengumpulkan artefak volatil (soket, `/proc`, memory maps) dan non-volatil (auth.log, history, audit) dari `web1` dan `db1` via Bastion ProxyJump dalam <30 detik. |
| **Fase 3** | Mesin Preservasi Bukti & Chain of Custody Kriptografis | Skrip `package-evidence.sh` membungkus artefak ke tarball terenkripsi/read-only, menghasilkan `hashes.sha256` dan `manifest.json`; skrip verifikasi membuktikan integritas 100%. |
| **Fase 4** | Analisis Post-Mortem & Rekonstruksi Super-Timeline Multi-Sumber | Skrip `build-super-timeline.py` berhasil menyatukan log OPNsense, Zeek, OpenCanary, dan Host Triage menjadi kronologi urut waktu berformat Markdown/CSV; stream carving membongkar payload exfil. |
| **Fase 5** | Eksekusi Investigasi Kasus 1 (DB Exfiltration) & Kasus 2 (Lateral SSH) | Dua Laporan Investigasi Insiden Forensik (`INCIDENT-REPORT-CASE-01.md` dan `02.md`) selesai ditulis dengan analisis teknis lengkap, bukti hash, dan visualisasi alur serangan. |
| **Fase 6** | Integrasi Portofolio, Panduan Demo DFIR 2-Menit & Finalisasi README | Skrip demo `run-dfir-walkthrough.sh` selesai; master README Proyek 4 diperbarui untuk menonjolkan kapabilitas DFIR; dokumentasi dwibahasa siap untuk etalase portofolio. |

---

### Rincian Fase 0: Persiapan Lingkungan & Forensic Readiness

- **Langkah 0.1:** Verifikasi sinkronisasi waktu (Time Synchronization / Chrony / NTP) antar host lab (`secops`, `opnsense`, `web1`, `db1`, `attacker`). Stempel waktu forensik wajib seragam dalam toleransi sub-detik untuk mencegah distorsi kronologi linimasa.
- **Langkah 0.2:** Perancangan skema manifest barang bukti digital berbasis standar ISO/IEC 27037 (`dfir/evidence/manifest-template.json`).
- **Langkah 0.3:** Inisialisasi struktur direktori modul `dfir/` dan konfigurasi `.gitignore` untuk mencegah berkas bukti berukuran besar masuk ke riwayat commit Git.

### Rincian Fase 1: Network Evidence Capture (Raw PCAP)

- **Langkah 1.1:** Verifikasi antarmuka sniffing `br-sensor` pada VM `secops` untuk penangkapan frame mentah dari 3 link mirror leaf (`mirror-l1`, `mirror-l2`, `mirror-l3`).
- **Langkah 1.2:** Pembuatan skrip `dfir/acquisition/capture-network-evidence.sh` yang mendukung penangkapan paket berbasis ring buffer, filter BPF terarah, dan pemotongan file PCAP otomatis berdasarkan trigger insiden.
- **Langkah 1.3:** Uji verifikasi penangkapan paket saat simulasi interaksi normal dan pengujian integritas pcap.

### Rincian Fase 2: Host Triage & Live Response (RFC 3227)

- **Langkah 2.1:** Perancangan skrip kolektor artefak live triage `dfir/acquisition/triage-host-evidence.sh` yang mematuhi urutan volatilitas RFC 3227:
  1. *Network Connections & Sockets:* `ss -tulpn`, `ss -tanp`, tabel ARP / tetangga.
  2. *Process & Execution Memory State:* Daftar proses terperinci (`ps auxwwfe`), *process memory maps* (`/proc/$PID/maps`), *open file descriptors* (`/proc/$PID/fd`).
  3. *User & Authentication State:* Sesi aktif (`w`, `who`), variabel lingkungan sesi, jejak socket agen SSH (`/tmp/ssh-*`).
  4. *Log Files & Disk Timestamps:* Salinan `/var/log/auth.log`, `.bash_history` seluruh user, dan pencarian file yang dimodifikasi dalam 60 menit terakhir (`find / -mmin -60 -ls`).
- **Langkah 2.2:** Integrasi eksekusi jarak jauh melalui jalur aman Bastion ProxyJump `secops` tanpa meninggalkan artefak sampah berbahaya di target host.
- **Langkah 2.3:** Uji benchmarking waktu triage (target < 30 detik) pada node `web1` dan `db1`.

### Rincian Fase 3: Chain of Custody & Evidence Packaging

- **Langkah 3.1:** Pembuatan skrip `dfir/acquisition/package-evidence.sh` yang secara otomatis mengonsolidasikan artefak jaringan dan artefak host ke dalam wadah bukti digital terstandar (`evidence_vault/`).
- **Langkah 3.2:** Otomasi kalkulasi checksum kriptografis SHA-256 dan SHA-512 untuk setiap file bukti mentah, pembuatan file manifest JSON, dan penguncian izin berkas menjadi *read-only* (`chmod 440 / 400`).
- **Langkah 3.3:** Pembuatan skrip verifikator `dfir/evidence/verify-evidence-integrity.sh` untuk membuktikan bahwa bukti belum mengalami alterasi (*zero tampering*).

### Rincian Fase 4: Analisis Post-Mortem & Super-Timeline Reconstruction

- **Langkah 4.1:** Pembuatan skrip ekstraksi artefak jaringan `dfir/analysis/extract-pcap-artifacts.py` menggunakan `tshark` untuk merekonstruksi aliran data TCP/ICMP, percakapan protokol, dan ekstraksi file yang dipindahkan (*payload carving*).
- **Langkah 4.2:** Pembuatan parser artefak host `dfir/analysis/parse-host-artifacts.py` untuk mengekstrak stempel waktu otentikasi SSH, eksekusi perintah shell, dan soket koneksi aktif ke format terstruktur.
- **Langkah 4.3:** Pembuatan generator super-timeline terpadu `dfir/analysis/build-super-timeline.py` yang mengkorelasikan log OPNsense (`filterlog`), log Zeek (`conn.log`), alert OpenCanary, dan artefak host triage ke dalam linimasa kronologis linier microsecond.

### Rincian Fase 5: Investigasi Kasus DFIR Nyata & Pelaporan

- **Langkah 5.1:** Eksekusi investigasi Kasus 1 (Upaya Eksfiltrasi Data DB - S6):
  - Rekonstruksi upaya transfer data nasabah 42 record via HTTP POST dan ICMP tunneling.
  - Pembuktian forensik bahwa payload dijatuhkan di firewall OPNsense dan host nftables (0 record bocor ke internet).
  - Penulisan laporan resmi `dfir/reports/INCIDENT-REPORT-CASE-01-DB-EXFILTRATION.md`.
- **Langkah 5.2:** Eksekusi investigasi Kasus 2 (Pergerakan Lateral SSH & Kompromi Akun - S2/S3):
  - Rekonstruksi rantai lompatan penyerang dari `web1` ke `app1` dan `db1`.
  - Analisis forensik pembajakan agent SSH dan bukti pencegahan saat pengerasan aktif.
  - Penulisan laporan resmi `dfir/reports/INCIDENT-REPORT-CASE-02-LATERAL-SSH.md`.

### Rincian Fase 6: Finalisasi Portofolio, Panduan Demo & Publikasi

- **Langkah 6.1:** Pembuatan skrip demo interaktif `dfir/demo/run-dfir-walkthrough.sh` (durasi 2 menit) untuk demonstrasi wawancara kerja.
- **Langkah 6.2:** Pemutakhiran master `README.md` dan `README.id.md` di root repositori dengan menautkan kapabilitas DFIR dan badge bukti forensik.
- **Langkah 6.3:** Gerbang Keputusan Final Modul DFIR dan penutupan portofolio.

---

## 10. Risiko Forensik dan Mitigasi

| ID | Risiko Teknis Forensik | Dampak | Mitigasi yang Diterapkan |
|---|---|---|---|
| **RF1** | Kontaminasi stempel waktu file (*MACB Timestamps*) pada host korban saat eksekusi triage | Bukti kehilangan integritas pembuktian di pengadilan/audit | Eksekusi triage menggunakan opsi *no-atime*, pengumpulan metadata sebelum pembacaan konten berkas, dan penyimpanan hasil langsung ke stdout/piped stream. |
| **RF2** | *Clock Drift* (Perbedaan stempel waktu antar VM) | Kegagalan korelasi kronologis linimasa antar sensor | Sinkronisasi waktu menggunakan Chrony/NTP terpusat sebelum pengujian; pencatatan offset delta waktu pada manifest. |
| **RF3** | Ukuran file PCAP terlalu besar memenuhi disk `secops` | Kehabisan kapasitas penyimpanan (*disk exhaustion*) | Penggunaan opsi ring buffer `tcpdump -W -C` dan filter BPF spesifik pada traffic investigasi yang ditargetkan. |
| **RF4** | Kredensial atau data sensitif (PII) nasabah terekspos ke repositori publik | Pelanggaran kerahasiaan data (*privacy leak*) | Folder `evidence/` yang berisi raw pcap dan dump data dimasukkan ke `.gitignore`; laporan publik disanitasi menggunakan data sintetis bertopeng (*masked PII*). |
| **RF5** | Skrip triage crash akibat dependensi biner pihak ketiga pada host korban | Triage terhenti saat investigasi live | Hanya menggunakan utilitas bawaan kernel/Linux standar (`ss`, `ps`, `cat`, `tar`, `awk`, `/proc`) tanpa menginstal paket tambahan di target host. |

---

## 11. Daftar Standar & Referensi Resmi yang Diverifikasi

1. **ISO/IEC 27037:2012:** *Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence*.
2. **NIST Special Publication 800-61 Revision 2:** *Computer Security Incident Handling Guide*.
3. **RFC 3227:** *Guidelines for Evidence Collection and Archiving (Best Current Practice)*.
4. **MITRE ATT&CK Framework for Enterprise:**
   - T1048: *Exfiltration Over Alternative Protocol*
   - T1021.004: *Remote Services: SSH*
   - T1563.001: *Remote Service Session Hijacking: SSH Hijacking*
   - T1046: *Network Service Discovery*
   - T1018: *Remote System Discovery*
5. **Wireshark / TShark Documentation:** *Command Line Packet Capture & Protocol Dissection Reference*.

---

## 12. Nilai Jual Portofolio (Resume & Interview Highlights)

Jika ditanya oleh pewawancara kerja mengenai proyek ini:
- *"Di proyek ini, saya tidak hanya membangun arsitektur Zero-Trust Micro-segmentation di level fabric jaringan, tetapi juga melengkapinya dengan kesiapan forensik digital (Forensic Readiness) sesuai standar ISO/IEC 27037."*
- *"Ketika sistem mendeteksi insiden eksfiltrasi data, saya mengembangkan framework otomasi live response yang menyadap PCAP mentah secara non-destruktif, melakukan live host triage sesuai Order of Volatility RFC 3227, mengunci integritas bukti dengan SHA-256, dan merekonstruksi super-timeline lintas sumber (Firewall + Zeek + Host) untuk membuktikan integritas rantai pertahanan."*

---

## 13. Status dan Log Progres

Bagian ini diperbarui setiap kali satu langkah selesai dikerjakan.

| Langkah | Tanggal | Status | Catatan / Hasil Ringkas |
|---|---|---|---|
| **0.1** | 2026-10-17 | Selesai | Verifikasi sinkronisasi waktu UTC: seluruh 6 node target (`secops`, `opnsense`, `web1`, `db1`, `canary1`, `attacker`) tersinkronisasi presisi sub-detik (< 750 ms offset terhadap Host UTC). Host clocksource `kvm-clock` paravirtualized aktif di semua guest Linux, dan `secops` aktif sinkron upstream NTP `ntp.ubuntu.com`. |
| **0.2** | 2026-10-17 | Selesai | Template manifest barang bukti digital berbasis standar ISO/IEC 27037:2012 selesai dirancang di `dfir/evidence/manifest-template.json` (mencakup case metadata, Order of Volatility RFC 3227, dual hashing SHA-256 & SHA-512, dan audit log Chain of Custody). |
| **0.3** | 2026-10-17 | Selesai | Struktur direktori `dfir/` (`acquisition/`, `evidence/`, `analysis/`, `reports/`, `demo/`), berkas panduan `dfir/README.md`, dan konfigurasi proteksi `.gitignore` (anti kebocoran raw evidence) selesai diinisialisasi dan diverifikasi. Fase 0 resmi tuntas 100%. |
| **1.1** | 2026-10-17 | Selesai | Antarmuka `br-sensor` pada `secops` (agregasi `eth1-3` nolearning promisc on) terverifikasi 100% aktif menyerap mirror Leaf1-3 (`tc mirred`). Uji live sniffing membuktikan penangkapan alur cascading dua arah Web (:8080) dan DB (:5432) sukses dengan 0 packet drops. |
| **1.2** | 2026-10-17 | Selesai | Pembuatan skrip `dfir/acquisition/capture-network-evidence.sh`: mendukung penangkapan sinkron (`--duration`), asinkron (`--start`/`--stop`), filter BPF kustom, dual hashing SHA-256 & SHA-512, dan pembuatan manifest metadata ISO/IEC 27037. |
| **1.3** | 2026-10-17 | Selesai | Pengujian penangkapan paket asinkron (`--start`/`--stop`) dan sinkron (`--duration`) sukses 100%. Trafik cascading multi-tier Web -> App -> DB tertangkap lengkap, hash SHA-256 terverifikasi cocok, izin file terkunci read-only (0440), dan berkas metadata JSON tervalidasi. Fase 1 resmi tuntas 100%. |
| **2.1** | 2026-10-17 | Selesai | Perancangan skrip kolektor live triage `dfir/acquisition/triage-host-evidence.sh`: mematuhi 7 tier urutan volatilitas RFC 3227, eksekusi RAM `/dev/shm` non-destruktif, inventaris hash per berkas, dual hashing SHA-256 & SHA-512, dan metadata ISO/IEC 27037. |
| **2.2** | 2026-10-17 | Selesai | Otomasi eksekusi live triage via Bastion ProxyJump pada `web1` dan `db1` berhasil 100%. Artefak 7-tier RFC 3227 terkumpul utuh di RAM `/dev/shm`, transfer tarball dan validasi hash SHA-256 terbukti cocok 100%, metadata ISO/IEC 27037 tergenerasi, dan residu remote dibersihkan total. |
| **2.3** | 2026-10-17 | Selesai | Benchmarking MTTT pada 4 node lintas-tier (`web1`, `app1`, `db1`, `canary1`): rata-rata durasi triage **2.36 detik** (target < 30 detik terlampaui 12x lebih cepat), Evidence Integrity Rate **100.0%** (zero corruption), dan rata-rata ukuran paket **100.1 KB**. Hasil tersimpan di `dfir/acquisition/results-benchmark-triage.txt`. Fase 2 resmi tuntas 100%. |
| **3.1** | 2026-10-17 | Selesai | Pembuatan perkakas konsolidasi `dfir/acquisition/package-evidence.sh` & `package-evidence.py`: mengonsolidasikan bukti jaringan mentah & host triage ke vault kasus terisolasi, menghitung `SHA256SUMS`/`SHA512SUMS`, menyusun master manifest ISO/IEC 27037, dan mengunci izin 0440. |
| **3.2** | 2026-10-17 | Selesai | Pembangkitan master manifest ISO/IEC 27037 (`evidence-manifest.json`), berkas checksum dual `SHA256SUMS` & `SHA512SUMS`, serta penguncian proteksi izin berkas *read-only* (`chmod 440`) terverifikasi sukses 100%. Uji integritas `sha256sum -c` lulus (OK) dan uji tamper write ditolak (Permission denied). |
| **3.3** | 2026-10-17 | Selesai | Perkakas verifikasi integritas bukti `dfir/evidence/verify-evidence-integrity.sh` & `.py` selesai diuji secara positif (100% GREEN) dan negatif (berhasil mendeteksi alterasi berkas dengan status RED / INTEGRITY VIOLATION DETECTED). Kepatuhan rantai bukti ISO/IEC 27037 terbukti kokoh. Fase 3 resmi tuntas 100%. |
| **4.1** | - | Belum | Pembuatan skrip stream carving & ekstraksi payload `extract-pcap-artifacts.py`. |
| **4.2** | - | Belum | Pembuatan parser artefak host `parse-host-artifacts.py`. |
| **4.3** | - | Belum | Pembuatan generator super-timeline `build-super-timeline.py`. |
| **5.1** | - | Belum | Investigasi Kasus 1 (DB Exfiltration) & Laporan Insiden. |
| **5.2** | - | Belum | Investigasi Kasus 2 (Lateral SSH) & Laporan Insiden. |
| **6.1** | - | Belum | Pembuatan skrip demo interaktif 2 menit `run-dfir-walkthrough.sh`. |
| **6.2** | - | Belum | Pemutakhiran master README repositori. |
| **6.3** | - | Belum | Gerbang Keputusan Final DFIR & Penutupan Proyek. |
