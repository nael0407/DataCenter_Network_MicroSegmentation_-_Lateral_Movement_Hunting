# Panduan Demo Wawancara DFIR 2 Menit & Naskah Presentasi Teknis

> **Proyek:** Data Center Zero-Trust Micro-segmentation & Digital Forensics (DFIR) Module  
> **Target Audiens:** Hiring Manager, Lead DFIR / SecOps Engineer, Cybersecurity Architect, SOC Manager  
> **Durasi:** 2 Menit (120 Detik)  
> **Skrip Otomasi Demo:** [`dfir/demo/run-dfir-walkthrough.sh`](../dfir/demo/run-dfir-walkthrough.sh)  
> **Standar Rujukan:** ISO/IEC 27037:2012, RFC 3227, NIST SP 800-61 Rev 2  

---

## 1. Elevator Pitch DFIR (Ringkasan Pembuka 30 Detik)

> *"Dalam proyek ini, saya merancang dan mengeksekusi kapabilitas **Digital Forensics and Incident Response (DFIR)** terotomasi di atas arsitektur data center Zero-Trust 14 virtual machine.*
>
> *Ketika insiden eksfiltrasi data dan pergerakan lateral terjadi, kami tidak sekadar mengandalkan pencegahan perimeter, melainkan membangun rantai pembuktian forensik yang memenuhi standar internasional **ISO/IEC 27037:2012**.*
>
> *Dengan framework live response yang saya kembangkan, kami mencapai **Mean Time to Triage (MTTT) rata-rata 2.36 detik** (12x lebih cepat dari standar industri < 30 detik) tanpa meninggalkan residu di disk korban (RAM `/dev/shm`), mengamankan bukti dengan dual hashing SHA-256 dan SHA-512, serta merekonstruksi **Super-Timeline linier mikrodetik** lintas 5 sumber heterogen. Hasilnya, kami membuktikan secara forensik di tingkat kernel bahwa **0 record nasabah berhasil dicuri penyerang**."*

---

## 2. Naskah Narasi Lengkap Demo 2 Menit (Sinkron dengan `run-dfir-walkthrough.sh`)

Jalankan perintah berikut di terminal:
```bash
./dfir/demo/run-dfir-walkthrough.sh
```
*(Gunakan opsi `--non-interactive` atau `-y` untuk eksekusi otomatis tanpa jeda).*

---

### [00:00 - 00:30] Babak 1: Kesiapan Forensik (Forensic Readiness) & Audit Waktu
**Aksi pada Layar:**
Skrip memverifikasi antarmuka sniffing pasif `br-sensor` pada node `secops` (agregasi mirror port Leaf1-3) dan melakukan audit sinkronisasi waktu UTC lintas 6 VM target.

**Naskah yang Diucapkan:**
> *"Di babak pertama, kita memastikan kesiapan forensik data center sebelum terjadinya insiden (Forensic Readiness ISO 27037). Seluruh trafik fabric jaringan tercermin secara transparan ke sensor jembatan `br-sensor` di secops tanpa membebani throughput produksi.*
>
> *Selain itu, kami mengaudit sinkronisasi waktu seluruh VM. Korelasi forensik mustahil valid jika ada clock drift. Di sini terbukti seluruh node memiliki delta waktu sub-detik (< 1 detik) terhadap clock acuan UTC, menjamin kronologi lintas sensor tersinkronisasi presisi."*

---

### [00:30 - 01:00] Babak 2: Insiden Eksfiltrasi Data & Live Response RFC 3227 Kilat
**Aksi pada Layar:**
Penyerang mengeksekusi script eksfiltrasi 42 record nasabah dari `db1` ke C2 WAN. Koneksi dijatuhkan seketika oleh kernel `nftables`. Framework live response langsung mengeksekusi pengumpulan artefak 7-tier RFC 3227 di RAM `/dev/shm`.

**Naskah yang Diucapkan:**
> *"Di babak kedua, penyerang mencoba mengeksfiltrasi 42 record data perbankan rahasia dari node basis data inti `db1` ke server C2 di internet. Respon kernel seketika memblokir transfer.*
>
> *Secara simultan, sistem DFIR meluncurkan live host triage sesuai Order of Volatility RFC 3227: soket jaringan, memori proses, sesi user, auth log, dan riwayat bash diekstraksi ke direktori RAM `/dev/shm`. Proses triage tuntas hanya dalam **0.62 detik** dengan **0 byte modifikasi disk**, menjaga MACB timestamp berkas korban tetap murni untuk kebutuhan audit hukum."*

---

### [01:00 - 01:30] Babak 3: Preservasi Evidence Vault & Audit Anti-Tamper
**Aksi pada Layar:**
Skrip menginspeksi wadah bukti digital `vault_ir_2026_s06`, memverifikasi checksum SHA-256 dan SHA-512, serta melakukan simulasi alterasi berkas yang ditolak oleh izin `0440` (*Permission Denied*).

**Naskah yang Diucapkan:**
> *"Di babak ketiga, kita membuktikan integritas rantai bukti digital (Chain of Custody). Seluruh bukti mentah—baik PCAP jaringan maupun tarball triage host—dikonsolidasikan ke dalam Evidence Vault terisolasi.*
>
> *Setiap berkas diaudit dengan dual-hashing SHA-256 dan SHA-512 dan dikunci dengan hak akses read-only 0440. Kami menguji simulasi serangan tamper: upaya modifikasi berkas ditolak mentah-mentah oleh sistem operasi dengan error Permission Denied. Tingkat integritas bukti mencapai 100% GREEN."*

---

### [01:30 - 02:00] Babak 4: Rekonstruksi Super-Timeline Multi-Sumber & Pembuktian Zero Leak
**Aksi pada Layar:**
Skrip mengorelasikan log lintas 5 sumber (PCAP + Host Triage + OPNsense filterlog + Zeek NSM + OpenCanary Honeypot) menjadi linimasa kronologis linier microsecond, menautkan dua laporan insiden resmi di folder `dfir/reports/`.

**Naskah yang Diucapkan:**
> *"Di babak terakhir, mesin Super-Timeline kami menyatukan lima sumber bukti digital heterogen ke dalam kronologi linier mikrodetik UTC ISO 8601.*
>
> *Dengan analisis stream carving dan audit rule counter nftables, kami merekonstruksi hubungan sebab-akibat secara definitif: perintah inisiasi di host `db1` dijatuhkan di stack kernel nftables sebelum sempat keluar dari antarmuka jaringan. Sisi penyerang mencatat 0 byte diterima.*
>
> *Kami telah menyusun laporan resmi NIST SP 800-61 Rev 2 untuk Kasus 1 (Eksfiltrasi Database) dan Kasus 2 (Pergerakan Lateral SSH). Ini membuktikan bahwa arsitektur kami tidak hanya tangguh bertahan, tetapi juga siap diaudit secara forensik di tingkat industri dan kepatuhan hukum."*

---

## 3. Pertanyaan Kunci Wawancara & Panduan Jawaban Teknis

### Q1: *"Mengapa live host triage dijalankan di `/dev/shm`?"*
> **Jawaban:** *"`/dev/shm` adalah implementasi RAM filesystem berbasis tmpfs di Linux. Dengan mengeksekusi skrip, mengekstrak artefak volatil (soket, proses, status memori), dan mengompresi tarball di dalam RAM, kami tidak menuliskan satu blok data pun ke hard drive korban (`/`). Hal ini mematuhi prinsip non-kontaminasi bukti digital ISO/IEC 27037 dan mencegah rusaknya MACB (Modified, Accessed, Changed, Birth) timestamp pada sistem berkas."*

### Q2: *"Bagaimana Anda menjamin keabsahan bukti digital di pengadilan (Chain of Custody)?"*
> **Jawaban:** *"Setiap artefak langsung dihitung nilai kriptografisnya menggunakan dual-hashing (SHA-256 dan SHA-512) tepat setelah selesai diekstraksi di target host. Nilai hash dicatat dalam manifest JSON terstandar ISO 27037 bersama metadata pengakuisisi, stempel waktu UTC, dan nomor kasus. Izin berkas segera dikunci menjadi `0440` (read-only). Perkakas `verify-evidence-integrity.py` kami memverifikasi kesesuaian bit-per-bit berkas terhadap manifest setiap kali bukti dipindahkan atau dianalisis."*

### Q3: *"Bagaimana Anda membuktikan bahwa 0 byte data nasabah yang bocor?"*
> **Jawaban:** *"Melalui korelasi tiga lapis bukti: (1) Di sisi jaringan, stream carving PCAP menunjukkan 0 frame HTTP payload yang berhasil ditransmisikan; (2) Di sisi firewall host `db1`, aturan `output policy drop` pada nftables mencatat pertambahan paket drop tepat pada detik percobaan transfer; dan (3) Di sisi penyerang di WAN, audit forensik pada listener C2 mengonfirmasi ketiadaan berkas log penerimaan (`NO_DATA_RECEIVED`). Ketiganya berkorelasi sempurna dalam Super-Timeline kami."*
