# Dokumentasi Forensik Digital (Fase 4): Analisis Post-Mortem & Rekonstruksi Super-Timeline Multi-Sumber

> **Standar Kepatuhan:** ISO/IEC 27037:2012, RFC 3227, NIST SP 800-61 Rev 2, MITRE ATT&CK Enterprise  
> **Modul Repositori:** [`dfir/analysis/`](../dfir/analysis/)  
> **Target Analisis:** Rekonstruksi Aliran PCAP, Live Triage 7-Tier RFC 3227, Korelasi Lintas Sumber (Firewall + Zeek + Honeypot + Host)

---

## 1. Arsitektur Analisis Post-Mortem & Engine Linimasa

Dalam investigasi insiden siber modern (*advanced persistent threats*), bukti digital terfragmentasi di berbagai lapisan infrastruktur:
1. **Lapisan Jaringan Mentah (Raw Packets):** Frame ethernet dan aliran TCP/UDP mentah dari mirror port Leaf spine-leaf fabric (`extract-pcap-artifacts.py`).
2. **Lapisan Host Korban (Endpoint Volatility):** Keadaan memori eksekusi, soket koneksi, sesi otentikasi SSH, riwayat shell pengguna, dan status berkas yang baru dimodifikasi (`parse-host-artifacts.py`).
3. **Lapisan Perimeter & Gateway (Firewall State):** Keputusan penegakan keamanan (*pass* vs *block*) oleh OPNsense filterlog.
4. **Lapisan Network Security Monitoring (Zeek NSM):** Metadata koneksi transaksional (`conn.log`, `ssh.log`, `notice.log`).
5. **Lapisan Deception (Honeypot Decoy):** Perangkap interaksi OpenCanary yang menangkap upaya penjelajahan lateral (*lateral reconnaissance*).

```
+----------------------------------------------------------------------------------------------------+
|                                    DFIR SUPER-TIMELINE ENGINE                                      |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [Raw PCAP Analysis]         [Host Triage RFC 3227]         [OPNsense Filterlog]  [Zeek & Canary]  |
|  extract-pcap-artifacts.py   parse-host-artifacts.py        (vtnet2 pass/block)   (conn & alerts)  |
|            |                           |                             |                    |        |
|            +---------------------------+-----------------------------+--------------------+        |
|                                        |                                                           |
|                                        v                                                           |
|                       +---------------------------------+                                          |
|                       |   Normalisasi Waktu UTC ISO8601 |                                          |
|                       |   (Presisi Sub-Mikrodetik)      |                                          |
|                       +---------------------------------+                                          |
|                                        |                                                           |
|                                        v                                                           |
|                       +---------------------------------+                                          |
|                       |  Cross-Source Correlator Engine |                                          |
|                       |  - Causal Link Analysis         |                                          |
|                       |  - MITRE ATT&CK Mapping         |                                          |
|                       +---------------------------------+                                          |
|                                        |                                                           |
|                    +-------------------+-------------------+                                       |
|                    |                                       |                                       |
|                    v                                       v                                       |
|        super-timeline.json                     super-timeline.csv                                  |
|        (SIEM / Graph Chronology)               (Spreadsheet / Court Ready)                         |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Rincian Modul Analisis Fase 4

### 2.1. Ekstraksi Artefak Jaringan & Stream Carving (`extract-pcap-artifacts.py`)
- **Lokasi Skrip:** [`dfir/analysis/extract-pcap-artifacts.py`](../dfir/analysis/extract-pcap-artifacts.py) | [`extract-pcap-artifacts.sh`](../dfir/analysis/extract-pcap-artifacts.sh)
- **Fungsi:**
  - Melakukan rekonstruksi aliran TCP dua arah (*bidirectional TCP reassembly*).
  - Melakukan diseksi mendalam pada protokol aplikasi:
    - **HTTP:** Ekstraksi method (`GET`, `POST`), URI, Host, Content-Type, Request body/payload, dan status response.
    - **ICMP:** Memeriksa panjang dan isi payload ICMP untuk mendeteksi *ICMP Tunneling / Data Exfiltration via Ping*.
    - **DNS:** Memeriksa pertanyaan DNS (QNAME, QTYPE) untuk mendeteksi teknik *DNS Tunneling* (subdomain berlabel panjang > 35 karakter).
    - **SSH:** Ekstraksi *banner exchange* versi perangkat lunak OpenSSH.
  - **Pencegahan Kebocoran Sensitif:** Memindai muatan dengan regex untuk menemukan kebocoran data perbankan (`core_accounts`, `nasabah`, `saldo`), query SQL, token JWT, dan kredensial.
  - **Carving Berkas Otomatis:** Menyimpan berkas/payload yang dipindahkan ke disk `carved_artifacts/` dan menghitung dual hash (SHA-256 dan SHA-512) sesuai ISO/IEC 27037.

#### Sintaks Penggunaan:
```bash
./dfir/analysis/extract-pcap-artifacts.sh \
  --pcap /path/to/evidence.pcap \
  --carve-files \
  --case-id IR-2026-S06 \
  --output-dir ./extracted_pcap/
```

---

### 2.2. Parser Artefak Host Triage RFC 3227 (`parse-host-artifacts.py`)
- **Lokasi Skrip:** [`dfir/analysis/parse-host-artifacts.py`](../dfir/analysis/parse-host-artifacts.py) | [`parse-host-artifacts.sh`](../dfir/analysis/parse-host-artifacts.sh)
- **Fungsi:**
  - Mendukung arsip `.tar.gz` (diekstrak ke RAM `/dev/shm` agar tidak mencemari disk target) maupun folder triage.
  - Membedah 7 Tier Urutan Volatilitas RFC 3227:
    - **Tier 1 (Soket):** Parsing `ss -tanpo` dan `ss -tulpn` untuk mengidentifikasi soket aktif yang terhubung ke IP penyerang di WAN (`203.0.113.11`).
    - **Tier 2 (Proses):** Parsing `ps auxwwfe` untuk mendeteksi *reverse shell*, netcat (`nc`), atau eksekusi proses dari direktori `/tmp`.
    - **Tier 3 (Berkas Terbuka):** Parsing `lsof` dan `/proc/$PID/fd`.
    - **Tier 4 (Sesi & SSH Agent):** Mendeteksi soket agen SSH di `/tmp/ssh-*` (*SSH Agent Hijacking* - T1563.001).
    - **Tier 5 (Otentikasi):** Parsing `auth.log` dan `journalctl_ssh`: melacak login SSH (`publickey` / `password`), *brute force*, dan eskalasi `sudo`.
    - **Tier 6 (Riwayat Perintah):** Mengurai riwayat perintah `.bash_history` (termasuk timestamp `#<epoch>`) dan crontab.
    - **Tier 7 (File Dimodifikasi):** Daftar berkas yang diubah dalam 60 menit terakhir (`find -mmin -60`).
  - **Pemetaan Otomatis MITRE ATT&CK:** Memberikan label taksonomi ancaman (misal `T1110`, `T1105`, `T1563.001`, `T1560`, `T1049`).

#### Sintaks Penggunaan:
```bash
./dfir/analysis/parse-host-artifacts.sh \
  --triage-tar /path/to/evd-host-web1.tar.gz \
  --case-id IR-2026-S02 \
  --output-dir ./parsed_host_web1/
```

---

### 2.3. Generator Super-Timeline Terpadu (`build-super-timeline.py`)
- **Lokasi Skrip:** [`dfir/analysis/build-super-timeline.py`](../dfir/analysis/build-super-timeline.py) | [`build-super-timeline.sh`](../dfir/analysis/build-super-timeline.sh)
- **Fungsi:**
  - Mengintegrasikan 5 sumber data secara simultan ke dalam linimasa kronologis linier berpresisi mikrodetik UTC ISO 8601.
  - **Cross-Source Causality Correlator:**
    - Mengkorelasikan inisiasi perintah di host (`curl -X POST ...`) dengan penampakan paket di jaringan (`HTTP POST`), pencatatan blokade di OPNsense (`vtnet2 block`), dan status koneksi di Zeek (`conn_state: S0`).
  - **Ekspor Ganda:**
    - `super-timeline.json`: Metadata lengkap untuk analisis SIEM, graph correlator, dan arsip kasus digital.
    - `super-timeline.csv`: Format spreadsheet untuk pelaporan investigasi formal.

#### Sintaks Penggunaan:
```bash
./dfir/analysis/build-super-timeline.sh \
  --case-id IR-2026-S06 \
  --pcap-report ./extracted_pcap/pcap-analysis-report.json \
  --host-report ./parsed_db1/host-analysis-report.json \
  --opnsense-log ./opnsense_filterlog.log \
  --zeek-log /var/log/zeek/conn.log \
  --canary-log /var/log/opencanary/opencanary.json \
  --output-dir ./super_timeline_s06/
```

---

## 3. Hasil Pengujian dan Bukti Validasi Empiris

### 3.1. Validasi Stream Carving Jaringan
Uji coba dilakukan terhadap berkas pcap simulasi eksfiltrasi:
- **Total Frame Dianalisis:** 5 frame (TCP, ICMP, DNS).
- **Temuan Kebocoran Data Sensitif:**
  - `HTTP_POST_BODY`: Berhasil mengidentifikasi kebocoran tabel `core_accounts` menuju WAN `203.0.113.11`.
  - `ICMP_PAYLOAD_EXFILTRATION`: Berhasil mendeteksi penyelundupan data nasabah dan token JWT di dalam payload ping.
  - `DNS_QUERY`: Berhasil mendeteksi query subdomain berentropi tinggi berukuran panjang (*DNS Exfiltration*).
- **Hasil Carving Bukti:**
  - Berkas `http_req_2_POST.txt` (134 bytes) ter-carve utuh dengan SHA-256 `c0f92050c0ebc436d2f37200d94613a74e7030bfda60c0eee807eb88f5b2b90a`.
  - Berkas `icmp_tunnel_1.bin` (61 bytes) ter-carve utuh dengan SHA-256 `18805b389a9842dc65b47d8a1d77c75cbaa968a99d0b1d28a6c1037bf7e9ba19`.

### 3.2. Validasi Host Triage Parser
Uji coba dilakukan pada arsip live triage `web1` dan skenario uji kompromi:
- **Live Triage `web1`:** Berhasil memetakan login SSH sah `dcadmin` via *publickey ED25519* pada port 22 beserta PID daemon `sshd`.
- **Skenario Kompromi:** Berhasil mendeteksi 9 indikator ancaman secara serentak (Brute Force SSH, unduhan malware via `curl` di sudo, pembajakan agen SSH via socket `/tmp/ssh-*`, listening backdoor netcat, dan upaya ekspor basis data via `pg_dump`).

### 3.3. Validasi Super-Timeline Engine
- Berhasil mengonsolidasi 72 event secara beruntun dari 5 sumber independen (PCAP, Host DB1, OPNsense Filterlog, Zeek NSM, dan OpenCanary).
- Berhasil membuktikan rantai kausalitas bahwa upaya transfer data dari host `db1` dijatuhkan total oleh firewall OPNsense (`FIREWALL_BLOCK`), mengonfirmasi 0 record bocor ke internet.
