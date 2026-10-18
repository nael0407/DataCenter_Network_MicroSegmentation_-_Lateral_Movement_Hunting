# Laporan Investigasi Insiden Forensik Digital (DFIR Incident Report)
## Kasus 02: Rekonstruksi Pembajakan Akses & Pergerakan Lateral SSH (Case ID: IR-2026-S02)

> **Standar Kepatuhan:** NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide) & ISO/IEC 27037:2012 (Digital Evidence Handling)  
> **Klasifikasi Insiden:** Kritis (Percobaan Pergerakan Lateral Multi-Tier / Lateral Movement Chain)  
> **Status Akhir Investigasi:** **TERISOLASI DI TITIK AWAL (0% Progresi Lateral, 0 Lompatan Berhasil)**  
> **Lead Investigator:** Natanael Simanjuntak (Lead Incident Responder & Forensic Analyst)  
> **Waktu Investigasi:** Minggu, 18 Oktober 2026, 05:10:43 s.d. 05:13:00 UTC  

---

## 1. Ringkasan Eksekutif (Executive Summary)

Pada 18 Oktober 2026 pukul 05:10:52 UTC, tim Incident Response mendeteksi aktivitas anomali eskalasi pergerakan lateral berantai (*lateral movement chain*) yang diinisiasi dari node web publik DMZ **`web1` (10.10.10.11)**. 

Setelah memperoleh titik tumpu awal (*initial pivot*), penyerang mencoba mengeksploitasi kredensial uji (`/tmp/compromised_id_ed25519`) untuk meretas infrastruktur internal lebih dalam melalui tiga vektor serangan:
1. **Lompatan Lateral Hop 1:** Mencoba login SSH langsung ke node aplikasi privat **`app1` (10.10.20.11:22)**.
2. **Lompatan Langsung (Direct Jump Bypass):** Mencoba melompati zona DMZ langsung ke server basis data inti **`db1` (10.10.30.11:22)**.
3. **Pembajakan Agen SSH & Tunneling (MITRE T1563.001 / T1572):** Memanipulasi soket agen SSH lokal (`/tmp/ssh-*/agent.*`) dan mencoba membangun terowongan TCP lokal (*SSH Local Port Forwarding* `-L 15432:10.10.30.11:5432`) untuk menyedot data database melintasi tier aplikasi.

Berdasarkan investigasi forensik digital post-mortem yang mematuhi standar ISO/IEC 27037 dan RFC 3227:
- **Blast Radius Terisolasi Total:** Seluruh percobaan lompatan lateral gagal total (*Connection timed out*). Penyerang terkunci 100% di dalam VM `web1`.
- **Pertahanan Berlapis Efektif:** Percobaan koneksi SSH keluar dari `web1` dijatuhkan seketika oleh aturan filter subsistem kernel `nftables` pada `web1` (hanya port 8080 yang diizinkan menuju subnet aplikasi) serta didukung oleh kebijakan default-deny OPNsense.
- **Kekebalan SSH Hardening:** Konfigurasi daemon OpenSSH pada host yang telah dikeraskan secara eksplisit mematikan `AllowAgentForwarding no` dan `AllowTcpForwarding no`, menggagalkan total upaya pembuatan proxy atau penggunaan soket agen curian.

---

## 2. Rantai Penanganan Bukti Digital (ISO/IEC 27037:2012 Chain of Custody)

Seluruh artefak barang bukti telah dikonsolidasikan dan diaudit dalam Evidence Vault terisolasi:

```
Evidence Vault: dfir/evidence/vault_ir_2026_s02/
├── evidence-manifest.json          [Master ISO/IEC 27037 Manifest, chmod 0440]
├── SHA256SUMS                      [Cryptographic Checksums, chmod 0440]
├── SHA512SUMS                      [Dual Hashing Checksums, chmod 0440]
├── host/
│   ├── evd-host-web1-20261018-051149.meta.json
│   └── evd-host-web1-20261018-051149.tar.gz    [RFC 3227 Triage WEB1, chmod 0440]
└── network/
    ├── EVD-NET-20261018-051043.meta.json
    └── EVD-NET-20261018-051043.pcap            [Raw Packet Capture br-sensor, chmod 0440]
```

### Tabel Inventaris & Integritas Kriptografis Barang Bukti:
| Evidence ID | Tipe Bukti | Sumber Node | Ukuran | Checksum Kriptografis SHA-256 | Status Integritas |
|---|---|---|---|---|---|
| **`EVD-NET-20261018-051043`** | Raw PCAP | `secops` (`br-sensor` mirror) | 7.9 KB | `b189c6293b93378bbbfd4b28cbfc3530ecf0e5e86b4d1f29e737d79dedb16d5a` | **100% VERIFIED** |
| **`EVD-HOST-WEB1-20261018-051149`** | RFC 3227 Triage | `web1` (RAM `/dev/shm`) | 74.8 KB | `a4c15505b27f90f8716702d70477cde69df5cadbb384b2c4750ca23f62673e2e` | **100% VERIFIED** |

*Audit integritas dieksekusi menggunakan `verify-evidence-integrity.py`: 100% GREEN (Lolos verifikasi dual-hashing SHA-256/SHA-512 dan izin read-only 0440).*

---

## 3. Kronologi & Super-Timeline Investigasi (Microsecond UTC)

Rekonstruksi kronologis linimasa disusun menggunakan engine `build-super-timeline.py`:

```
+----------------------------------------------------------------------------------------------------+
| Waktu (UTC)                   | Sumber / Node        | Aksi / Peristiwa Forensik Terverifikasi     |
+----------------------------------------------------------------------------------------------------+
| 2026-10-18T05:10:43.000000Z   | SECOPS (br-sensor)   | Penyadapan jaringan diaktifkan pada filter  |
|                               |                      | "tcp port 22" di tulang punggung Leaf1-3.   |
| 2026-10-18T05:10:52.270840Z   | HOST_WEB1 (sshd)     | Akses sesi penyerang terdeteksi pada web1   |
|                               |                      | via autentikasi publickey ED25519 (PID 5901)|
| 2026-10-18T05:10:53.100000Z   | HOST_WEB1 (Shell)    | Penyerang menaruh private key kompromi di   |
|                               |                      | /tmp/compromised_id_ed25519 (chmod 600).    |
| 2026-10-18T05:10:53.400000Z   | HOST_WEB1 (Perintah) | Percobaan Hop 1 diluncurkan:                |
|                               |                      | ssh -i key dcadmin@10.10.20.11:22           |
| 2026-10-18T05:10:56.405000Z   | KERNEL_NFTABLES(WEB1)| Paket TCP SYN tujuan 10.10.20.11:22 DIDROP; |
|                               |                      | Eksekusi timeout (Connection timed out).    |
| 2026-10-18T05:10:56.600000Z   | HOST_WEB1 (Perintah) | Percobaan Direct Jump ke DB diluncurkan:    |
|                               |                      | ssh -i key dcadmin@10.10.30.11:22           |
| 2026-10-18T05:10:59.605000Z   | KERNEL_NFTABLES(WEB1)| Paket TCP SYN tujuan 10.10.30.11:22 DIDROP; |
|                               |                      | Eksekusi timeout (Connection timed out).    |
| 2026-10-18T05:10:59.800000Z   | HOST_WEB1 (Perintah) | Upaya pembajakan agen SSH (eval ssh-agent,  |
|                               |                      | socket /tmp/ssh-*/agent.5982 dibuat).       |
| 2026-10-18T05:11:02.805000Z   | HOST_WEB1 (Perintah) | Percobaan pivoting via agent socket gagal   |
|                               |                      | (Connection timed out). Agen dimatikan.     |
| 2026-10-18T05:11:03.000000Z   | HOST_WEB1 (Perintah) | Upaya pembuatan SSH Tunnel -L 15432 ditolak |
|                               |                      | karena kegagalan jabat tangan koneksi.      |
| 2026-10-18T05:11:32.000000Z   | SECOPS (Akuisisi)    | Penyadapan PCAP dihentikan; bukti disimpan. |
| 2026-10-18T05:11:49.000000Z   | HOST_WEB1 (Triage)   | Live triage RFC 3227 dijalankan di RAM;     |
|                               |                      | arsip bukti 7-tier diamankan ke vault.      |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. Analisis Teknis Forensik Mendalam

### 4.1. Analisis Aliran Jaringan Mentah (Network PCAP Analysis)
Pemeriksaan dilakukan dengan `extract-pcap-artifacts.py` terhadap `EVD-NET-20261018-051043.pcap`:
- **Total Paket:** 28 frame paket TCP port 22.
- **Analisis Jabat Tangan TCP:**
  - Terdeteksi pengiriman frame `[SYN]` dari alamat IP `10.10.10.11` menuju `10.10.20.11:22` dan `10.10.30.11:22`.
  - Tidak ada satupun paket balasan `[SYN-ACK]` yang kembali dari target tier aplikasi maupun database.
  - Sesi koneksi berakhir dengan `RST` internal pada host lokal setelah *timeout* 3 detik.
- **Kesimpulan Jaringan:** Tidak ada sesi SSH interaktif yang berhasil terjalin melintasi batas zona EVPN/VXLAN.

### 4.2. Analisis Host Endpoint Triage (`web1`)
Pemeriksaan artefak 7-tier RFC 3227 pada `evd-host-web1-20261018-051149.tar.gz`:
1. **Analisis Aturan Firewall Host (`nftables`):**
   ```text
   chain output {
       type filter hook output priority filter; policy drop;
       oif "lo" accept
       ct state established,related accept
       ip daddr 10.10.10.1 icmp type echo-request accept
       ip daddr 10.10.10.1 udp dport 53 accept
       ip daddr 10.10.40.11 udp dport 1514 accept
       ip daddr 10.10.20.0/24 tcp dport 8080 accept
       counter packets 12355 bytes 853772 drop
   }
   ```
   Aturan `chain output policy drop` hanya membuka akses keluar ke port **8080** (HTTP REST API App). Seluruh paket keluar menuju port **22** dijatuhkan langsung di stack kernel host korban (**12.355 paket / 853 KB dropped**).
2. **Analisis Pengerasan Daemon SSH (`sshd_config`):**
   ```text
   allowagentforwarding no
   allowtcpforwarding no
   ```
   Pengerasan ini secara definitif menutup vektor serangan MITRE ATT&CK `T1563.001` (pembajakan soket agen) dan `T1572` (penerusan port TCP lokal/remote).

---

## 5. Pemetaan Taktik, Teknik, dan Prosedur (MITRE ATT&CK Mapping)

| Taktik MITRE | ID Teknik | Nama Teknik | Indikator Forensik Kasus | Status Penegakan |
|---|---|---|---|---|
| **Lateral Movement** | `T1021.004` | *Remote Services: SSH* | Upaya eksekusi `ssh -i key dcadmin@10.10.20.11` & `10.10.30.11` | **BLOCKED (Kernel Drop / Timeout)** |
| **Lateral Movement** | `T1563.001` | *SSH Agent Hijacking* | Pembuatan & manipulasi soket `/tmp/ssh-*/agent.*` | **MITIGATED (AllowAgentForwarding no)** |
| **Command and Control** | `T1572` | *Protocol Tunneling* | Upaya pembuatan port forward `-L 15432:db1:5432` | **BLOCKED (AllowTcpForwarding no)** |
| **Initial Access** | `T1078` | *Valid Accounts* | Penggunaan kunci SSH ed25519 kompromi | **CONTAINED (Terkunci di web1)** |
| **Discovery** | `T1046` | *Network Service Scanning* | Penjelajahan port 22 pada subnet internal | **BLOCKED (nftables egress drop)** |

---

## 6. Kesimpulan & Rekomendasi Mitigasi (Root Cause & Recommendations)

### 6.1. Kesimpulan Investigasi
Infrastruktur membuktikan ketahanan absolut terhadap upaya pergerakan lateral berantai. Sekalipun penyerang menguasai hak akses penuh di host web publik DMZ (`web1`), arsitektur **Zero-Trust Microsegmentation** dan **Host-Level Hardening** membatasi *blast radius* secara sempurna, menjaga tier aplikasi privat dan database inti tetap tak tersentuh (*zero compromise*).

### 6.2. Rekomendasi Tindak Lanjut:
1. **Pembersihan Node `web1`:** Menghapus kunci kompromi `/tmp/compromised_id_ed25519` dan merotasi *authorized_keys* seluruh akun administratif.
2. **Implementasi Ephemeral SSH Certificates:** Mengganti penggunaan kunci statis dengan sertifikat SSH berumur pendek (*short-lived SSH certificates* berbasis HashiCorp Vault atau Step-CA).
3. **Penyempurnaan Host Intrusion Detection:** Memasang modul auditd untuk mendeteksi pemanggilan biner `ssh` atau `ssh-agent` oleh akun proses layanan non-manusia (`www-data`).

---

## 7. Pernyataan Penutup & Tanda Tangan Forensik

Laporan ini disusun secara obyektif berdasarkan bukti digital yang terkumpul, diaudit, dan diverifikasi sesuai kaidah integritas rantai bukti hukum internasional (ISO/IEC 27037:2012). Seluruh artefak bukti digital mentah tersimpan dalam status terarsip dan terkunci di *Evidence Vault*.

**Investigator Forensik Bertanggung Jawab:**  
*Natanael Simanjuntak*  
Lead DFIR Incident Responder & Cloud Security Architect  
`Signature: SHA256[b189c6293b93378bbbfd4b28cbfc3530ecf0e5e86b4d1f29e737d79dedb16d5a]`
