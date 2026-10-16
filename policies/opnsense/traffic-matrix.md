# Matriks Kebijakan Segmentasi Jaringan & Firewall OPNsense

Dokumen ini mendefinisikan matriks izin komunikasi antar-zona (*East-West* dan *North-South*) yang ditegakkan secara terpusat oleh firewall OPNsense dalam arsitektur **Zero-Trust Micro-segmentation**.

---

## 1. Definisi Zona & Antarmuka OPNsense

| Zona | ID VLAN | Subnet | Antarmuka OPNsense | Peran & Beban Kerja |
|---|---|---|---|---|
| **Web DMZ** | VLAN 10 | 10.10.10.0/24 | `vlan01` (vtnet1.10) | Web frontend (`web1`, `web2`) |
| **Aplikasi** | VLAN 20 | 10.10.20.0/24 | `vlan02` (vtnet1.20) | Layanan aplikasi backend (`app1`, `app2`) |
| **Database** | VLAN 30 | 10.10.30.0/24 | `vlan03` (vtnet1.30) | Database postgres-mock (`db1`) |
| **Manajemen / SecOps** | VLAN 40 | 10.10.40.0/24 | `vlan04` (vtnet1.40) | Bastion SSH, Sensor Zeek, Loki, Grafana (`secops`) |
| **Decoy** | VLAN 50 | 10.10.50.0/24 | `vlan05` (vtnet1.50) | Honeypot OpenCanary (`canary1`) |
| **WAN / Eksternal** | Untagged | 203.0.113.0/24 | `vtnet2` | Penyerang & internet eksternal (`attacker`) |

---

## 2. Matriks Izin Komunikasi Antar-Zona (Traffic Matrix)

Prinsip dasar: **Default Deny All**. Seluruh lalu lintas antar-zona diblokir secara eksplisit dan dicatat ke log, kecuali aliran yang tercantum dalam tabel izin di bawah ini:

| Sumber (Source) | Destinasi (Destination) | Port / Protokol | Aksi | Log | Keterangan & Rationale Keamanan |
|---|---|---|---|---|---|
| **WAN** (`203.0.113.11`) | **Web DMZ** (`10.10.10.11`) | TCP 80 | **PASS** | Ya | Akses publik resmi via NAT port-forwarding WAN:80 |
| **Web DMZ** (`10.10.10.0/24`) | **Aplikasi** (`10.10.20.0/24`) | TCP 8080 | **PASS** | Ya | Panggilan API aplikasi dari Web ke App tier |
| **Aplikasi** (`10.10.20.0/24`) | **Database** (`10.10.30.11`) | TCP 5432 | **PASS** | Ya | Kueri database dari App backend ke PostgreSQL |
| **SecOps Bastion** (`10.10.40.11`) | **Seluruh Zona** (`10.10.0.0/16`) | TCP 22 | **PASS** | Ya | Akses administratif sah via SSH Bastion ProxyJump |
| **Seluruh Zona** (`10.10.0.0/16`) | **SecOps** (`10.10.40.11`) | UDP 1514 | **PASS** | Ya | Pengiriman log telemetri syslog (RFC 5424) ke Alloy |
| **Seluruh Zona** | **Gateway OPNsense** (`10.10.x.1`) | ICMP / DNS :53 | **PASS** | Ya | Resolusi nama & diagnosa konektivitas gateway |
| **Web DMZ** (`10.10.10.0/24`) | **Database** (`10.10.30.0/24`) | ANY | **BLOCK** | Ya | **Mitigasi S1/S2**: Blokir direct bypass Web -> DB |
| **Web DMZ** (`10.10.10.0/24`) | **Aplikasi** (`10.10.20.0/24`) | TCP 22 | **BLOCK** | Ya | **Mitigasi S2/S3/S4**: Blokir SSH lateral & tunneling |
| **Database** (`10.10.30.0/24`) | **WAN / Eksternal** | ANY | **BLOCK** | Ya | **Mitigasi S6**: Zero-Trust Egress (Database tidak boleh ke WAN) |
| **ANY** | **ANY** | ANY | **BLOCK** | Ya | Default Deny All + Filterlog Logging |

---

## 3. Strategi Implementasi pada OPNsense Firewall

Pada OPNsense 24.7, aturan firewall dievaluasi dari atas ke bawah (*first match wins*). Urutan aturan per antarmuka dikonfigurasi sebagai berikut:

### A. Antarmuka Web (VLAN 10 / `vlan01`):
1. **PASS**: Outbound ke `10.10.20.0/24` Port `TCP 8080` (Aplikasi).
2. **PASS**: Outbound ke `10.10.40.11` Port `UDP 1514` (Syslog SecOps).
3. **PASS**: Outbound ke `10.10.10.1` ICMP & UDP 53 (Gateway OPNsense).
4. **BLOCK + LOG**: Default Deny All (Memblokir akses ke DB :5432, App :22, Canary, dll).

### B. Antarmuka App (VLAN 20 / `vlan02`):
1. **PASS**: Outbound ke `10.10.30.11` Port `TCP 5432` (Database).
2. **PASS**: Outbound ke `10.10.40.11` Port `UDP 1514` (Syslog SecOps).
3. **PASS**: Outbound ke `10.10.20.1` ICMP & UDP 53 (Gateway OPNsense).
4. **BLOCK + LOG**: Default Deny All (Memblokir SSH ke DB :22, memblokir akses ke Web, dll).

### C. Antarmuka DB (VLAN 30 / `vlan03`):
1. **PASS**: Outbound ke `10.10.40.11` Port `UDP 1514` (Syslog SecOps).
2. **PASS**: Outbound ke `10.10.30.1` ICMP & UDP 53 (Gateway OPNsense).
3. **BLOCK + LOG**: Default Deny All (Memblokir seluruh inisiasi koneksi keluar ke WAN maupun zona lain).

### D. Antarmuka SecOps (VLAN 40 / `vlan04`):
1. **PASS**: Outbound ke `10.10.0.0/16` Port `TCP 22` (SSH Manajemen Bastion).
2. **PASS**: Outbound ke `10.10.40.1` ICMP & UDP 53 (Gateway OPNsense).
3. **BLOCK + LOG**: Default Deny All.

### E. Antarmuka Decoy (VLAN 50 / `vlan05`):
1. **PASS**: Outbound ke `10.10.40.11` Port `UDP 1514` (Syslog Alert OpenCanary).
2. **BLOCK + LOG**: Default Deny All.
