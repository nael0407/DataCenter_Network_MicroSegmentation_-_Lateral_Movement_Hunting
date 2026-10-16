# Laporan Komparasi Kuantitatif Blast Radius & Matriks Keterjangkauan
**Tanggal Pengujian**: 2026-10-16 20:48:33
**Status Evaluasi**: Fase 7 (Penegakan Micro-segmentation & Pengerasan Pertahanan)

---

## 1. Ringkasan Eksekutif & Metrik Kuantitatif Inti

| Parameter Metrik | Kondisi Baseline (Pre-Hardening) | Kondisi Hardened (Post-Hardening) | Perubahan / Efektivitas |
|---|---|---|---|
| **Jumlah Layanan Terekspos ke Web DMZ** | 14 layanan (App, DB, Canary) | 2 layanan (hanya App:8080) | **Turun 85.71%** (Sisa 14.29%) |
| **Keterjangkauan Database Tier dari Web DMZ** | 100% Terbuka (Port 5432 & 22) | 0% Terbuka (Diblokir Total) | **100% Eliminasi Paparan DB** |
| **Keterjangkauan Decoy Tier dari Web DMZ** | 100% Terbuka (8 Port Decoy) | 0% Terbuka (Diblokir Total) | **100% Isolasi Decoy** |
| **Keberhasilan SSH Lateral Movement (S2)** | 100% Sukses (3/3 Lompatan) | 0% Sukses (3/3 Dijatuhkan) | **100% Pencegahan Lateral SSH** |
| **Eksfiltrasi Data Sensitif DB ke WAN (S6)** | 100% Bocor (42 Record) | 0% Bocor (0 Record) | **100% Pencegahan Eksfiltrasi** |
| **Integritas Alur Aplikasi Sah 3-Tier** | 100% Lulus (HTTP 200 OK) | 100% Lulus (HTTP 200 OK) | **0% Disrupsi Bisnis (Zero Downtime)** |

> [!IMPORTANT]
> **Evaluasi Kriteria Kelulusan**: Target penurunan blast radius ke **<= 15%** berhasil dicapai secara sempurna (**14.29%** layanan tersisa, yang merupakan port API bisnis yang sah). Paparan terhadap tier sensitif (Database dan Manajemen SSH) turun menjadi **0%**.

---

## 2. Rincian Pemindaian Layanan Lateral dari Web DMZ (Skenario S1)

| Node Target | IP Address | Port Terbuka (Baseline) | Port Terbuka (Hardened) | Status Keamanan |
|---|---|---|---|---|
| `app1` | `10.10.20.11` | 22/tcp (ssh), 8080/tcp (http-proxy) | 8080/tcp (http-proxy) | SECURED (Least Privilege) |
| `app2` | `10.10.20.12` | 22/tcp (ssh), 8080/tcp (http-proxy) | 8080/tcp (http-proxy) | SECURED (Least Privilege) |
| `db1` | `10.10.30.11` | 22/tcp (ssh), 5432/tcp (postgresql) | **BLOCKED (0 port)** | FULLY ISOLATED |
| `canary1` | `10.10.50.11` | 21/tcp (ftp), 22/tcp (ssh), 23/tcp (telnet), 80/tcp (http), 2222/tcp (ssh-decoy), 3306/tcp (mysql), 6379/tcp (redis), 8080/tcp (proxy) | **BLOCKED (0 port)** | FULLY ISOLATED |

---

## 3. Matriks Hasil Pengujian Skenario Serangan (MITRE ATT&CK Mapping)

| ID | Skenario Serangan | Teknik MITRE ATT&CK | Status Baseline | Status Hardened | Mekanisme Penegakan |
|---|---|---|---|---|---|
| **S1** | Network Service Discovery | `T1046 / T1018` | VULNERABLE (14 layanan internal ditemukan dari Web DMZ, blast radius 100%) | **RESTRICTED (Hanya 2 port API 8080 ditemukan; DB & Canary diblokir total)** | OPNsense Default Deny + Host nftables Output Chain |
| **S2** | Chained Lateral SSH Movement | `T1021.004 / T1078` | VULNERABLE (3/3 lompatan berhasil: web1->app1, app1->db1, web1->db1) | **BLOCKED (3/3 lompatan dijatuhkan: Connection timed out / Policy Drop)** | nftables output drop port 22 + OPNsense inter-zone block |
| **S3** | SSH Agent Forwarding Hijacking | `T1563.001` | VULNERABLE (Autentikasi lateral sukses memanfaatkan socket RAM) | **BLOCKED (sshd 'AllowAgentForwarding no' + network isolation)** | Drop-in sshd_config hardening + nftables |
| **S4** | Protocol Tunneling via SSH (-L) | `T1572 / T1090` | VULNERABLE (Data database diekstrak melalui SSH tunnel lokal 15432) | **BLOCKED (sshd 'AllowTcpForwarding no' + port-forwarding ditolak)** | Drop-in sshd_config hardening + nftables |
| **S5** | Honeypot Decoy Touch & Alerting | `T1046 (Detection)` | ACCESSIBLE (8 port umpan disentuh langsung dari Web DMZ; latensi 64ms) | **ISOLATED (Probe lateral dari Web dijatuhkan sebelum mencapai honeypot)** | OPNsense VLAN 50 isolation + OpenCanary standby |
| **S6** | Database Egress Exfiltration | `T1041 / T1048` | VULNERABLE (42 record nasabah db1 berhasil dieksfiltrasi ke WAN via HTTP & ICMP) | **BLOCKED (0 record bocor, HTTP POST & ICMP egress dijatuhkan 100%)** | Zero-Trust Egress nftables db1 + OPNsense Default Deny |
| **S7** | External North-South Perimeter | `External Recon / Attack` | PROTECTED (Web DMZ 200 OK via NAT, direct bypass ke internal diblokir) | **PROTECTED (Web DMZ 200 OK via NAT 3-tier, perimeter drop 100% terjaga)** | OPNsense WAN Filter & NAT Port Forwarding |

---

## 4. Matriks Keterjangkauan Komunikasi Jaringan (Traffic Reachability Matrix)

| Sumber (Source) | Destinasi (Destination) | Kondisi Baseline | Kondisi Hardened (Zero-Trust) | Rationale Keamanan |
|---|---|---|---|---|
| **WAN (Attacker)** | **Web DMZ** | `TCP 80 (Pass)` | **`TCP 80 (Pass - Sah)`** | Enforced by OPNsense & nftables |
| **WAN (Attacker)** | **App Tier** | `BLOCKED` | **`BLOCKED (Drop)`** | Enforced by OPNsense & nftables |
| **WAN (Attacker)** | **Database** | `BLOCKED` | **`BLOCKED (Drop)`** | Enforced by OPNsense & nftables |
| **Web DMZ** | **Web DMZ (Intra)** | `ALL (Pass)` | **`ICMP only (Drop Intra-zone SSH)`** | Enforced by OPNsense & nftables |
| **Web DMZ** | **App Tier** | `ALL (Pass)` | **`TCP 8080 (Pass - Sah) | TCP 22 (Drop)`** | Enforced by OPNsense & nftables |
| **Web DMZ** | **Database** | `ALL (Pass - Rentan)` | **`ALL BLOCKED (Drop Total)`** | Enforced by OPNsense & nftables |
| **Web DMZ** | **Decoy** | `ALL (Pass)` | **`ALL BLOCKED (Drop Total)`** | Enforced by OPNsense & nftables |
| **Web DMZ** | **WAN (Internet)** | `ALL (Pass)` | **`ALL BLOCKED (Drop Total)`** | Enforced by OPNsense & nftables |
| **App Tier** | **Database** | `ALL (Pass)` | **`TCP 5432 (Pass - Sah) | TCP 22 (Drop)`** | Enforced by OPNsense & nftables |
| **App Tier** | **Web DMZ** | `ALL (Pass)` | **`ALL BLOCKED (Drop Total)`** | Enforced by OPNsense & nftables |
| **App Tier** | **WAN (Internet)** | `ALL (Pass)` | **`ALL BLOCKED (Drop Total)`** | Enforced by OPNsense & nftables |
| **Database** | **WAN (Internet)** | `ALL (Pass - Eksfiltrasi)` | **`ALL BLOCKED (Zero-Trust Egress)`** | Enforced by OPNsense & nftables |
| **Database** | **App Tier** | `ALL (Pass)` | **`Established/Related ONLY`** | Enforced by OPNsense & nftables |
| **Database** | **Web DMZ** | `ALL (Pass)` | **`ALL BLOCKED (Drop Total)`** | Enforced by OPNsense & nftables |
| **SecOps Bastion** | **Workloads (All)** | `TCP 22 (Pass)` | **`TCP 22 (Pass - Admin Sah)`** | Enforced by OPNsense & nftables |

---

## 5. Kesimpulan Penegakan Micro-segmentation (Fase 7)
1. **Pertahanan Berlapis (*Defense-in-Depth*) Terbukti**: Kombinasi firewall stateful OPNsense pada Layer-3 inter-zona, filter paket host `nftables` pada Layer-2/4 intra-zona, serta pengerasan konfigurasi daemon SSH (`sshd_config`) terbukti menggagalkan seluruh vektor serangan lateral movement tanpa mengganggu alur operasional aplikasi 3-tier sah.
2. **Blast Radius Terisolasi Total**: Penyerang yang menguasai Web DMZ (`web1`) terkurung total dalam zonanya; tidak dapat memindai port database, tidak dapat melakukan pivot SSH, tidak dapat menyalahgunakan socket agent, dan tidak dapat melakukan pembajakan tunnel.
3. **Zero-Trust Egress Efektif**: Zona Database (`db1`) tidak lagi memiliki akses keluar ke jaringan eksternal (WAN), sehingga eksfiltrasi data otomatis terhenti.
