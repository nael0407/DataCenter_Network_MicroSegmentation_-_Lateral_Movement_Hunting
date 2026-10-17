# Modul Digital Forensics & Incident Response (DFIR)

Modul ini menyediakan framework investigasi forensik digital dan penanganan insiden paska-pembobolan (*Post-Breach Investigation*) pada lingkungan Data Center terdistribusi Spine-Leaf EVPN/VXLAN.

Arsitektur modul mematuhi standar internasional:
* **ISO/IEC 27037:2012:** Manajemen bukti digital, integritas hash SHA-256/SHA-512, dan pelacakan *Chain of Custody*.
* **RFC 3227:** Pengumpulan bukti host sesuai *Order of Volatility*.
* **NIST SP 800-61 Rev 2:** Alur investigasi insiden komputer dan pelaporan resmi.

---

## 1. Struktur Direktori Modul

```
dfir/
├── README.md                      # Dokumentasi modul dan metodologi DFIR
├── acquisition/                   # Skrip otomasi pengumpulan bukti digital
│   ├── capture-network-evidence.sh # Sniffing PCAP mentah via antarmuka br-sensor secops
│   ├── triage-host-evidence.sh    # Kolektor bukti live triage host (RFC 3227 compliant)
│   └── package-evidence.sh        # Pengemas wadah bukti & pengunci hak akses read-only
├── evidence/                      # Vault penyimpanan bukti (terproteksi .gitignore)
│   ├── manifest-template.json     # Skema metadata Chain of Custody ISO 27037
│   ├── verify-evidence-integrity.sh # Validasi otomatis kecocokan hash SHA-256 bukti
│   ├── network/                   # Direktori arsip berkas PCAP bukti jaringan
│   └── host/                      # Direktori arsip tarball artefak host triage
├── analysis/                      # Toolset analisis post-mortem & rekonstruksi
│   ├── extract-pcap-artifacts.py  # Ekstraksi payload, stream carving tshark
│   ├── parse-host-artifacts.py    # Parser log otentikasi, soket, dan history eksekusi
│   └── build-super-timeline.py    # Generator linimasa kronologis terpadu multi-sensor
├── reports/                       # Laporan resmi hasil investigasi forensik
│   ├── INCIDENT-REPORT-CASE-01-DB-EXFILTRATION.md
│   └── INCIDENT-REPORT-CASE-02-LATERAL-SSH.md
└── demo/                          # Skrip walkthrough dan presentasi singkat
    └── run-dfir-walkthrough.sh
```

---

## 2. Alur Kerja Investigasi

1. **Trigger / Alert:** Terdeteksi indikasi anomali eksfiltrasi atau pergerakan lateral (Zeek / OPNsense / OpenCanary).
2. **Network Acquisition:** Sniffing frame data mentah di antarmuka mirror `secops` (`br-sensor`) disimpan ke format PCAP.
3. **Host Live Triage:** Eksekusi triage non-destruktif ke host korban (`web1` atau `db1`) via Bastion ProxyJump mengumpulkan soket, memori/proc, riwayat perintah, dan log otentikasi.
4. **Preservasi & Hashing:** Menghitung checksum kriptografis SHA-256 dan SHA-512, mencatat metadata ISO 27037 ke `manifest.json`, dan mengunci izin berkas menjadi *read-only* (`0440`).
5. **Analisis & Rekonstruksi Super-Timeline:** Korelasi linimasa mikrodetik UTC lintas sumber (Firewall SPI, Zeek metadata, Host triage, Decoy).
6. **Laporan Forensik:** Penyusunan laporan insiden berstandar industri dengan pemetaan taktik dan teknik MITRE ATT&CK.
