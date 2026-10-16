#!/usr/bin/env bash
# attack-tests/run-hardened-attacks.sh
# Master Test Runner untuk Skenario Serangan Pasca-Pengerasan (Fase 7.4)
# Menjalankan S1, S2, S3, S4, S5, S6, S7 dalam kondisi hardened dan mengkalkulasi komparasi blast radius.
set -euo pipefail

echo "=========================================================="
echo "  PENGUJIAN KOMPREHENSIF SKENARIO SERANGAN PASCA-PENGUATAN"
echo "  FASE 7.4: RE-RUN ATTACK SCENARIOS & BLAST RADIUS METRICS"
echo "=========================================================="
echo "Tanggal Eksekusi: $(date '+%Y-%m-%d %H:%M:%S')"
echo

# 1. Skenario S1: Pemindaian Layanan Lateral (T1046 / T1018)
echo ">>> [1/5] Menjalankan Skenario S1 (Network Service Discovery)..."
bash attack-tests/s01-network-discovery-hardened.sh
echo

# 2. Skenario S2: Pergerakan Lateral SSH Berantai (T1021.004)
echo ">>> [2/5] Menjalankan Skenario S2 (Chained Lateral SSH Movement)..."
bash attack-tests/s02-lateral-ssh-movement-hardened.sh
echo

# 3. Skenario S3 & S4: SSH Agent Hijacking & Protocol Tunneling (T1563.001 & T1572)
echo ">>> [3/5] Menjalankan Skenario S3 & S4 (SSH Agent Hijacking & Tunneling)..."
bash attack-tests/s03-s04-hijack-and-tunnel-hardened.sh
echo

# 4. Skenario S5: Decoy Touch & Isolasi Honeypot
echo ">>> [4/5] Menjalankan Skenario S5 (OpenCanary Decoy & Isolation)..."
bash attack-tests/s05-canary-decoy-hardened.sh
echo

# 5. Skenario S6 & S7: Data Exfiltration & External Perimeter (T1041 / T1048 & Perimeter)
echo ">>> [5/5] Menjalankan Skenario S6 & S7 (DB Egress Exfiltration & Perimeter)..."
bash attack-tests/s06-s07-egress-and-perimeter-hardened.sh
echo

# 6. Komparasi Kuantitatif Blast Radius Baseline vs Hardened
echo ">>> Menghasilkan Laporan Komparasi Blast Radius Kuantitatif..."
python3 attack-tests/compare-blast-radius.py
echo

echo "=========================================================="
echo "  SELURUH PENGUJIAN SKENARIO HARDENED SELESAI DIEKSEKUSI!"
echo "  Semua artefak tersimpan di direktori: attack-tests/"
echo "=========================================================="
