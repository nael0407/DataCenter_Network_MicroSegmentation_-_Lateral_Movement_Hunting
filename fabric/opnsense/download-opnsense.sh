#!/usr/bin/env bash
# fabric/opnsense/download-opnsense.sh
# Mengunduh citra resmi OPNsense 24.7 (DVD ISO), memverifikasi SHA256 checksum, dan mengekstraknya
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/iso"
OPNSENSE_VER="24.7"
ISO_NAME="OPNsense-${OPNSENSE_VER}-dvd-amd64.iso"
BZ2_NAME="${ISO_NAME}.bz2"
CHECKSUM_NAME="OPNsense-${OPNSENSE_VER}-checksums-amd64.sha256"

# Daftar mirror resmi berkecepatan tinggi dengan fallback otomatis
MIRRORS=(
  "https://mirror.fra10.de.leaseweb.net/opnsense/releases/${OPNSENSE_VER}"
  "https://mirror.ams1.nl.leaseweb.net/opnsense/releases/${OPNSENSE_VER}"
  "https://opnsense.c0urier.net/releases/${OPNSENSE_VER}"
  "https://mirror.wdc1.us.leaseweb.net/opnsense/releases/${OPNSENSE_VER}"
)

mkdir -p "$TARGET_DIR"

echo "=========================================================="
echo "Pengunduhan & Verifikasi Citra OPNsense ${OPNSENSE_VER} (DVD ISO)"
echo "Target Direktori: $TARGET_DIR"
echo "=========================================================="

# 1. Unduh berkas checksum resmi
cd "$TARGET_DIR"
if [ ! -f "$CHECKSUM_NAME" ]; then
  echo "--- Mengunduh berkas checksum resmi ($CHECKSUM_NAME) ---"
  DOWNLOADED=0
  for base in "${MIRRORS[@]}"; do
    echo "Mencoba: $base/$CHECKSUM_NAME"
    if curl --connect-timeout 10 -fsSL "$base/$CHECKSUM_NAME" -o "$CHECKSUM_NAME"; then
      DOWNLOADED=1
      break
    fi
  done
  if [ $DOWNLOADED -eq 0 ]; then
    echo "ERROR: Gagal mengunduh berkas checksum dari seluruh mirror!" >&2
    exit 1
  fi
fi

# Tampilkan checksum yang diharapkan untuk berkas bz2
EXPECTED_SHA=$(grep "$BZ2_NAME" "$CHECKSUM_NAME" | awk '{print $NF}')
echo "Expected SHA256 ($BZ2_NAME): $EXPECTED_SHA"

# 2. Periksa apakah berkas ISO uncompressed sudah ada
if [ -f "$ISO_NAME" ]; then
  echo "[OK] Berkas $ISO_NAME sudah ada di direktori target."
  ls -lh "$ISO_NAME"
  exit 0
fi

# 3. Unduh berkas .iso.bz2 (mendukung resume download via wget -c / curl -C -)
if [ ! -f "$BZ2_NAME" ]; then
  echo "--- Mengunduh citra $BZ2_NAME (Ukuran ~511 MB) ---"
  DOWNLOADED=0
  for base in "${MIRRORS[@]}"; do
    echo "Mengunduh dari mirror: $base/$BZ2_NAME..."
    if curl --connect-timeout 15 --retry 3 -C - -# -fSL "$base/$BZ2_NAME" -o "$BZ2_NAME"; then
      DOWNLOADED=1
      break
    else
      echo "Gagal mengunduh dari $base, mencoba mirror berikutnya..."
    fi
  done
  if [ $DOWNLOADED -eq 0 ]; then
    echo "ERROR: Gagal mengunduh $BZ2_NAME dari seluruh mirror!" >&2
    exit 1
  fi
fi

# 4. Verifikasi Checksum SHA256 secara kriptografis
echo "--- Memverifikasi integritas SHA256 ($BZ2_NAME) ---"
CALCULATED_SHA=$(sha256sum "$BZ2_NAME" | awk '{print $1}')
echo "Calculated : $CALCULATED_SHA"
echo "Expected   : $EXPECTED_SHA"

if [ "$CALCULATED_SHA" != "$EXPECTED_SHA" ]; then
  echo "FATAL: Checksum SHA256 TIDAK COCOK! Berkas rusak atau terkorupsi." >&2
  echo "Menghapus berkas rusak: $BZ2_NAME"
  rm -f "$BZ2_NAME"
  exit 1
fi
echo "[VERIFIED] Integritas berkas $BZ2_NAME 100% VALID dan ASLI."

# 5. Ekstraksi .bz2 menjadi berkas .iso
echo "--- Mengekstrak $BZ2_NAME menggunakan bunzip2 ---"
bunzip2 -k -f "$BZ2_NAME"

echo
echo "=========================================================="
echo "Citra OPNsense Siap Digunakan:"
ls -lh "$ISO_NAME"
echo "=========================================================="
