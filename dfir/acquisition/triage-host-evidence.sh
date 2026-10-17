#!/usr/bin/env bash
# dfir/acquisition/triage-host-evidence.sh
# Skrip Kolektor Bukti Forensik Live Triage Host (RFC 3227 & ISO/IEC 27037)
# Mengumpulkan artefak volatil & non-volatil dari host korban via Bastion ProxyJump
set -euo pipefail

SECOPS_IP="192.168.122.81"
SECOPS_USER="dcadmin"
SSH_KEY="${HOME}/.ssh/k8s-lab"
SSH_OPTS="-i ${SSH_KEY} -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VAULT_HOST_DIR="${REPO_ROOT}/dfir/evidence/host"

mkdir -p "${VAULT_HOST_DIR}"

# Nilai Default
TARGET=""
CASE_ID="CASE-2026-DFIR-001"
OUTPUT_NAME=""
EVIDENCE_ID=""

print_usage() {
  cat << EOF
Penggunaan: $0 --target <IP_ATAU_HOSTNAME> [OPSI]

Opsi Wajib:
  --target <IP|NAME>    Target host korban (contoh: 10.10.10.11, 10.10.30.11, web1, db1)

Opsi Tambahan:
  --case-id <ID>        ID Kasus DFIR (Default: CASE-2026-DFIR-001)
  --evidence-id <ID>    ID Bukti ISO 27037 unik (Default: EVD-HOST-<TARGET>-YYYYMMDD-HHMMSS)
  --output <nama_file>  Nama berkas tarball hasil (contoh: evd-host-web1-triage.tar.gz)
  -h, --help            Tampilkan bantuan ini

Urutan Volatilitas (RFC 3227):
  1. Soket Jaringan & Koneksi Aktif (ss -tulpn, ss -tanpo, ip neigh, ip route)
  2. Status Proses & Memori Eksekusi (ps auxwwfe, pstree, /proc/\$PID/cmdline, /proc/\$PID/status)
  3. Berkas Terbuka & File Descriptors (lsof -n -P, /proc/\$PID/fd)
  4. Sesi Pengguna Aktif & Lingkungan (who, w, last, /tmp/ssh-*)
  5. Log Otentikasi & Jejak Sistem (/var/log/auth.log, journalctl ssh)
  6. Riwayat Shell & Konfigurasi Persistensi (.bash_history, crontab, systemd)
  7. Berkas yang Baru Dimodifikasi 60 Menit Terakhir (find -mmin -60 -ls)

Contoh:
  $0 --target 10.10.10.11 --output evd-host-web1-triage.tar.gz
  $0 --target 10.10.30.11 --case-id CASE-2026-DFIR-S06 --evidence-id EVD-HOST-DB1-001
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --case-id)
      CASE_ID="$2"
      shift 2
      ;;
    --evidence-id)
      EVIDENCE_ID="$2"
      shift 2
      ;;
    --output)
      OUTPUT_NAME="$2"
      shift 2
      ;;
    -h|--help)
      print_usage 0
      ;;
    *)
      echo "Error: Opsi tidak dikenal: $1" >&2
      print_usage 1
      ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "Error: Opsi --target wajib diisi." >&2
  print_usage 1
fi

# Konversi alias hostname ke IP jika diperlukan
case "$TARGET" in
  web1) TARGET_IP="10.10.10.11" ;;
  web2) TARGET_IP="10.10.10.12" ;;
  app1) TARGET_IP="10.10.20.11" ;;
  app2) TARGET_IP="10.10.20.12" ;;
  db1) TARGET_IP="10.10.30.11" ;;
  canary1) TARGET_IP="10.10.50.11" ;;
  attacker) TARGET_IP="203.0.113.11" ;;
  secops) TARGET_IP="10.10.40.11" ;;
  *) TARGET_IP="$TARGET" ;;
esac

TARGET_NAME="$TARGET"
if [ "$TARGET_NAME" = "$TARGET_IP" ]; then
  case "$TARGET_IP" in
    10.10.10.11) TARGET_NAME="web1" ;;
    10.10.10.12) TARGET_NAME="web2" ;;
    10.10.20.11) TARGET_NAME="app1" ;;
    10.10.20.12) TARGET_NAME="app2" ;;
    10.10.30.11) TARGET_NAME="db1" ;;
    10.10.50.11) TARGET_NAME="canary1" ;;
    203.0.113.11) TARGET_NAME="attacker" ;;
    10.10.40.11) TARGET_NAME="secops" ;;
  esac
fi

DATE_STAMP="$(date -u +%Y%m%d)"
TIME_STAMP="$(date -u +%H%M%S)"

if [ -z "$EVIDENCE_ID" ]; then
  EVIDENCE_ID="EVD-HOST-${TARGET_NAME^^}-${DATE_STAMP}-${TIME_STAMP}"
fi

if [ -z "$OUTPUT_NAME" ]; then
  OUTPUT_NAME="${EVIDENCE_ID,,}.tar.gz"
fi
[[ "$OUTPUT_NAME" != *.tar.gz ]] && OUTPUT_NAME="${OUTPUT_NAME}.tar.gz"

LOCAL_TAR="${VAULT_HOST_DIR}/${OUTPUT_NAME}"
LOCAL_META="${VAULT_HOST_DIR}/${OUTPUT_NAME%.tar.gz}.meta.json"
rm -f "${LOCAL_TAR}" "${LOCAL_META}"

START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
START_EPOCH=$(date +%s.%N)

echo "=========================================================="
echo "Memulai Live Host Triage Forensik (RFC 3227 & ISO 27037)"
echo "=========================================================="
echo "Target Host : ${TARGET_NAME} (${TARGET_IP})"
echo "Case ID     : ${CASE_ID}"
echo "Evidence ID : ${EVIDENCE_ID}"
echo "Bastion     : ${SECOPS_IP} (ProxyJump)"
echo "Target File : ${LOCAL_TAR}"
echo "Waktu Mulai : ${START_TIME}"
echo "=========================================================="

# Eksekusi Triage di Target Host melalui Bastion ProxyJump
# Triage dijalankan di /dev/shm (RAM filesystem) untuk menjaga integritas disk korban
REMOTE_SCRIPT=$(cat << 'REMOTE_EOF'
set -euo pipefail

TARGET_NAME="$1"
EVD_ID="$2"
START_TIME="$3"

TMP_DIR=$(mktemp -d /dev/shm/triage_XXXXXX)
cd "$TMP_DIR"

mkdir -p 01_network_sockets 02_process_state 03_open_files 04_user_sessions 05_auth_and_syslogs 06_persistence_and_histories 07_modified_files_60m

# [Tier 1] Soket Jaringan & Koneksi Aktif
sudo ss -tulpn > 01_network_sockets/ss_tulpn.txt 2>/dev/null || true
sudo ss -tanpo > 01_network_sockets/ss_tanpo.txt 2>/dev/null || true
ip -d route show table all > 01_network_sockets/ip_route.txt 2>/dev/null || true
ip neigh show > 01_network_sockets/ip_neigh.txt 2>/dev/null || true
ip -d addr show > 01_network_sockets/ip_addr.txt 2>/dev/null || true

# [Tier 2] Status Proses & Memori Eksekusi
ps auxwwfe > 02_process_state/ps_auxwwfe.txt 2>/dev/null || true
pstree -apuhl > 02_process_state/pstree.txt 2>/dev/null || true
top -b -n 1 > 02_process_state/top_batch.txt 2>/dev/null || true

mkdir -p 02_process_state/proc_cmdlines 02_process_state/proc_status
for pid_dir in /proc/[0-9]*; do
  pid="${pid_dir##*/}"
  if [ -r "$pid_dir/cmdline" ]; then
    tr '\0' ' ' < "$pid_dir/cmdline" > "02_process_state/proc_cmdlines/${pid}.txt" 2>/dev/null || true
  fi
  if [ -r "$pid_dir/status" ]; then
    cp "$pid_dir/status" "02_process_state/proc_status/${pid}.txt" 2>/dev/null || true
  fi
done

# [Tier 3] Berkas Terbuka & File Descriptors
sudo lsof -n -P > 03_open_files/lsof.txt 2>/dev/null || true
sudo ls -la /proc/[0-9]*/fd > 03_open_files/proc_fds.txt 2>/dev/null || true

# [Tier 4] Sesi Pengguna Aktif & Jejak Kredensial
who -a > 04_user_sessions/who.txt 2>/dev/null || true
w > 04_user_sessions/w.txt 2>/dev/null || true
last -F -n 50 > 04_user_sessions/last.txt 2>/dev/null || true
lastlog > 04_user_sessions/lastlog.txt 2>/dev/null || true
sudo ls -la /tmp/ssh-* > 04_user_sessions/ssh_agent_sockets.txt 2>/dev/null || true
env > 04_user_sessions/session_env.txt 2>/dev/null || true

# [Tier 5] Log Otentikasi & Sistem
if [ -f /var/log/auth.log ]; then
  sudo cp -p /var/log/auth.log 05_auth_and_syslogs/auth.log 2>/dev/null || true
fi
sudo journalctl -u ssh.service -n 500 --no-pager > 05_auth_and_syslogs/journalctl_ssh.txt 2>/dev/null || true
if [ -f /var/log/syslog ]; then
  sudo tail -n 1000 /var/log/syslog > 05_auth_and_syslogs/syslog_tail.txt 2>/dev/null || true
fi

# [Tier 6] Riwayat Shell & Persistensi
mkdir -p 06_persistence_and_histories/bash_histories
for home_dir in /home/* /root; do
  user="${home_dir##*/}"
  if [ -f "$home_dir/.bash_history" ]; then
    sudo cp -p "$home_dir/.bash_history" "06_persistence_and_histories/bash_histories/${user}_bash_history.txt" 2>/dev/null || true
  fi
done
sudo crontab -l -u root > 06_persistence_and_histories/root_crontab.txt 2>/dev/null || true
sudo cat /etc/crontab > 06_persistence_and_histories/etc_crontab.txt 2>/dev/null || true
sudo ls -la /etc/cron.* > 06_persistence_and_histories/etc_cron_dirs.txt 2>/dev/null || true
sudo ls -lat /etc/systemd/system/ > 06_persistence_and_histories/systemd_system_units.txt 2>/dev/null || true

# [Tier 7] Berkas yang Dimodifikasi 60 Menit Terakhir
sudo find /etc /var /tmp /home -xdev -mmin -60 -ls > 07_modified_files_60m/modified_files_60m.txt 2>/dev/null || true

# Metadata Lingkungan Target
HOSTNAME=$(hostname)
UPTIME=$(uptime)
KERNEL=$(uname -a)
MAC_DATA=$(ip link show eth1 2>/dev/null | grep link/ether | awk '{print $2}' || echo "N/A")

cat > METADATA.txt << META
EVIDENCE_ID=${EVD_ID}
TARGET_NAME=${TARGET_NAME}
HOSTNAME=${HOSTNAME}
KERNEL=${KERNEL}
MAC_ETH1=${MAC_DATA}
ACQUISITION_START=${START_TIME}
UPTIME=${UPTIME}
COLLECTOR=Natanael (Incident Response Team)
STANDARD=RFC 3227 & ISO/IEC 27037:2012
META

# Pastikan seluruh berkas artefak dapat dibaca sebelum inventarisasi hash
sudo chmod -R a+r .

# Inventaris Hash Internal Sebelum Kompresi
find . -type f ! -name "INVENTORY_HASHES.sha256" -exec sha256sum {} + > INVENTORY_HASHES.sha256

# Kemas ke tarball di /dev/shm
ARCHIVE="/dev/shm/${EVD_ID}.tar.gz"
tar -czf "$ARCHIVE" .

REMOTE_SIZE=$(stat -c %s "$ARCHIVE")
REMOTE_SHA256=$(sha256sum "$ARCHIVE" | awk '{print $1}')
REMOTE_SHA512=$(sha512sum "$ARCHIVE" | awk '{print $1}')

# Kirim kembali data ringkasan ke stdout pembungkus
echo "TRIAGE_META|SIZE=${REMOTE_SIZE}|SHA256=${REMOTE_SHA256}|SHA512=${REMOTE_SHA512}|HOST=${HOSTNAME}|MAC=${MAC_DATA}"

# Simpan sebagai out.tar.gz untuk ditarik scp dan bersihkan direktori kerja
cp "$ARCHIVE" /dev/shm/out.tar.gz
chmod 644 /dev/shm/out.tar.gz
rm -rf "$TMP_DIR" "$ARCHIVE"
REMOTE_EOF
)

# Jalankan eksekusi remote via Bastion ProxyJump
echo "Menjalankan skrip kolektor live triage di ${TARGET_NAME} via Bastion ProxyJump..."

# Kita buat direktori sementara di host untuk menangkap output
HOST_TMP_DIR=$(mktemp -d /tmp/triage_fetch_XXXXXX)
trap 'rm -rf "$HOST_TMP_DIR"' EXIT

ssh $SSH_OPTS -J "${SECOPS_USER}@${SECOPS_IP}" "dcadmin@${TARGET_IP}" \
  "$(printf 'bash -s -- %q %q %q' "$TARGET_NAME" "$EVIDENCE_ID" "$START_TIME")" > "${HOST_TMP_DIR}/raw_output.txt" << EOF
$REMOTE_SCRIPT
EOF

# Ekstrak baris TRIAGE_META
META_LINE=$(grep "^TRIAGE_META" "${HOST_TMP_DIR}/raw_output.txt" || true)
if [ -z "$META_LINE" ]; then
  echo "Error: Gagal mengekstrak metadata triage dari ${TARGET_NAME}." >&2
  cat "${HOST_TMP_DIR}/raw_output.txt" >&2
  exit 1
fi

IFS='|' read -r _ SIZE_PAIR SHA256_PAIR SHA512_PAIR HOST_PAIR MAC_PAIR <<< "$META_LINE"
REMOTE_SIZE="${SIZE_PAIR#*=}"
REMOTE_SHA256="${SHA256_PAIR#*=}"
REMOTE_SHA512="${SHA512_PAIR#*=}"
REMOTE_HOST="${HOST_PAIR#*=}"
REMOTE_MAC="${MAC_PAIR#*=}"

# Ambil berkas tarball out.tar.gz via scp ProxyJump
echo "Mengambil arsip bukti terkompresi dari ${TARGET_NAME}..."
scp $SSH_OPTS -o "ProxyJump=${SECOPS_USER}@${SECOPS_IP}" "dcadmin@${TARGET_IP}:/dev/shm/out.tar.gz" "${LOCAL_TAR}" >/dev/null

# Hapus out.tar.gz dari target host untuk menjaga kebersihan sistem korban
ssh $SSH_OPTS -J "${SECOPS_USER}@${SECOPS_IP}" "dcadmin@${TARGET_IP}" "rm -f /dev/shm/out.tar.gz" >/dev/null

# Kunci izin berkas bukti menjadi read-only (0440)
chmod 440 "${LOCAL_TAR}"

# Verifikasi integritas hash lokal
LOCAL_SHA256=$(sha256sum "${LOCAL_TAR}" | awk '{print $1}')
LOCAL_SHA512=$(sha512sum "${LOCAL_TAR}" | awk '{print $1}')
LOCAL_SIZE=$(stat -c %s "${LOCAL_TAR}")

if [ "$LOCAL_SHA256" != "$REMOTE_SHA256" ]; then
  echo "CRITICAL ERROR: Hash SHA-256 lokal ($LOCAL_SHA256) TIDAK COCOK dengan remote ($REMOTE_SHA256)!" >&2
  echo "Integritas bukti terkorupsi saat transmisi." >&2
  exit 1
fi

END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
END_EPOCH=$(date +%s.%N)
DURATION_SEC=$(echo "$END_EPOCH - $START_EPOCH" | bc -l)

# Bangkitkan Berkas Metadata JSON ISO/IEC 27037
cat > "${LOCAL_META}" << META_EOF
{
  "evidence_id": "${EVIDENCE_ID}",
  "case_id": "${CASE_ID}",
  "evidence_type": "host_triage_tarball",
  "description": "Paket kompresi artefak volatil & non-volatil korban (soket, proc, auth.log, bash history)",
  "source_node": {
    "hostname": "${REMOTE_HOST}",
    "role": "${TARGET_NAME}",
    "ip_address": "${TARGET_IP}",
    "mac_address": "${REMOTE_MAC}"
  },
  "acquisition": {
    "tool_name": "triage-host-evidence.sh",
    "tool_version": "1.0",
    "method": "Live Host Triage via Bastion ProxyJump (RFC 3227 Order of Volatility)",
    "execution_path": "In-Memory (/dev/shm)",
    "start_time_utc": "${START_TIME}",
    "end_time_utc": "${END_TIME}",
    "duration_seconds": ${DURATION_SEC},
    "collector_name": "Natanael (Lead Incident Responder)"
  },
  "file_properties": {
    "filename": "${OUTPUT_NAME}",
    "relative_path": "dfir/evidence/host/${OUTPUT_NAME}",
    "file_size_bytes": ${LOCAL_SIZE},
    "mime_type": "application/gzip",
    "file_permissions": "0440"
  },
  "cryptographic_hashes": {
    "sha256": "${LOCAL_SHA256}",
    "sha512": "${LOCAL_SHA512}",
    "hash_timestamp_utc": "${END_TIME}",
    "integrity_verification": "PASSED (100% Match with Target Source)"
  },
  "volatility_order_adherence": [
    "Tier 1: Active Network Connections & Sockets (ss -tulpn, ss -tanpo, ip neigh, ip route)",
    "Tier 2: Process States & Execution Memory Context (ps auxwwfe, pstree, /proc/PID/cmdline)",
    "Tier 3: Open File Descriptors & Memory Maps (lsof -n -P, /proc/PID/fd)",
    "Tier 4: Active User Sessions & Credential Traces (who, w, last, /tmp/ssh-*)",
    "Tier 5: System Authentication Logs & Audit Trails (/var/log/auth.log, journalctl ssh)",
    "Tier 6: Shell Histories & Persistence (.bash_history, crontabs, systemd units)",
    "Tier 7: File Modifications in Past 60 Minutes (find -mmin -60 -ls)"
  ]
}
META_EOF

DURATION_FORMATTED=$(printf "%.2f" "$DURATION_SEC")

echo "=========================================================="
echo "Live Host Triage Berhasil Diamankan (ISO 27037 Compliant)"
echo "=========================================================="
echo "Evidence ID : ${EVIDENCE_ID}"
echo "Source Host : ${REMOTE_HOST} (${TARGET_IP})"
echo "Berkas Bukti: ${LOCAL_TAR}"
echo "Ukuran      : ${LOCAL_SIZE} bytes"
echo "Durasi      : ${DURATION_FORMATTED} detik"
echo "SHA-256     : ${LOCAL_SHA256}"
echo "Integritas  : VERIFIED MATCH (100%)"
echo "Metadata    : ${LOCAL_META}"
echo "Hak Akses   : Read-Only (0440)"
echo "=========================================================="
