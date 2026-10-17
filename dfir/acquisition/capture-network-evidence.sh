#!/usr/bin/env bash
# dfir/acquisition/capture-network-evidence.sh
# Skrip Akuisisi Bukti Forensik Jaringan Mentah (Raw PCAP)
# Berbasis Standar ISO/IEC 27037:2012 & Order of Volatility RFC 3227
set -euo pipefail

SECOPS_IP="192.168.122.81"
SECOPS_USER="dcadmin"
SSH_KEY="${HOME}/.ssh/k8s-lab"
SSH_OPTS="-i ${SSH_KEY} -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VAULT_NET_DIR="${REPO_ROOT}/dfir/evidence/network"

mkdir -p "${VAULT_NET_DIR}"

# Nilai Default
CASE_ID="CASE-2026-DFIR-001"
EVIDENCE_ID="EVD-NET-$(date -u +%Y%m%d)-$(date -u +%H%M%S)"
OUTPUT_NAME=""
BPF_FILTER=""
DURATION=0
ACTION="run" # run | start | stop | status
STATE_FILE="/var/forensics/network/capture.state"

print_usage() {
  cat << EOF
Penggunaan: $0 [OPSI]

Opsi Mode Eksekusi:
  --duration <detik>    Durasi penangkapan paket terukur (sinkron).
  --start               Mulai penangkapan paket di latar belakang (asinkron).
  --stop                Hentikan penangkapan asinkron, hitung hash & tarik bukti.
  --status              Cek status penangkapan latar belakang yang sedang aktif.

Opsi Metadata Bukti:
  --case-id <ID>        ID Kasus DFIR (Default: CASE-2026-DFIR-001)
  --evidence-id <ID>    ID Bukti ISO 27037 unik (Default: EVD-NET-YYYYMMDD-HHMMSS)
  --output <nama_file>  Nama berkas PCAP (contoh: evd-net-s06-exfil.pcap)
  --filter <BPF>        Filter ekspresi Berkeley Packet Filter (contoh: "port 5432 or icmp")

Contoh:
  $0 --duration 10 --filter "port 8080 or port 5432" --output test-capture.pcap
  $0 --start --output s06-exfil.pcap --filter "port 8000 or port 5432"
  $0 --stop
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      DURATION="$2"
      ACTION="run"
      shift 2
      ;;
    --start)
      ACTION="start"
      shift
      ;;
    --stop)
      ACTION="stop"
      shift
      ;;
    --status)
      ACTION="status"
      shift
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
    --filter)
      BPF_FILTER="$2"
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

# Menentukan apakah skrip berjalan lokal di secops atau di host
IS_LOCAL=false
if ip addr show 2>/dev/null | grep -q "192.168.122.81"; then
  IS_LOCAL=true
fi

# 1. ACTION: STATUS
if [ "$ACTION" = "status" ]; then
  echo "=== Status Perekaman Bukti Jaringan (secops: br-sensor) ==="
  if [ "$IS_LOCAL" = true ]; then
    bash -s "$STATE_FILE" << 'EOF'
      STATE_FILE="$1"
      if [ -f "$STATE_FILE" ]; then
        cat "$STATE_FILE"
        PID=$(grep '^PID=' "$STATE_FILE" | cut -d= -f2)
        if ps -p "$PID" >/dev/null 2>&1; then
          echo "Status: RUNNING (PID $PID)"
        else
          echo "Status: STOPPED / STALE"
        fi
      else
        echo "Tidak ada proses penangkapan jaringan yang aktif."
      fi
EOF
  else
    ssh $SSH_OPTS "${SECOPS_USER}@${SECOPS_IP}" "$(printf 'bash -s -- %q' "$STATE_FILE")" << 'EOF'
      STATE_FILE="$1"
      if [ -f "$STATE_FILE" ]; then
        cat "$STATE_FILE"
        PID=$(grep '^PID=' "$STATE_FILE" | cut -d= -f2)
        if ps -p "$PID" >/dev/null 2>&1; then
          echo "Status: RUNNING (PID $PID)"
        else
          echo "Status: STOPPED / STALE"
        fi
      else
        echo "Tidak ada proses penangkapan jaringan yang aktif."
      fi
EOF
  fi
  exit 0
fi

# 2. ACTION: STOP
if [ "$ACTION" = "stop" ]; then
  echo "=== Menghentikan Penangkapan Bukti Jaringan ==="
  
  if [ "$IS_LOCAL" = true ]; then
    STOP_OUTPUT=$(bash -s "$STATE_FILE" << 'EOF'
      STATE_FILE="$1"
      if [ ! -f "$STATE_FILE" ]; then
        echo "ERROR: Berkas state $STATE_FILE tidak ditemukan. Tidak ada penangkapan aktif."
        exit 1
      fi
      source "$STATE_FILE"
      if ps -p "$PID" >/dev/null 2>&1; then
        sudo kill -2 "$PID" 2>/dev/null || sudo kill -15 "$PID" 2>/dev/null
        sleep 1
      fi
      sudo chown dcadmin:dcadmin "$PCAP_FILE" 2>/dev/null || true
      FILE_SIZE=$(sudo stat -c %s "$PCAP_FILE" 2>/dev/null || echo 0)
      SHA256=$(sudo sha256sum "$PCAP_FILE" | awk '{print $1}')
      SHA512=$(sudo sha512sum "$PCAP_FILE" | awk '{print $1}')
      sudo chmod 440 "$PCAP_FILE"
      
      echo "STOP_OK|END_TIME=${END_TIME}|FILE_SIZE=${FILE_SIZE}|SHA256=${SHA256}|SHA512=${SHA512}|PCAP_FILE=${PCAP_FILE}|EVD_ID=${EVD_ID}|CASE_ID=${CASE_ID}|START_TIME=${START_TIME}|BPF=${BPF}"
      rm -f "$STATE_FILE"
EOF
    )
  else
    STOP_OUTPUT=$(ssh $SSH_OPTS "${SECOPS_USER}@${SECOPS_IP}" "$(printf 'bash -s -- %q' "$STATE_FILE")" << 'EOF'
      STATE_FILE="$1"
      if [ ! -f "$STATE_FILE" ]; then
        echo "ERROR: Berkas state $STATE_FILE tidak ditemukan. Tidak ada penangkapan aktif."
        exit 1
      fi
      source "$STATE_FILE"
      if ps -p "$PID" >/dev/null 2>&1; then
        sudo kill -2 "$PID" 2>/dev/null || sudo kill -15 "$PID" 2>/dev/null
        sleep 1
      fi
      END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
      sudo chown dcadmin:dcadmin "$PCAP_FILE" 2>/dev/null || true
      FILE_SIZE=$(sudo stat -c %s "$PCAP_FILE" 2>/dev/null || echo 0)
      SHA256=$(sudo sha256sum "$PCAP_FILE" | awk '{print $1}')
      SHA512=$(sudo sha512sum "$PCAP_FILE" | awk '{print $1}')
      sudo chmod 440 "$PCAP_FILE"
      
      echo "STOP_OK|END_TIME=${END_TIME}|FILE_SIZE=${FILE_SIZE}|SHA256=${SHA256}|SHA512=${SHA512}|PCAP_FILE=${PCAP_FILE}|EVD_ID=${EVD_ID}|CASE_ID=${CASE_ID}|START_TIME=${START_TIME}|BPF=${BPF}"
      rm -f "$STATE_FILE"
EOF
    )
  fi

  if [[ "$STOP_OUTPUT" != *"STOP_OK"* ]]; then
    echo "$STOP_OUTPUT" >&2
    exit 1
  fi

  DATA_LINE=$(echo "$STOP_OUTPUT" | grep "^STOP_OK")
  IFS='|' read -r _ END_PAIR SIZE_PAIR SHA256_PAIR SHA512_PAIR PCAP_PAIR EVD_PAIR CASE_PAIR START_PAIR BPF_PAIR <<< "$DATA_LINE"
  
  END_TIME="${END_PAIR#*=}"
  FILE_SIZE="${SIZE_PAIR#*=}"
  SHA256="${SHA256_PAIR#*=}"
  SHA512="${SHA512_PAIR#*=}"
  REMOTE_PCAP="${PCAP_PAIR#*=}"
  EVD_ID="${EVD_PAIR#*=}"
  CASE_ID="${CASE_PAIR#*=}"
  START_TIME="${START_PAIR#*=}"
  BPF="${BPF_PAIR#*=}"
  BASE_NAME="$(basename "${REMOTE_PCAP}")"

  LOCAL_PCAP="${VAULT_NET_DIR}/${BASE_NAME}"
  LOCAL_META="${VAULT_NET_DIR}/${BASE_NAME%.pcap}.meta.json"
  rm -f "${LOCAL_PCAP}" "${LOCAL_META}"

  if [ "$IS_LOCAL" = false ]; then
    echo "Menyalin berkas bukti dari secops ke local vault..."
    scp $SSH_OPTS "${SECOPS_USER}@${SECOPS_IP}:${REMOTE_PCAP}" "${LOCAL_PCAP}" >/dev/null
  else
    cp "${REMOTE_PCAP}" "${LOCAL_PCAP}"
  fi

  chmod 440 "${LOCAL_PCAP}"

  cat > "${LOCAL_META}" << META_EOF
{
  "evidence_id": "${EVD_ID}",
  "case_id": "${CASE_ID}",
  "evidence_type": "network_pcap",
  "description": "Raw packet capture pada sensor mirror port interface br-sensor",
  "source_node": {
    "hostname": "secops",
    "interface": "br-sensor",
    "ip_management": "192.168.122.81",
    "ip_data": "10.10.40.11"
  },
  "acquisition": {
    "tool_name": "tcpdump",
    "tool_version": "4.99.4",
    "filter_applied": "${BPF}",
    "start_time_utc": "${START_TIME}",
    "end_time_utc": "${END_TIME}",
    "collector_name": "Natanael (Incident Responder)"
  },
  "file_properties": {
    "filename": "${BASE_NAME}",
    "relative_path": "dfir/evidence/network/${BASE_NAME}",
    "file_size_bytes": ${FILE_SIZE},
    "mime_type": "application/vnd.tcpdump.pcap",
    "file_permissions": "0440"
  },
  "cryptographic_hashes": {
    "sha256": "${SHA256}",
    "sha512": "${SHA512}",
    "hash_timestamp_utc": "${END_TIME}"
  }
}
META_EOF

  echo "=========================================================="
  echo "Bukti Jaringan Berhasil Diamankan (ISO/IEC 27037 Compliant)"
  echo "=========================================================="
  echo "Evidence ID : ${EVD_ID}"
  echo "Berkas PCAP : ${LOCAL_PCAP}"
  echo "Ukuran      : ${FILE_SIZE} bytes"
  echo "SHA-256     : ${SHA256}"
  echo "Metadata    : ${LOCAL_META}"
  echo "Hak Akses   : Read-Only (0440)"
  echo "=========================================================="
  exit 0
fi

# 3. ACTION: START atau RUN
if [ -z "$OUTPUT_NAME" ]; then
  OUTPUT_NAME="${EVIDENCE_ID}.pcap"
fi
[[ "$OUTPUT_NAME" != *.pcap ]] && OUTPUT_NAME="${OUTPUT_NAME}.pcap"

REMOTE_PCAP="/var/forensics/network/${OUTPUT_NAME}"
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")

echo "=========================================================="
echo "Memulai Akuisisi Bukti Jaringan Mentah (br-sensor)"
echo "=========================================================="
echo "Case ID     : ${CASE_ID}"
echo "Evidence ID : ${EVIDENCE_ID}"
echo "Interface   : br-sensor (secops)"
echo "Target File : ${REMOTE_PCAP}"
echo "BPF Filter  : ${BPF_FILTER:-"(semua paket)"}"
echo "Waktu Mulai : ${START_TIME}"
echo "=========================================================="

if [ "$ACTION" = "start" ]; then
  if [ "$IS_LOCAL" = true ]; then
    bash -s "$REMOTE_PCAP" "$BPF_FILTER" "$EVIDENCE_ID" "$CASE_ID" "$START_TIME" "$STATE_FILE" << 'EOF'
      REMOTE_PCAP="$1"
      BPF="$2"
      EVD_ID="$3"
      CASE_ID="$4"
      START_TIME="$5"
      STATE_FILE="$6"

      sudo mkdir -p /var/forensics/network
      sudo chmod 777 /var/forensics/network
      sudo pkill -f 'tcpdump -i br-sensor' 2>/dev/null || true
      sudo nohup tcpdump -i br-sensor -s 0 -w "$REMOTE_PCAP" -U $BPF < /dev/null > /dev/null 2>&1 &
      PID=$!
      cat > "$STATE_FILE" << STATE
PID=$PID
PCAP_FILE="$REMOTE_PCAP"
EVD_ID="$EVD_ID"
CASE_ID="$CASE_ID"
START_TIME="$START_TIME"
BPF="$BPF"
STATE
      echo "Started background capture with PID $PID"
EOF
  else
    ssh $SSH_OPTS "${SECOPS_USER}@${SECOPS_IP}" "$(printf 'bash -s -- %q %q %q %q %q %q' "$REMOTE_PCAP" "$BPF_FILTER" "$EVIDENCE_ID" "$CASE_ID" "$START_TIME" "$STATE_FILE")" << 'EOF'
      REMOTE_PCAP="$1"
      BPF="$2"
      EVD_ID="$3"
      CASE_ID="$4"
      START_TIME="$5"
      STATE_FILE="$6"

      sudo mkdir -p /var/forensics/network
      sudo chmod 777 /var/forensics/network
      sudo pkill -f 'tcpdump -i br-sensor' 2>/dev/null || true
      sudo nohup tcpdump -i br-sensor -s 0 -w "$REMOTE_PCAP" -U $BPF < /dev/null > /dev/null 2>&1 &
      PID=$!
      cat > "$STATE_FILE" << STATE
PID=$PID
PCAP_FILE="$REMOTE_PCAP"
EVD_ID="$EVD_ID"
CASE_ID="$CASE_ID"
START_TIME="$START_TIME"
BPF="$BPF"
STATE
      echo "Started background capture with PID $PID"
EOF
  fi
  echo "[OK] Penangkapan berjalan di latar belakang. Jalankan '$0 --stop' untuk menyelesaikan."
  exit 0
fi

if [ "$ACTION" = "run" ]; then
  if [ "$DURATION" -le 0 ]; then
    DURATION=10
  fi
  echo "Merekam selama ${DURATION} detik..."

  if [ "$IS_LOCAL" = true ]; then
    RUN_OUTPUT=$(bash -s "$REMOTE_PCAP" "$BPF_FILTER" "$DURATION" << 'EOF'
      REMOTE_PCAP="$1"
      BPF="$2"
      DURATION="$3"

      sudo mkdir -p /var/forensics/network
      sudo chmod 777 /var/forensics/network
      sudo timeout -s 2 "$DURATION" tcpdump -i br-sensor -s 0 -w "$REMOTE_PCAP" -U $BPF < /dev/null > /dev/null 2>&1 || true
      END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
      sudo chown dcadmin:dcadmin "$REMOTE_PCAP" 2>/dev/null || true
      FILE_SIZE=$(sudo stat -c %s "$REMOTE_PCAP" 2>/dev/null || echo 0)
      SHA256=$(sudo sha256sum "$REMOTE_PCAP" | awk '{print $1}')
      SHA512=$(sudo sha512sum "$REMOTE_PCAP" | awk '{print $1}')
      sudo chmod 440 "$REMOTE_PCAP"
      echo "RUN_OK|${END_TIME}|${FILE_SIZE}|${SHA256}|${SHA512}"
EOF
    )
  else
    RUN_OUTPUT=$(ssh $SSH_OPTS "${SECOPS_USER}@${SECOPS_IP}" "$(printf 'bash -s -- %q %q %q' "$REMOTE_PCAP" "$BPF_FILTER" "$DURATION")" << 'EOF'
      REMOTE_PCAP="$1"
      BPF="$2"
      DURATION="$3"

      sudo mkdir -p /var/forensics/network
      sudo chmod 777 /var/forensics/network
      sudo timeout -s 2 "$DURATION" tcpdump -i br-sensor -s 0 -w "$REMOTE_PCAP" -U $BPF < /dev/null > /dev/null 2>&1 || true
      END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
      sudo chown dcadmin:dcadmin "$REMOTE_PCAP" 2>/dev/null || true
      FILE_SIZE=$(sudo stat -c %s "$REMOTE_PCAP" 2>/dev/null || echo 0)
      SHA256=$(sudo sha256sum "$REMOTE_PCAP" | awk '{print $1}')
      SHA512=$(sudo sha512sum "$REMOTE_PCAP" | awk '{print $1}')
      sudo chmod 440 "$REMOTE_PCAP"
      echo "RUN_OK|${END_TIME}|${FILE_SIZE}|${SHA256}|${SHA512}"
EOF
    )
  fi

  RES_LINE=$(echo "$RUN_OUTPUT" | grep "^RUN_OK" || true)
  if [ -z "$RES_LINE" ]; then
    echo "Error saat menjalankan tcpdump di secops: $RUN_OUTPUT" >&2
    exit 1
  fi

  IFS='|' read -r _ END_TIME FILE_SIZE SHA256 SHA512 <<< "$RES_LINE"

  LOCAL_PCAP="${VAULT_NET_DIR}/${OUTPUT_NAME}"
  LOCAL_META="${VAULT_NET_DIR}/${OUTPUT_NAME%.pcap}.meta.json"
  rm -f "${LOCAL_PCAP}" "${LOCAL_META}"

  if [ "$IS_LOCAL" = false ]; then
    scp $SSH_OPTS "${SECOPS_USER}@${SECOPS_IP}:${REMOTE_PCAP}" "${LOCAL_PCAP}" >/dev/null
  else
    cp "${REMOTE_PCAP}" "${LOCAL_PCAP}"
  fi
  chmod 440 "${LOCAL_PCAP}"

  cat > "${LOCAL_META}" << META_EOF
{
  "evidence_id": "${EVIDENCE_ID}",
  "case_id": "${CASE_ID}",
  "evidence_type": "network_pcap",
  "description": "Raw packet capture pada sensor mirror port interface br-sensor",
  "source_node": {
    "hostname": "secops",
    "interface": "br-sensor",
    "ip_management": "192.168.122.81",
    "ip_data": "10.10.40.11"
  },
  "acquisition": {
    "tool_name": "tcpdump",
    "tool_version": "4.99.4",
    "filter_applied": "${BPF_FILTER}",
    "start_time_utc": "${START_TIME}",
    "end_time_utc": "${END_TIME}",
    "duration_seconds": ${DURATION},
    "collector_name": "Natanael (Incident Responder)"
  },
  "file_properties": {
    "filename": "${OUTPUT_NAME}",
    "relative_path": "dfir/evidence/network/${OUTPUT_NAME}",
    "file_size_bytes": ${FILE_SIZE},
    "mime_type": "application/vnd.tcpdump.pcap",
    "file_permissions": "0440"
  },
  "cryptographic_hashes": {
    "sha256": "${SHA256}",
    "sha512": "${SHA512}",
    "hash_timestamp_utc": "${END_TIME}"
  }
}
META_EOF

  echo "=========================================================="
  echo "Bukti Jaringan Berhasil Diamankan (ISO/IEC 27037 Compliant)"
  echo "=========================================================="
  echo "Evidence ID : ${EVIDENCE_ID}"
  echo "Berkas PCAP : ${LOCAL_PCAP}"
  echo "Ukuran      : ${FILE_SIZE} bytes"
  echo "SHA-256     : ${SHA256}"
  echo "Metadata    : ${LOCAL_META}"
  echo "Hak Akses   : Read-Only (0440)"
  echo "=========================================================="
fi
