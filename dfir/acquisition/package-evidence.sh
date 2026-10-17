#!/usr/bin/env bash
# dfir/acquisition/package-evidence.sh
# Wrapper eksekusi konsolidasi wadah barang bukti digital & generator manifest ISO/IEC 27037:2012
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/package-evidence.py" "$@"
