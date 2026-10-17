#!/usr/bin/env bash
# dfir/evidence/verify-evidence-integrity.sh
# Wrapper verifikasi integritas bukti digital & kepatuhan Chain of Custody ISO/IEC 27037:2012
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/verify-evidence-integrity.py" "$@"
