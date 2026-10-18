#!/bin/bash
# Wrapper shell script for extract-pcap-artifacts.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/extract-pcap-artifacts.py" "$@"
