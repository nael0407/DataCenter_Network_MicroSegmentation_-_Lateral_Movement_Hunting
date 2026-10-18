#!/bin/bash
# Wrapper shell script for parse-host-artifacts.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/parse-host-artifacts.py" "$@"
