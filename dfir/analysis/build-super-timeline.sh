#!/bin/bash
# Wrapper shell script for build-super-timeline.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/build-super-timeline.py" "$@"
