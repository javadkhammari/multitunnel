#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m py_compile "$ROOT/multitunnel.py"
bash -n "$ROOT/install.sh"
python3 -m unittest discover -s "$ROOT/tests" -v
printf '%s\n' "All static, unit and CLI integration tests passed"
