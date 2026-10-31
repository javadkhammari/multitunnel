#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

for cmd in python3 install ln; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing command: $cmd" >&2; exit 1; }
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 -m py_compile "$SCRIPT_DIR/multitunnel.py"

install -d -m 0755 /opt/multitunnel-manager
if [[ -f /opt/multitunnel-manager/multitunnel.py ]]; then
  cp -a /opt/multitunnel-manager/multitunnel.py "/opt/multitunnel-manager/multitunnel.py.backup.$(date +%Y%m%d-%H%M%S)"
fi
install -m 0755 "$SCRIPT_DIR/multitunnel.py" /opt/multitunnel-manager/multitunnel.py
install -m 0644 "$SCRIPT_DIR/README.md" /opt/multitunnel-manager/README.md
install -m 0644 "$SCRIPT_DIR/CHANGELOG.md" /opt/multitunnel-manager/CHANGELOG.md
ln -sfn /opt/multitunnel-manager/multitunnel.py /usr/local/sbin/multitunnel

/usr/local/sbin/multitunnel --version
printf '%s\n' "Installed: /usr/local/sbin/multitunnel"
printf '%s\n' "Next: run multitunnel for the interactive menu, or use multitunnel init --role entry|relay|final"
