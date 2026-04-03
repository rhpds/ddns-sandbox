#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/bind-key-api}"
ENV_DIR="${ENV_DIR:-/etc/bind-key-api}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

systemctl disable --now bind-key-api.service 2>/dev/null || true
rm -f /etc/systemd/system/bind-key-api.service
systemctl daemon-reload

echo "Stopped and removed systemd unit."
echo "Remove ${INSTALL_ROOT} and ${ENV_DIR} manually if desired:"
echo "  rm -rf ${INSTALL_ROOT}"
echo "  rm -rf ${ENV_DIR}"
