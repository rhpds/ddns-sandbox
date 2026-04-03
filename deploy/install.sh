#!/usr/bin/env bash
# Install bind-key-api under /opt and register systemd service.
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/bind-key-api}"
ENV_DIR="${ENV_DIR:-/etc/bind-key-api}"
ENV_FILE="${ENV_DIR}/bind-key-api.env"
SYSTEMD_UNIT="/etc/systemd/system/bind-key-api.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

die() { echo "error: $*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

require_cmd install
require_cmd systemctl
require_cmd rsync

if [[ "$(id -u)" -ne 0 ]]; then
  die "run as root (sudo ./install.sh)"
fi

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if command -v python3.12 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.12)"
  elif [[ -x /opt/cpython-3.12/bin/python3.12 ]]; then
    PYTHON_BIN=/opt/cpython-3.12/bin/python3.12
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    die "no python3 found; set PYTHON_BIN=/path/to/python3.11+"
  fi
fi

echo "Using Python: ${PYTHON_BIN}"
"${PYTHON_BIN}" -c 'import sys; assert sys.version_info[:2] >= (3, 11), "Python 3.11+ required"' \
  || die "Python 3.11+ required"

echo "Installing application to ${INSTALL_ROOT}"
install -d -m 0755 "${INSTALL_ROOT}"
rsync -a --delete \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.git' \
  --exclude '.pytest_cache' \
  --exclude '*.egg-info' \
  "${PROJECT_ROOT}/" "${INSTALL_ROOT}/"

echo "Creating virtualenv"
if [[ ! -d "${INSTALL_ROOT}/.venv" ]]; then
  "${PYTHON_BIN}" -m venv "${INSTALL_ROOT}/.venv"
fi
# shellcheck source=/dev/null
source "${INSTALL_ROOT}/.venv/bin/activate"
pip install -q -U pip
pip install -q -e "${INSTALL_ROOT}"

install -m 0755 "${SCRIPT_DIR}/run.sh" "${INSTALL_ROOT}/run.sh"

echo "Installing systemd unit"
sed -e "s|__INSTALL_ROOT__|${INSTALL_ROOT}|g" -e "s|__ENV_FILE__|${ENV_FILE}|g" \
  "${SCRIPT_DIR}/systemd/bind-key-api.service" > "${SYSTEMD_UNIT}"
chmod 0644 "${SYSTEMD_UNIT}"

install -d -m 0700 "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
  install -m 0600 "${SCRIPT_DIR}/bind-key-api.env.example" "${ENV_FILE}"
  echo ""
  echo "Created ${ENV_FILE} — edit BIND_KEY_API_AUTH_TOKEN (and options), then:"
  echo "  systemctl daemon-reload && systemctl enable --now bind-key-api"
  echo ""
else
  echo "Keeping existing ${ENV_FILE}"
fi

systemctl daemon-reload
systemctl enable bind-key-api.service

echo ""
echo "Done. Commands:"
echo "  sudo systemctl start bind-key-api     # if not already running"
echo "  sudo systemctl status bind-key-api"
echo "  sudo journalctl -u bind-key-api -f"
echo ""
