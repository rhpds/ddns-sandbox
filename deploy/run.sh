#!/usr/bin/env bash
# Invoked by systemd; inherits EnvironmentFile (UVICORN_*, BIND_KEY_API_*).
set -euo pipefail
cd "$(dirname "$0")"
exec .venv/bin/uvicorn bind_key_api.main:app \
  --host "${UVICORN_HOST:-127.0.0.1}" \
  --port "${UVICORN_PORT:-8080}" \
  --workers 1
