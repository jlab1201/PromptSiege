#!/usr/bin/env bash
# Thin shim around start.py.
set -euo pipefail

cd "$(dirname "$0")"

if [[ -x venv/bin/python ]]; then
  PY=venv/bin/python
else
  PY=python3
fi

exec "$PY" start.py "$@"
