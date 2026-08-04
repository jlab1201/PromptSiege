#!/usr/bin/env bash
# Thin shim: clone if needed, then hand off to install.py (the real installer).
set -euo pipefail

if [[ -f ui/server.py && -f requirements.txt ]]; then
  echo "existing PromptSiege checkout detected, installing in place"
else
  echo "cloning PromptSiege..."
  git clone https://github.com/jlab1201/PromptSiege.git
  cd PromptSiege
  export PROMPTSIEGE_CLONED=1
fi

PY=""
for c in python3 python; do
  command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }
done
[[ -n "$PY" ]] || { echo "python3 not found. Install Python 3.12+ and re-run." >&2; exit 1; }

# `curl ... | bash` leaves stdin pointing at the pipe, so hand the installer a
# real terminal when there is one — otherwise it skips the API key prompt.
# -r /dev/tty is not enough: the node can exist while no terminal is attached,
# so actually try to open it.
if (exec 3< /dev/tty) 2>/dev/null; then
  exec "$PY" install.py "$@" < /dev/tty
fi
exec "$PY" install.py "$@"
