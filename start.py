#!/usr/bin/env python3
"""Cross-platform launcher for the PromptSiege UI."""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
from pathlib import Path

from install import venv_python

ROOT = Path(__file__).resolve().parent


def port_arg(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {value}") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port: {value}")
    return port


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as s:
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Start the PromptSiege harness.")
    ap.add_argument("-p", "--port", type=port_arg, default=8000, help="port to serve on (default: 8000)")
    args = ap.parse_args(argv)

    venv_py = venv_python(ROOT)
    py = str(venv_py) if venv_py.exists() else sys.executable

    if port_in_use(args.port):
        print(f"port {args.port} is already in use. Stop that process or pass --port <N>.", file=sys.stderr)
        return 1

    subprocess.run([py, "-m", "ui.banner"], cwd=ROOT)  # cosmetic, ignore failures

    print(f"starting harness at http://127.0.0.1:{args.port}/")
    return subprocess.run(
        [py, "-m", "uvicorn", "ui.server:app", "--host", "127.0.0.1", "--port", str(args.port)],
        cwd=ROOT,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
