#!/usr/bin/env python3
"""PromptSiege installer. Stdlib only, same behavior on Windows/macOS/Linux.

Safe to re-run on an existing checkout. Cloning is handled by the thin
install.sh / install.ps1 shims; by the time this runs, cwd is the checkout.
"""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 12)
ROOT = Path(__file__).resolve().parent

# Run in the venv interpreter so ui.judge's deps are importable.
SAVE_KEY = """
import os
from pathlib import Path
from ui.judge import save_api_key_to_env
save_api_key_to_env(Path(".env"), os.environ["PS_API_KEY"], os.environ["PS_PROVIDER"])
"""


def python_ok(version_info: tuple[int, ...] = sys.version_info) -> bool:
    """True if the running interpreter is new enough to install PromptSiege."""
    return tuple(version_info[:2]) >= MIN_PYTHON


def venv_python(root: Path, windows: bool | None = None) -> Path:
    """Path to the venv interpreter.

    Always invoke this as `<venv_python> -m pip` / `-m playwright`, never the
    generated venv pip/playwright console scripts. Those are wrappers with an
    absolute shebang baked in at creation time, so they break the moment the
    checkout is renamed or moved. The interpreter itself survives.
    """
    if windows is None:
        windows = os.name == "nt"
    return root / "venv" / ("Scripts" if windows else "bin") / ("python.exe" if windows else "python")


def configure_key(py: Path, no_config: bool) -> None:
    if no_config:
        print("skipping API key setup (--no-config/--yes). Configure later by editing .env.")
        return
    if not sys.stdin.isatty():
        print("no interactive terminal detected; skipping API key setup. Configure later by editing .env.")
        return

    print()
    provider = input("Set judge LLM API key now? (anthropic/openai/skip): ").strip().lower()
    if provider not in ("anthropic", "openai"):
        print("skipping API key setup.")
        return
    api_key = getpass.getpass(f"Enter {provider} API key (input hidden): ").strip()
    if not api_key:
        print("empty key entered, skipping.")
        return

    subprocess.run(
        [str(py), "-c", SAVE_KEY],
        check=True,
        cwd=ROOT,
        env={**os.environ, "PS_API_KEY": api_key, "PS_PROVIDER": provider},
    )
    print(f"saved {provider} key to .env")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Install PromptSiege into ./venv. Safe to re-run.")
    ap.add_argument("--skip-browser", action="store_true", help="skip `playwright install chromium`")
    ap.add_argument(
        "--yes",
        "--no-config",
        dest="no_config",
        action="store_true",
        help="non-interactive: skip the API key prompt",
    )
    args = ap.parse_args(argv)

    if not python_ok():
        print(
            f"Python {sys.version.split()[0]} found, but PromptSiege requires "
            f">={MIN_PYTHON[0]}.{MIN_PYTHON[1]}. Install it and re-run.",
            file=sys.stderr,
        )
        return 1

    py = venv_python(ROOT)
    if not py.exists():
        print("creating venv...")
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / "venv")], check=True)

    subprocess.run([str(py), "-m", "pip", "install", "-r", "requirements.txt"], check=True, cwd=ROOT)

    if args.skip_browser:
        print(
            "warning: --skip-browser set; browser-based scans and run.py will not work "
            f'until you run: "{py}" -m playwright install chromium'
        )
    else:
        subprocess.run([str(py), "-m", "playwright", "install", "chromium"], check=True, cwd=ROOT)

    # Never overwrite an existing .env — it may hold a real API key.
    if not (ROOT / ".env").exists() and (ROOT / ".env.example").exists():
        shutil.copyfile(ROOT / ".env.example", ROOT / ".env")

    subprocess.run([str(py), "-m", "ui.banner"], cwd=ROOT)  # cosmetic, ignore failures

    configure_key(py, args.no_config)

    start = "powershell -ExecutionPolicy Bypass -File .\\start.ps1" if os.name == "nt" else "./start.sh"
    # The one-liner runs in the parent dir, so the caller's shell is not inside
    # the clone the shim just made — tell them to cd, or start won't be found.
    if os.environ.get("PROMPTSIEGE_CLONED") == "1":
        start = f"cd PromptSiege && {start}"
    print()
    print(f"PromptSiege installed. Start it with: {start}")
    print("It will serve at http://127.0.0.1:8000/")
    print()
    print("WARNING: For authorized security testing only. Only scan systems you own")
    print("or have explicit written permission to test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
