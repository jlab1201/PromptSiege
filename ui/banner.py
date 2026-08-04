"""Startup banner for PromptSiege. Stdlib-only — must run before deps are installed."""

__version__ = "0.1.0"

BANNER = rf"""
  ___                       _   ____  _
 |  _ \ _ __ ___  _ __ ___ | |_/ ___|(_) ___  __ _  ___
 | |_) | '__/ _ \| '_ ` _ \| __\___ \| |/ _ \/ _` |/ _ \
 |  __/| | | (_) | | | | | | |_ ___) | |  __/ (_| |  __/
 |_|   |_|  \___/|_| |_| |_|\__|____/|_|\___|\__, |\___|
                                              |___/
  Lay siege to your chatbot's defenses.
  v{__version__}

  WARNING: For authorized security testing only. Only scan systems
  you own or have explicit written permission to test.
"""

if __name__ == "__main__":
    print(BANNER)
