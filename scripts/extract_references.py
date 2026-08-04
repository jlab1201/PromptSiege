"""
One-time migration: pull source URLs and attribution lines out of prompt
`text` and into a dedicated `reference` field.

Conservative by design — under-extracting is preferred to corrupting payloads.

Usage:
    python scripts/extract_references.py --dry-run       # preview only
    python scripts/extract_references.py                 # apply, with backup
    python scripts/extract_references.py --limit 20      # only process N entries
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "prompts.json"

ATTR_RE = re.compile(
    r"^\s*(?:by|credit|credits|source|author|created\s+by)\s*[:\-]?\s+(\S[^\n]{0,49})\s*$",
    re.IGNORECASE,
)
# Words that disqualify a string as a real attribution — these are
# sentence/payload markers, not author bylines.
_SENTENCE_TOKENS = re.compile(
    r"\b(?:the|is|are|was|were|you|your|will|can|has|have|had|do|does|did|"
    r"not|and|but|or|if|then|please|must|should|consent|generate|prompt)\b",
    re.IGNORECASE,
)


def _looks_like_attribution(value: str) -> bool:
    """True if `value` looks like a real byline (name/handle), not a sentence."""
    if not value:
        return False
    if "," in value:
        return False
    if _SENTENCE_TOKENS.search(value):
        return False
    return True
HANDLE_RE = re.compile(r"^\s*@([A-Za-z0-9_]{2,40})\s*$")
URL_ONLY_RE = re.compile(r"^\s*(https?://\S+)\s*$")

KNOWN_HOSTS = (
    "github.com",
    "githubusercontent.com",
    "imgur.com",
    "x.com",
    "twitter.com",
    "reddit.com",
    "youtube.com",
    "youtu.be",
    "discord.gg",
    "discord.com",
)
_hosts_alt = "|".join(re.escape(h) for h in KNOWN_HOSTS)
MD_LINK_RE = re.compile(
    rf"\[(?P<label>[^\]]{{1,80}})\]\((?P<url>https?://(?:{_hosts_alt})/[^\s)]+)\)"
)


def _looks_like_code_fence(line: str) -> bool:
    return line.lstrip().startswith("```")


def _in_code_block(lines: list[str], idx: int) -> bool:
    fences = 0
    for i in range(idx):
        if _looks_like_code_fence(lines[i]):
            fences += 1
    return fences % 2 == 1


def extract(text: str) -> tuple[str | None, str, str]:
    """Return (reference, new_text, rule). rule is "" if no change."""
    if not text:
        return None, text, ""

    raw_lines = text.split("\n")
    n = len(raw_lines)

    # Trailing attribution line (last non-empty line).
    last_idx = None
    for i in range(n - 1, -1, -1):
        if raw_lines[i].strip():
            last_idx = i
            break
    if last_idx is not None and not _in_code_block(raw_lines, last_idx):
        line = raw_lines[last_idx]
        m = ATTR_RE.match(line)
        if m and _looks_like_attribution(m.group(1).strip()):
            return m.group(1).strip(), "\n".join(raw_lines[:last_idx]).rstrip(), "trailing-attribution"
        m = URL_ONLY_RE.match(line)
        if m and any(h in m.group(1) for h in KNOWN_HOSTS):
            return m.group(1).strip(), "\n".join(raw_lines[:last_idx]).rstrip(), "trailing-url"
        m = HANDLE_RE.match(line)
        if m:
            return "@" + m.group(1), "\n".join(raw_lines[:last_idx]).rstrip(), "trailing-handle"

    # Leading attribution line (first non-empty line).
    first_idx = None
    for i in range(n):
        if raw_lines[i].strip():
            first_idx = i
            break
    if first_idx is not None and not _in_code_block(raw_lines, first_idx):
        line = raw_lines[first_idx]
        m = ATTR_RE.match(line)
        if m and _looks_like_attribution(m.group(1).strip()):
            return m.group(1).strip(), "\n".join(raw_lines[first_idx + 1:]).lstrip(), "leading-attribution"

    # Markdown link to known host in last 3 non-empty lines (extract URL, leave label inline).
    tail_lines = [(i, raw_lines[i]) for i in range(n) if raw_lines[i].strip()][-3:]
    for i, line in tail_lines:
        if _in_code_block(raw_lines, i):
            continue
        m = MD_LINK_RE.search(line)
        if m:
            return m.group("url"), text, "markdown-link"

    return None, text, ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="preview only, no write")
    ap.add_argument("--limit", type=int, default=0, help="stop after N changes (0 = all)")
    ap.add_argument(
        "--prompts",
        type=Path,
        default=PROMPTS,
        help="path to prompts.json (default: project root)",
    )
    args = ap.parse_args()

    if not args.prompts.exists():
        print(f"error: {args.prompts} not found", file=sys.stderr)
        return 1

    data = json.loads(args.prompts.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        print("error: prompts.json must be a JSON array", file=sys.stderr)
        return 1

    changes: list[tuple[str, str, str, str]] = []  # (id, rule, reference, snippet)
    rule_counts: dict[str, int] = {}

    for entry in data:
        if entry.get("reference"):
            continue  # idempotent: skip already-extracted
        ref, new_text, rule = extract(entry.get("text", ""))
        if not ref or not rule:
            continue
        if not new_text.strip():
            # never reduce text to empty
            continue
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        snippet = ref[:80]
        changes.append((entry["id"], rule, ref, snippet))
        if not args.dry_run:
            entry["reference"] = ref
            entry["text"] = new_text
        if args.limit and len(changes) >= args.limit:
            break

    print(f"scanned: {len(data)} entries")
    print(f"would modify: {len(changes)}" if args.dry_run else f"modified: {len(changes)}")
    if rule_counts:
        print("by rule:")
        for rule, n in sorted(rule_counts.items(), key=lambda kv: -kv[1]):
            print(f"  {rule}: {n}")

    print("\nsample:")
    for cid, rule, _, snip in changes[:12]:
        print(f"  {cid}  [{rule}]  → {snip!r}")

    if args.dry_run:
        print("\ndry-run: no files written.")
        return 0

    if not changes:
        print("nothing to do.")
        return 0

    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = args.prompts.with_suffix(args.prompts.suffix + f".bak-{stamp}")
    shutil.copy2(args.prompts, backup)
    print(f"\nbackup: {backup.name}")

    tmp = args.prompts.with_suffix(args.prompts.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=None), encoding="utf-8")
    tmp.replace(args.prompts)
    print(f"wrote: {args.prompts.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
