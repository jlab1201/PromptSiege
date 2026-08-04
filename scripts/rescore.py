#!/usr/bin/env python3
"""Re-score past runs with the current classifier.

Rows are graded at capture time, so a classifier fix never reaches results
already on disk. This recomputes `injection_outcome` / `run_health` / `read`
(and the meta sidecar's counters) from the stored prompt + response.

    python scripts/rescore.py            # preview changes
    python scripts/rescore.py --apply    # rewrite in place

`results/` is gitignored, so preview is the default. Stored judge verdicts win
over the replayed classifier — a regrade must not silently un-do rows the judge
already settled.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ui.judge import regrade_record, sync_meta_counters  # noqa: E402

RESULTS = Path(__file__).resolve().parent.parent / "results"


def main(apply: bool) -> int:
    changed_files = 0
    changed_rows = 0
    for path in sorted(RESULTS.glob("*.jsonl")):
        rows = [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        new_rows = [regrade_record(r) for r in rows]
        deltas = [
            (o.get("seq"), o.get("injection_outcome"), n.get("injection_outcome"))
            for o, n in zip(rows, new_rows, strict=True)
            if o.get("injection_outcome") != n.get("injection_outcome")
        ]
        if not deltas:
            continue
        changed_files += 1
        changed_rows += len(deltas)
        moves: dict[str, int] = {}
        for _, old, new in deltas:
            moves[f"{old} → {new}"] = moves.get(f"{old} → {new}", 0) + 1
        print(f"{path.name}: {len(deltas)}/{len(rows)} rows  " +
              ", ".join(f"{k} ({v})" for k, v in sorted(moves.items())))
        if not apply:
            continue

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in new_rows),
            encoding="utf-8",
        )
        os.replace(tmp, path)

        # Keep the sidecar's cached counters consistent with the rows.
        sync_meta_counters(path.with_suffix(".meta.json"), new_rows)

    verb = "Rewrote" if apply else "Would rewrite"
    print(f"\n{verb} {changed_rows} rows across {changed_files} files.")
    if not apply and changed_files:
        print("Re-run with --apply to write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main("--apply" in sys.argv))
