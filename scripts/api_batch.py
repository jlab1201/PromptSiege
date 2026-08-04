#!/usr/bin/env python3
"""
Smoke-batch sender for the /api/chat endpoint.
Samples prompts from prompts.json across categories, POSTs each via curl
(so the project allowlist covers it), and appends one JSONL record per result.
"""
import json
import os
import random
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "prompts.json"
RESULTS_DIR = ROOT / "results"
URL = os.environ.get("TARGET_URL", "https://www.example.com/api/chat")
ORIGIN = os.environ.get("TARGET_ORIGIN", "https://example.com")

SAMPLE_PLAN = {
    "unauthorized_action": 4,
    "config_disclosure": 4,
    "poisoned_input": 4,
    "made_up_promise": 1,
    "customer_data_leak": 1,
    "brand_damage": 1,
    "free_labor": 1,
}
DELAY_S = 3.0
TIMEOUT_S = 90


def send(message: str) -> tuple[int, str, float]:
    body = json.dumps({"message": message, "history": []})
    t0 = time.time()
    proc = subprocess.run(
        [
            "curl", "-s", "-w", "\n__HTTP__%{http_code}",
            "-X", "POST", URL,
            "-H", "Content-Type: application/json",
            "-H", f"Origin: {ORIGIN}",
            "--max-time", str(TIMEOUT_S),
            "--data-binary", "@-",
        ],
        input=body,
        text=True,
        capture_output=True,
    )
    latency_ms = int((time.time() - t0) * 1000)
    out = proc.stdout
    marker = out.rfind("\n__HTTP__")
    if marker == -1:
        return 0, out, latency_ms
    body_out = out[:marker]
    code = int(out[marker + len("\n__HTTP__"):].strip() or "0")
    return code, body_out, latency_ms


def main():
    random.seed(42)
    corpus = json.loads(CORPUS.read_text())
    by_cat: dict[str, list] = {}
    for p in corpus:
        by_cat.setdefault(p["category"], []).append(p)

    picks = []
    for cat, n in SAMPLE_PLAN.items():
        pool = by_cat.get(cat, [])
        picks.extend(random.sample(pool, min(n, len(pool))))

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_path = RESULTS_DIR / f"api-smoke-{ts}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"sending {len(picks)} prompts -> {out_path}")
    with out_path.open("w") as fh:
        for i, p in enumerate(picks, 1):
            code, resp, latency_ms = send(p["text"])
            rec = {
                "id": p["id"],
                "category": p["category"],
                "source": p["source"],
                "url": URL,
                "timestamp": datetime.now(UTC).isoformat(),
                "latency_ms": latency_ms,
                "http_status": code,
                "prompt": p["text"],
                "response": resp,
            }
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            snippet = resp.replace("\n", " ")[:120]
            print(f"  [{i:>2}/{len(picks)}] {p['category']:<22} {code} {latency_ms}ms  {snippet}")
            time.sleep(DELAY_S)

    print(f"done. {out_path}")


if __name__ == "__main__":
    main()
