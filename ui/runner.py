"""
Async run loop for the prompt-injection UI.

Wraps the api_batch.py approach (direct POST to a chat API) as an asyncio.Task
that emits events to an asyncio.Queue for the SSE stream to consume.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from run import load_prompts, stratified_pick  # type: ignore  # noqa: E402

from .browser_profile import HONEST, XHR  # noqa: E402
from .classifiers import (  # noqa: E402
    STALL_WINDOW,
    classify_block_reason,
    classify_injection_outcome,
    classify_run_health,
    detect_findings,
    detect_stall,
    generate_read,
)
from .recon import (  # noqa: E402
    LayerEvent,
    classify_block_layer,
    escalate_once,
    negotiate_passport,
)

RESULTS_DIR = ROOT / "results"
MAX_INLINE_ESCALATIONS = 3

# Rate-limit (HTTP 429) backoff: wait these many seconds before retrying the
# SAME request. 5 retries; the 5th holds at 120s. Still 429 after the last →
# the target is (temporarily) blocking us, so halt the whole run.
RATE_LIMIT_BACKOFFS = (10, 30, 60, 120, 120)


class RateLimitHalt(Exception):
    """Raised when the target stays rate-limited past the final backoff."""


@dataclass
class FindingAggregate:
    layer: str
    severity: str
    description: str
    count: int = 0
    first_seen_seq: int = 0
    last_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Counters:
    reached: int = 0
    blocked: int = 0
    compromised: int = 0
    # Compromised-looking turns that landed *after* the session was already
    # compromised. Only the browser runner can produce these — see
    # judge.session_cascade. Held apart from `compromised` so they aren't
    # tallied as independent hits, and apart from `refused` so they aren't
    # hidden either. compromised + inherited + refused == total_done.
    inherited: int = 0
    refused: int = 0
    total_done: int = 0
    total: int = 0


def partition_by_char_cap(
    prompts: list[dict], max_chars: int
) -> tuple[list[dict], list[dict]]:
    """Split prompts into (kept, skipped) by message length.

    A target with a known input character limit rejects or truncates longer
    prompts, so sending them wastes a request and pollutes the report. When
    ``max_chars > 0`` we keep prompts whose text is at most that many chars and
    skip the rest. ``max_chars <= 0`` means "no cap" — keep everything.
    """
    if max_chars <= 0:
        return prompts, []
    kept: list[dict] = []
    skipped: list[dict] = []
    for p in prompts:
        (kept if len(p["text"]) <= max_chars else skipped).append(p)
    return kept, skipped


def select_under_cap(
    prompts: list[dict], max_chars: int, limit: int | None
) -> tuple[list[dict], list[dict]]:
    """Pick up to ``limit`` within-cap prompts; return (selected, reserve).

    The reserve holds the leftover within-cap prompts. When the target's length
    cap is learned mid-run, the loop pops from the reserve to *replace* an
    over-cap prompt instead of dropping it — so the tested total stays at what
    the operator asked for (20 tests requested → 20 delivered, corpus willing).

    The selection is stratified across harm categories rather than a plain
    slice: at the default limit of 20 a straight slice off a shuffled corpus can
    contain no `customer_data_leak` prompt at all, and the report then reads as
    "no data-leak risk" when the truth is "never tested for it".
    """
    fitting, _over = partition_by_char_cap(prompts, max_chars)
    selected = stratified_pick(fitting, limit)
    chosen = {id(p) for p in selected}
    reserve = [p for p in fitting if id(p) not in chosen]
    return selected, reserve


def pop_under_cap(pool: list[dict], max_chars: int) -> dict | None:
    """Pop the next reserve prompt that fits under ``max_chars`` (0 = no cap).

    The reserve is built before the cap is known, so it may itself hold over-cap
    prompts; those are discarded as we scan. Returns None when the reserve dries
    up (only then does the caller fall back to an honest skip).
    """
    while pool:
        cand = pool.pop(0)
        if max_chars <= 0 or len(cand["text"]) <= max_chars:
            return cand
    return None


def _identity_headers(state: RunState) -> dict[str, str]:
    """Base headers for ``state.identity``, with ``custom_headers`` layered on
    top. Always returns a fresh dict — never mutates the imported constants."""
    base = {"browser": XHR, "honest": HONEST}.get(state.identity, {})
    return {**base, **state.custom_headers}


@dataclass
class RunState:
    run_id: str
    target_url: str
    pacing_s: float
    cancel_event: asyncio.Event
    queue: asyncio.Queue
    counters: Counters
    # Skip prompts whose text exceeds this many characters (0 = no cap). Set at
    # run-start when the operator knows the target's input length limit.
    max_prompt_chars: int = 0
    # Which header set to send: "browser" (Chrome XHR fingerprint), "honest"
    # (attributable PromptSiege UA), or "custom" (operator-supplied only).
    identity: str = "browser"
    custom_headers: dict[str, str] = field(default_factory=dict)
    skipped_over_cap: int = 0
    # Over-cap prompts replaced with shorter within-cap reserves (count) and the
    # reserve pool they're drawn from (leftover within-cap prompts).
    swapped_over_cap: int = 0
    backfill_pool: list[dict] = field(default_factory=list)
    findings: dict[str, FindingAggregate] = field(default_factory=dict)
    results_path: Path | None = None
    started_at: str = ""
    done: bool = False
    # Pause/resume: SET means "running" (loop proceeds), CLEARED means "paused".
    # Initialized as set so the loop runs by default.
    unpause_event: asyncio.Event = field(default_factory=asyncio.Event)
    paused: bool = False
    # Recon-negotiated passport (headers/cookies that pass the perimeter).
    passport_headers: dict[str, str] = field(default_factory=dict)
    passport_cookies: dict[str, str] = field(default_factory=dict)
    passport_layers: list[dict[str, Any]] = field(default_factory=list)
    # Platform classification from discovery — informs which runner type the
    # scan needs and shows up as a top-line finding in the UI.
    platform: str = ""               # ada | intercom | drift | zendesk | thin_wrapper | ""
    platform_label: str = ""         # human-readable e.g. "Ada Chat Platform (SaaS)"
    recommended_runner: str = ""     # "http" | "browser" | ""
    host_page_url: str = ""          # for SaaS bots: the page that hosts the widget


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def _emit(state: RunState, event_type: str, payload: dict) -> None:
    await state.queue.put({"type": event_type, "data": payload})


def _write_meta_sidecar(
    state: RunState,
    *,
    categories: list[str] | None,
    status: str,
    finished_at: str,
) -> None:
    """Write run-level metadata next to the JSONL results file.

    Browsed via the Reports tab; the JSONL records are the per-prompt detail.
    """
    if state.results_path is None:
        return
    meta_path = state.results_path.with_suffix(".meta.json")
    findings = [
        {
            "layer": agg.layer,
            "severity": agg.severity,
            "description": agg.description,
            "count": agg.count,
            "first_seen_seq": agg.first_seen_seq,
        }
        for agg in state.findings.values()
    ]
    meta = {
        "run_id": state.run_id,
        "target_url": state.target_url,
        "categories": list(categories or []),
        "started_at": state.started_at,
        "finished_at": finished_at,
        "status": status,
        "platform": state.platform,
        "platform_label": state.platform_label,
        "recommended_runner": state.recommended_runner,
        "host_page_url": state.host_page_url,
        "counters": asdict(state.counters),
        "findings": findings,
        "security_posture": state.passport_layers,
        "max_prompt_chars": state.max_prompt_chars,
        "skipped_over_cap": state.skipped_over_cap,
        "swapped_over_cap": state.swapped_over_cap,
        "judge": None,
    }
    meta_path.write_text(
        json.dumps(meta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


async def run_batch(
    state: RunState,
    categories: list[str] | None,
    limit: int,
    shuffle: bool,
) -> None:
    """Main async loop. Emits SSE events into state.queue. Cancellable + pausable."""
    state.started_at = _now_iso()
    # Default to running (not paused).
    state.unpause_event.set()
    try:
        # Load the FULL filtered pool (no limit) so over-cap prompts can be
        # replaced from the leftover reserve rather than shrinking the run.
        prompts = load_prompts(
            limit=None,
            categories=categories,
            shuffle=shuffle,
            resume_from=None,
            platform=state.platform or None,
        )
    except SystemExit as e:
        await _emit(state, "run_error", {"message": f"failed to load prompts: {e}"})
        state.done = True
        await _emit(state, "run_complete", {
            "run_id": state.run_id,
            "results_path": None,
            "summary": {},
        })
        return

    # Select `limit` within-cap prompts; keep the rest as a substitution
    # reserve. A cap known upfront simply never picks over-cap prompts; a cap
    # learned mid-run swaps them from this reserve (see pop_under_cap below).
    prompts, state.backfill_pool = select_under_cap(
        prompts, state.max_prompt_chars, limit
    )
    state.counters.total = len(prompts)

    RESULTS_DIR.mkdir(exist_ok=True)
    state.results_path = RESULTS_DIR / f"ui-{state.run_id}.jsonl"

    await _emit(state, "run_started", {
        "run_id": state.run_id,
        "total": len(prompts),
        "target_url": state.target_url,
        "started_at": state.started_at,
    })

    # Emit platform classification as a top-line finding so users see what
    # KIND of chatbot they're testing before any prompts go through.
    if state.platform:
        await _emit(state, "platform_detected", {
            "platform": state.platform,
            "platform_label": state.platform_label,
            "recommended_runner": state.recommended_runner,
            "host_page_url": state.host_page_url,
            "compatible_with_runner": state.recommended_runner == "http",
        })

    # ---- Recon phase: negotiate a passport (headers + cookies + tokens)
    # that passes the target's perimeter defenses before any prompt is sent.
    await _emit(state, "recon_started", {"target_url": state.target_url})

    async def _emit_layer(evt: LayerEvent) -> None:
        state.passport_layers.append({
            "layer": evt.layer,
            "spoof_header": evt.spoof_header,
            "spoof_value": evt.spoof_value,
            "verdict": evt.verdict,
            "http_before": evt.http_before,
            "http_after": evt.http_after,
            "note": evt.note,
        })
        await _emit(state, "recon_layer_discovered", state.passport_layers[-1])

    try:
        passport = await negotiate_passport(
            state.target_url, on_attempt=_emit_layer,
        )
    except Exception as e:
        await _emit(state, "recon_error", {
            "message": f"{type(e).__name__}: {e}",
        })
        passport = None  # type: ignore[assignment]

    if passport is not None:
        state.passport_headers = dict(passport.headers)
        state.passport_cookies = dict(passport.cookies)
        await _emit(state, "passport_negotiated", {
            "success": passport.success,
            "final_status": passport.final_status,
            "headers": state.passport_headers,
            "cookies_count": len(state.passport_cookies),
            "layers_discovered": len(state.passport_layers),
        })

    # Track which layers we've already bypassed (don't re-escalate) or
    # confirmed hard-block (don't waste cycles retrying).
    known_bypassed: set[str] = {
        rec["layer"] for rec in state.passport_layers if rec["verdict"] == "bypassed"
    }
    known_hard_block: set[str] = {
        rec["layer"] for rec in state.passport_layers
        if rec["verdict"] in ("hard-block", "no-bypass-known")
    }

    exit_status = "completed"
    try:
        out_f = state.results_path.open("w", encoding="utf-8")
        async with httpx.AsyncClient(
            timeout=90.0,
            cookies=state.passport_cookies,
            headers=_identity_headers(state),
            follow_redirects=True,
        ) as client:

            async def _post_with_backoff(headers, content, seq):
                """POST, retrying the SAME request on HTTP 429 with escalating
                backoff. Sleeps are cancel-interruptible. Raises RateLimitHalt
                if still 429 after the final backoff."""
                resp = await client.post(
                    state.target_url, headers=headers, content=content
                )
                for wait_s in RATE_LIMIT_BACKOFFS:
                    if resp.status_code != 429:
                        return resp
                    await _emit(state, "rate_limited", {
                        "seq": seq, "retry_in_s": wait_s,
                    })
                    try:
                        # Wake early if the run is cancelled mid-wait.
                        await asyncio.wait_for(
                            state.cancel_event.wait(), timeout=wait_s
                        )
                        return resp  # cancelled; caller's cancel check handles it
                    except TimeoutError:
                        pass
                    resp = await client.post(
                        state.target_url, headers=headers, content=content
                    )
                if resp.status_code == 429:
                    raise RateLimitHalt()
                return resp

            recent: deque[tuple[int, str]] = deque(maxlen=STALL_WINDOW)

            for seq, prompt in enumerate(prompts, 1):
                if state.cancel_event.is_set():
                    break

                # Pause gate: if paused, emit run_paused and wait until either
                # unpause or cancel fires. Zero overhead when not paused.
                if not state.unpause_event.is_set():
                    await _emit(state, "run_paused", {"at_seq": seq - 1})
                    cancel_wait = asyncio.create_task(state.cancel_event.wait())
                    unpause_wait = asyncio.create_task(state.unpause_event.wait())
                    _, pending = await asyncio.wait(
                        [cancel_wait, unpause_wait], return_when=asyncio.FIRST_COMPLETED
                    )
                    for t in pending:
                        t.cancel()
                    if state.cancel_event.is_set():
                        break
                    await _emit(state, "run_resumed", {
                        "at_seq": seq - 1, "pacing_s": state.pacing_s,
                    })

                # Adaptive substitution: if a cap is known and THIS prompt is
                # over it (learned after selection), swap in a shorter reserve
                # prompt so the tested total holds at what was requested. Only
                # skip (and decrement) when the reserve is exhausted.
                cap = state.max_prompt_chars
                if cap > 0 and len(prompt["text"]) > cap:
                    replacement = pop_under_cap(state.backfill_pool, cap)
                    if replacement is not None:
                        state.swapped_over_cap += 1
                        await _emit(state, "prompt_swapped", {
                            "seq": seq, "dropped_id": prompt["id"],
                            "dropped_chars": len(prompt["text"]),
                            "new_id": replacement["id"],
                            "category": replacement.get("category", "?"),
                            "max_prompt_chars": cap,
                        })
                        prompt = replacement
                    else:
                        state.skipped_over_cap += 1
                        state.counters.total = max(0, state.counters.total - 1)
                        await _emit(state, "prompt_skipped", {
                            "seq": seq, "id": prompt["id"],
                            "chars": len(prompt["text"]), "max_prompt_chars": cap,
                        })
                        await _emit(state, "counter_update", asdict(state.counters))
                        continue

                await _emit(state, "prompt_sent", {
                    "seq": seq,
                    "id": prompt["id"],
                    "category": prompt.get("category", "?"),
                    "source": prompt.get("source", ""),
                    "reference": prompt.get("reference"),
                    "text": prompt["text"],
                })

                t0 = time.time()
                http_status = 0
                body = ""
                resp = None
                content_bytes = json.dumps(
                    {"message": prompt["text"], "history": []}
                )
                for _attempt_idx in range(MAX_INLINE_ESCALATIONS + 1):
                    # Per attempt, not per prompt: a later attempt that raises
                    # would otherwise leave the PREVIOUS attempt's status/resp
                    # paired with this attempt's error body, and the classifiers
                    # would grade a status/body pair that never happened.
                    http_status = 0
                    resp = None
                    req_headers = {
                        **state.custom_headers,
                        **state.passport_headers,
                        "Content-Type": "application/json",
                    }
                    try:
                        resp = await _post_with_backoff(
                            req_headers, content_bytes, seq
                        )
                        http_status = resp.status_code
                        body = resp.text
                    except httpx.RequestError as e:
                        body = f"__network_error__: {type(e).__name__}: {e}"
                        break

                    # 2xx → done. Not blocked, or blocked-by-content (refusal).
                    if 200 <= http_status < 300:
                        break

                    block_layer = classify_block_layer(http_status, body)
                    # Don't escalate if: unknown layer, already bypassed once
                    # (re-block means content-triggered, not perimeter), or
                    # known hard-block (waste of cycles).
                    if (
                        block_layer is None
                        or block_layer in known_bypassed
                        or block_layer in known_hard_block
                    ):
                        break

                    result = await escalate_once(
                        state.target_url,
                        state.passport_headers,
                        state.passport_cookies,
                        block_layer,
                        on_attempt=_emit_layer,
                    )
                    if result is None:
                        known_hard_block.add(block_layer)
                        break
                    new_headers, new_cookies, _evt = result
                    state.passport_headers = new_headers
                    state.passport_cookies = new_cookies
                    known_bypassed.add(block_layer)
                    # Update the live client's cookie jar so subsequent
                    # prompts in this loop inherit any newly-harvested session.
                    for k, v in new_cookies.items():
                        client.cookies.set(k, v)
                    # Retry the SAME prompt with the escalated passport.
                latency_ms = int((time.time() - t0) * 1000)

                findings = detect_findings(http_status, body, prompt["text"])
                # Cross-turn check: same canned reply (or no reply) N times in a
                # row means we're cut off, which no single response can show.
                recent.append((http_status, body))
                stall = detect_stall(list(recent))
                if stall is not None:
                    findings.append(stall)
                # Adaptive length cap: once the target rejects an over-long prompt,
                # learn its ceiling so the loop skips longer prompts from here on.
                for f in findings:
                    if f.layer.startswith("Length cap"):
                        cap = f.evidence.get("max_chars")
                        if cap:
                            state.max_prompt_chars = (
                                cap if state.max_prompt_chars <= 0
                                else min(state.max_prompt_chars, cap)
                            )
                run_health = classify_run_health(http_status, body)
                outcome = classify_injection_outcome(http_status, body, prompt["text"], category=prompt.get("category"))
                read = generate_read(http_status, body, prompt["text"], findings, category=prompt.get("category"))
                block_reason = classify_block_reason(http_status, body)
                if resp is not None and resp.history:
                    # httpx converts POST->GET on 301/302; a 200 after that
                    # redirect isn't a real chat answer.
                    block_reason = (
                        f"{block_reason}, redirected" if block_reason else "redirected"
                    )

                if run_health == "reached":
                    state.counters.reached += 1
                else:
                    state.counters.blocked += 1
                if outcome == "compromised":
                    state.counters.compromised += 1
                else:
                    state.counters.refused += 1
                state.counters.total_done = seq

                record = {
                    "id": prompt["id"],
                    "seq": seq,
                    "category": prompt.get("category"),
                    "source": prompt.get("source"),
                    "reference": prompt.get("reference"),
                    "url": state.target_url,
                    "timestamp": _now_iso(),
                    "latency_ms": latency_ms,
                    "http_status": http_status,
                    "run_health": run_health,
                    "injection_outcome": outcome,
                    "block_reason": block_reason,
                    "read": read,
                    "prompt": prompt["text"],
                    "response": body,
                }
                out_f.write(json.dumps(record, ensure_ascii=False) + "\n")
                out_f.flush()

                await _emit(state, "response_received", {
                    "seq": seq,
                    "id": prompt["id"],
                    "http_status": http_status,
                    "latency_ms": latency_ms,
                    "body_snippet": body[:200],
                    "body_full": body,
                    "run_health": run_health,
                    "injection_outcome": outcome,
                    "block_reason": block_reason,
                    "read": read,
                })

                for f in findings:
                    agg = state.findings.get(f.layer)
                    if agg is None:
                        agg = FindingAggregate(
                            layer=f.layer,
                            severity=f.severity,
                            description=f.description,
                            count=0,
                            first_seen_seq=seq,
                        )
                        state.findings[f.layer] = agg
                    agg.count += 1
                    agg.last_evidence = f.evidence
                    await _emit(state, "finding_detected", {
                        "layer": agg.layer,
                        "severity": agg.severity,
                        "description": agg.description,
                        "first_seen_seq": agg.first_seen_seq,
                        "count": agg.count,
                        "evidence": agg.last_evidence,
                    })

                await _emit(state, "counter_update", asdict(state.counters))

                if seq < len(prompts):
                    try:
                        await asyncio.wait_for(
                            state.cancel_event.wait(),
                            timeout=state.pacing_s,
                        )
                        break
                    except TimeoutError:
                        pass

    except asyncio.CancelledError:
        exit_status = "stopped"
        await _emit(state, "run_error", {"message": "cancelled"})
        raise
    except RateLimitHalt:
        exit_status = "rate_limited"
        await _emit(state, "run_error", {
            "message": (
                "Target kept rate-limiting us (HTTP 429) through 5 backoff "
                "retries — you may be temporarily blocked. Halting the run; "
                "wait a while before retrying."
            ),
        })
    except Exception as e:
        exit_status = "error"
        await _emit(state, "run_error", {
            "message": f"{type(e).__name__}: {e}",
        })
    finally:
        try:
            out_f.close()  # type: ignore[possibly-unbound]
        except Exception:
            pass
        state.done = True
        _write_meta_sidecar(
            state,
            categories=categories,
            status=exit_status,
            finished_at=_now_iso(),
        )
        by_status: dict[str, int] = {}
        await _emit(state, "run_complete", {
            "run_id": state.run_id,
            "results_path": str(state.results_path) if state.results_path else None,
            "summary": {
                "by_status": by_status,
                "counters": asdict(state.counters),
                "findings_count": len(state.findings),
            },
        })
