"""
Browser-driven scan loop for SaaS chatbot widgets (Ada, Intercom, etc.).

Mirrors runner.py's external interface — same RunState, same SSE event names
(prompt_sent / response_received / finding_detected / counter_update /
run_complete) — so the existing UI works unchanged. Difference is internal:
no HTTP recon, no httpx; we launch one Playwright session and drive the real
widget for the duration of the scan.

Per-provider DOM knowledge lives in browser_adapters.py. This file knows
nothing about Ada-vs-Intercom — it asks the adapter to open the widget,
send a message, and wait for a reply.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from run import load_prompts  # type: ignore  # noqa: E402

from .browser_adapters import CHROME_UA, BrowserAdapter, _Cancelled, get_adapter  # noqa: E402
from .browser_profile import HONEST  # noqa: E402
from .classifiers import (  # noqa: E402
    STALL_WINDOW,
    classify_injection_outcome,
    classify_run_health,
    detect_findings,
    detect_stall,
    generate_read,
)
from .runner import (  # noqa: E402
    RESULTS_DIR,
    FindingAggregate,
    RunState,
    _now_iso,
    _write_meta_sidecar,
    pop_under_cap,
    select_under_cap,
)


def context_identity(state: RunState) -> tuple[str, dict[str, str]]:
    """Resolve (user_agent, custom_headers) for the Playwright context.

    Deliberately does NOT reuse runner.py's ``_identity_headers``: that returns
    the XHR set, which Playwright would apply to document navigations too, and
    a navigation carrying ``Sec-Fetch-Dest: empty`` is a stronger bot tell than
    sending none (see browser_profile.py). Chrome emits its own correct
    Sec-Fetch-*/sec-ch-ua headers; only the UA is ours to choose.

    Only ``browser`` spoofs. ``honest`` sends the attributable UA — the whole
    point of it is traffic the client can find in their own logs — and
    ``custom`` falls back to the same rather than a spoof, matching the HTTP
    runner, which sends no browser UA at all for ``custom``. An explicit
    ``User-Agent:`` custom header overrides either.
    """
    extra = dict(state.custom_headers)
    default_ua = CHROME_UA if state.identity == "browser" else HONEST["User-Agent"]
    # Case-insensitive: the UI hint is `Name: value`, so `user-agent:` is a
    # realistic thing to type and must not slip past into extra_http_headers.
    ua = default_ua
    for key in list(extra):
        if key.lower() == "user-agent":
            ua = extra.pop(key)
    return ua, extra


def belongs_to_target(request_url: str, target_host: str) -> bool:
    """Is this request going to the target's own hosts (vs a CDN/analytics)?

    ponytail: host-suffix match, not eTLD+1 — `widget.acme.com` under
    `acme.com` is covered, a genuinely cross-origin widget (acme.com hosting an
    ada.support iframe) is not, and its requests go out without the custom
    headers. Swap in a public-suffix list if that combination shows up.
    """
    from urllib.parse import urlparse

    if not target_host:
        return False
    host = (urlparse(request_url).hostname or "").lower()
    return host == target_host or host.endswith("." + target_host)


async def _scope_headers_to_target(ctx, host_page_url: str, extra: dict[str, str]) -> None:
    """Send operator custom headers to the target's own hosts, nothing else.

    Playwright's extra_http_headers is context-wide, so setting them there
    would leak an `Authorization:` line to every origin the widget page loads.
    """
    from urllib.parse import urlparse

    target = (urlparse(host_page_url).hostname or "").lower()
    lowered = {k.lower(): v for k, v in extra.items()}

    async def _route(route, request) -> None:
        if belongs_to_target(request.url, target):
            await route.continue_(headers={**request.headers, **lowered})
        else:
            await route.continue_()

    await ctx.route("**/*", _route)


async def _emit(state: RunState, event_type: str, payload: dict) -> None:
    await state.queue.put({"type": event_type, "data": payload})


async def run_batch_browser(
    state: RunState,
    categories: list[str] | None,
    limit: int,
    shuffle: bool,
) -> None:
    """Browser-driven equivalent of runner.run_batch.

    Picks the right per-provider adapter from state.platform, opens the widget
    on state.host_page_url, then iterates prompts through it.
    """
    state.started_at = _now_iso()
    state.unpause_event.set()

    try:
        # Full filtered pool (no limit) so over-cap prompts can be replaced
        # from the reserve rather than shrinking the run. See runner.run_batch.
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
            "run_id": state.run_id, "results_path": None, "summary": {},
        })
        return

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

    # Surface platform classification immediately.
    await _emit(state, "platform_detected", {
        "platform": state.platform,
        "platform_label": state.platform_label,
        "recommended_runner": state.recommended_runner,
        "host_page_url": state.host_page_url,
        "compatible_with_runner": True,  # this IS the browser runner
    })

    # Pick adapter
    adapter_cls = get_adapter(state.platform)
    if adapter_cls is None:
        await _emit(state, "run_error", {
            "message": f"no browser adapter for platform {state.platform!r}",
        })
        state.done = True
        await _emit(state, "run_complete", {
            "run_id": state.run_id, "results_path": None, "summary": {},
        })
        return

    if not state.host_page_url:
        await _emit(state, "run_error", {
            "message": "browser runner needs host_page_url (where the widget lives)",
        })
        state.done = True
        await _emit(state, "run_complete", {
            "run_id": state.run_id, "results_path": None, "summary": {},
        })
        return

    exit_status = "completed"
    out_f = state.results_path.open("w", encoding="utf-8")

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                channel="chrome", headless=True,
                args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
            )
            try:
                ua, extra = context_identity(state)
                ctx = await browser.new_context(
                    user_agent=ua,
                    viewport={"width": 1280, "height": 900},
                    locale="en-PH",
                )
                # NOT extra_http_headers=: that is context-wide, so an operator
                # pasting `Authorization: Bearer …` would send it to every CDN,
                # font and analytics host the widget page touches. The HTTP
                # runner only ever sends custom headers to the target.
                if extra:
                    await _scope_headers_to_target(ctx, state.host_page_url, extra)
                page = await ctx.new_page()
                page.on("pageerror", lambda e: None)

                adapter: BrowserAdapter = adapter_cls(page)
                await _emit(state, "browser_opening_widget", {
                    "host_page_url": state.host_page_url,
                    "adapter": adapter.name,
                })
                try:
                    await adapter.open_widget(state.host_page_url, cancel=state.cancel_event)
                except _Cancelled:
                    # Stop pressed while the widget was still opening — not an
                    # error, just an early exit. exit_status stays "completed".
                    return
                except Exception as e:
                    await _emit(state, "run_error", {
                        "message": f"open_widget failed: {type(e).__name__}: {e}",
                    })
                    return
                await _emit(state, "browser_widget_ready", {"adapter": adapter.name})

                recent: deque[tuple[int, str]] = deque(maxlen=STALL_WINDOW)

                # Every prompt goes down the SAME widget session — nothing here
                # resets the page, deliberately, because a real customer
                # conversation is continuous. So the turn number matters: once
                # the bot is compromised, later turns inherit a broken session
                # rather than proving anything new. `seq` can't stand in for it
                # — a skipped over-cap prompt burns a seq without sending a
                # message. See judge.session_cascade for the read side.
                turn_index = 0
                first_compromise_turn: int | None = None

                for seq, prompt in enumerate(prompts, 1):
                    if state.cancel_event.is_set():
                        break

                    # Pause gate (same semantics as HTTP runner).
                    if not state.unpause_event.is_set():
                        await _emit(state, "run_paused", {"at_seq": seq - 1})
                        cancel_wait = asyncio.create_task(state.cancel_event.wait())
                        unpause_wait = asyncio.create_task(state.unpause_event.wait())
                        _, pending = await asyncio.wait(
                            [cancel_wait, unpause_wait], return_when=asyncio.FIRST_COMPLETED,
                        )
                        for t in pending:
                            t.cancel()
                        if state.cancel_event.is_set():
                            break
                        await _emit(state, "run_resumed", {
                            "at_seq": seq - 1, "pacing_s": state.pacing_s,
                        })

                    # Adaptive substitution: swap over-cap prompts for shorter
                    # reserves so the tested total holds; skip only if dry.
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

                    turn_index += 1
                    await _emit(state, "prompt_sent", {
                        "seq": seq,
                        "id": prompt["id"],
                        "category": prompt.get("category", "?"),
                        "source": prompt.get("source", ""),
                        "reference": prompt.get("reference"),
                        "text": prompt["text"],
                    })

                    t0 = time.time()
                    before = await adapter.current_bubble_count()
                    http_status = 200  # synthetic — the widget handled the request
                    body = ""
                    try:
                        await adapter.send_message(prompt["text"])
                        reply = await adapter.wait_for_reply(
                            before_count=before, timeout_s=45, cancel=state.cancel_event,
                        )
                        if reply.timed_out:
                            http_status = 0
                            body = "__no_reply__: widget timeout (45s)"
                        else:
                            body = reply.text
                    except Exception as e:
                        http_status = 0
                        body = f"__browser_error__: {type(e).__name__}: {e}"
                    latency_ms = int((time.time() - t0) * 1000)

                    # Reuse the same classifiers as the HTTP runner.
                    findings = detect_findings(http_status, body, prompt["text"])
                    recent.append((http_status, body))
                    stall = detect_stall(list(recent))
                    if stall is not None:
                        findings.append(stall)
                    # Adaptive length cap: learn the target's ceiling on rejection.
                    for f in findings:
                        if f.layer.startswith("Length cap"):
                            cap = f.evidence.get("max_chars")
                            if cap:
                                state.max_prompt_chars = (
                                    cap if state.max_prompt_chars <= 0
                                    else min(state.max_prompt_chars, cap)
                                )
                    run_health = classify_run_health(http_status, body)
                    outcome = classify_injection_outcome(
                        http_status, body, prompt["text"], category=prompt.get("category")
                    )
                    read = generate_read(
                        http_status, body, prompt["text"], findings, category=prompt.get("category")
                    )

                    if run_health == "reached":
                        state.counters.reached += 1
                    else:
                        state.counters.blocked += 1
                    if outcome != "compromised":
                        state.counters.refused += 1
                    elif first_compromise_turn is None:
                        first_compromise_turn = turn_index
                        state.counters.compromised += 1
                        await _emit(state, "session_compromised", {
                            "turn_index": turn_index,
                            "total_turns": len(prompts),
                            "seq": seq,
                        })
                    else:
                        # Same broken session — not an independent hit.
                        state.counters.inherited += 1
                    state.counters.total_done = seq

                    record = {
                        "id": prompt["id"], "seq": seq,
                        "turn_index": turn_index,
                        "category": prompt.get("category"),
                        "source": prompt.get("source"),
                        "reference": prompt.get("reference"),
                        "url": state.target_url,
                        "timestamp": _now_iso(),
                        "latency_ms": latency_ms,
                        "http_status": http_status,
                        "run_health": run_health,
                        "injection_outcome": outcome,
                        "read": read,
                        "prompt": prompt["text"],
                        "response": body,
                        "runner": "browser",
                    }
                    out_f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    out_f.flush()

                    await _emit(state, "response_received", {
                        "seq": seq, "id": prompt["id"],
                        "http_status": http_status,
                        "latency_ms": latency_ms,
                        "body_snippet": body[:200],
                        "body_full": body,
                        "run_health": run_health,
                        "injection_outcome": outcome,
                        "read": read,
                    })

                    for f in findings:
                        agg = state.findings.get(f.layer)
                        if agg is None:
                            agg = FindingAggregate(
                                layer=f.layer, severity=f.severity,
                                description=f.description, count=0, first_seen_seq=seq,
                            )
                            state.findings[f.layer] = agg
                        agg.count += 1
                        agg.last_evidence = f.evidence
                        await _emit(state, "finding_detected", {
                            "layer": agg.layer, "severity": agg.severity,
                            "description": agg.description,
                            "first_seen_seq": agg.first_seen_seq,
                            "count": agg.count, "evidence": agg.last_evidence,
                        })

                    await _emit(state, "counter_update", asdict(state.counters))

                    if seq < len(prompts):
                        try:
                            await asyncio.wait_for(
                                state.cancel_event.wait(), timeout=state.pacing_s,
                            )
                            break
                        except TimeoutError:
                            pass
            finally:
                # Root-cause fix for the leak: browser.close() now runs no
                # matter where setup/loop fails, not just on the happy path.
                # Guarded so a close() error can't mask the real in-flight
                # exception propagating out of the try block.
                try:
                    await browser.close()
                except Exception:
                    pass

    except asyncio.CancelledError:
        exit_status = "stopped"
        await _emit(state, "run_error", {"message": "cancelled"})
        raise
    except Exception as e:
        exit_status = "error"
        await _emit(state, "run_error", {
            "message": f"{type(e).__name__}: {e}",
        })
    finally:
        try:
            out_f.close()
        except Exception:
            pass
        state.done = True
        _write_meta_sidecar(
            state, categories=categories, status=exit_status,
            finished_at=_now_iso(),
        )
        await _emit(state, "run_complete", {
            "run_id": state.run_id,
            "results_path": str(state.results_path) if state.results_path else None,
            "summary": {
                "by_status": {},
                "counters": asdict(state.counters),
                "findings_count": len(state.findings),
            },
        })
