"""
FastAPI app for the prompt-injection harness UI.

Run with:
    python -m ui.server
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os as _os
import secrets
import sys
from collections import Counter as CounterCol
from dataclasses import dataclass
from dataclasses import field as _field
from functools import partial
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .browser_profile import parse_custom
from .judge import (
    BASE_URLS,
    CATEGORY_REMEDIATION,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    DEFAULT_PROVIDER_ID,
    JudgeConfig,
    _read_cached_catalog,
    count_outcomes,
    harm_rank,
    load_env_file,
    normalize_category,
    owner_questions,
    provider_env_var,
    regrade_record,
    session_cascade,
    worst_finding,
)
from .net_guard import validate_public_url
from .runner import Counters, RunState, run_batch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from run import fill_prompt_slots  # type: ignore  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROMPTS_FILE = ROOT / "prompts.json"
RESULTS_DIR = ROOT / "results"

ENV_FILE = ROOT / ".env"

# prompts.json is ~3.79MB — parsing/writing it synchronously stalls the
# event loop (and all live SSE streams with it). Route every load/save
# through a thread via _run_blocking, and serialize the CRUD
# read-modify-write endpoints through this lock so two concurrent writers
# can't clobber each other's changes.
_prompts_lock = asyncio.Lock()


async def _run_blocking(fn, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(fn, *args, **kwargs))


def _load_env_into_os() -> None:
    """Read project .env and populate os.environ for missing keys."""
    import os

    from .judge import load_env_file
    for k, v in load_env_file(ENV_FILE).items():
        os.environ.setdefault(k, v)


_load_env_into_os()

app = FastAPI(title="PromptSiege UI")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class RunRegistry:
    """In-process single-run-at-a-time registry."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.current: dict | None = None

    async def start(
        self,
        target_url: str,
        categories: list[str] | None,
        limit: int,
        pacing_s: float,
        shuffle: bool,
        max_prompt_chars: int = 0,
        platform: str = "",
        platform_label: str = "",
        recommended_runner: str = "",
        host_page_url: str = "",
        identity: str = "browser",
        custom_headers: str = "",
    ) -> str:
        async with self._lock:
            if self.current is not None and not self.current["state"].done:
                raise HTTPException(
                    status_code=409,
                    detail=f"a run is already active (run_id={self.current['state'].run_id})",
                )

            run_id = secrets.token_hex(8)
            cancel_event = asyncio.Event()
            queue: asyncio.Queue = asyncio.Queue()
            state = RunState(
                run_id=run_id,
                target_url=target_url,
                pacing_s=pacing_s,
                cancel_event=cancel_event,
                queue=queue,
                counters=Counters(),
                max_prompt_chars=max_prompt_chars,
                platform=platform,
                platform_label=platform_label,
                recommended_runner=recommended_runner,
                host_page_url=host_page_url,
                identity=identity,
                custom_headers=parse_custom(custom_headers),
            )

            history: list[dict] = []
            subscribers: list[asyncio.Queue] = []
            history_lock = asyncio.Lock()
            seq_counter = itertools.count(1)

            async def fanout() -> None:
                while True:
                    evt = await queue.get()
                    # Same critical section as subscriber registration below
                    # (stream()) so an event can never land in both the
                    # snapshot and a live subscriber's queue (or in neither).
                    async with history_lock:
                        evt["seq"] = next(seq_counter)
                        history.append(evt)
                        if len(history) > 5000:
                            del history[:1000]
                        for sub in list(subscribers):
                            try:
                                sub.put_nowait(evt)
                            except asyncio.QueueFull:
                                pass
                    if evt["type"] == "run_complete":
                        break

            fanout_task = asyncio.create_task(fanout())

            # Pick runner: browser for SaaS-platform bots (Ada etc.), HTTP
            # for everything else. Default is HTTP for back-compat with
            # runs started without a platform classification.
            if recommended_runner == "browser":
                from .runner_browser import run_batch_browser
                runner_task = asyncio.create_task(run_batch_browser(
                    state=state, categories=categories,
                    limit=limit, shuffle=shuffle,
                ))
            else:
                runner_task = asyncio.create_task(run_batch(
                    state=state, categories=categories,
                    limit=limit, shuffle=shuffle,
                ))

            self.current = {
                "state": state,
                "history": history,
                "subscribers": subscribers,
                "history_lock": history_lock,
                "fanout_task": fanout_task,
                "runner_task": runner_task,
            }
            return run_id

    def get(self, run_id: str) -> dict:
        if self.current is None or self.current["state"].run_id != run_id:
            raise HTTPException(status_code=404, detail="unknown run_id")
        return self.current

    async def stop(self, run_id: str) -> None:
        entry = self.get(run_id)
        entry["state"].cancel_event.set()

    async def pause(self, run_id: str) -> None:
        entry = self.get(run_id)
        state = entry["state"]
        state.paused = True
        state.unpause_event.clear()

    async def resume(self, run_id: str, pacing_s: float | None = None) -> None:
        entry = self.get(run_id)
        state = entry["state"]
        if pacing_s is not None:
            state.pacing_s = pacing_s
        state.paused = False
        state.unpause_event.set()


@dataclass
class JudgePass:
    run_id: str
    model: str
    cancel_event: asyncio.Event
    queue: asyncio.Queue
    history: list[dict] = _field(default_factory=list)
    subscribers: list[asyncio.Queue] = _field(default_factory=list)
    done: bool = False
    summary: dict | None = None
    runner_task: asyncio.Task | None = None
    history_lock: asyncio.Lock = _field(default_factory=asyncio.Lock)
    _seq_counter: itertools.count = _field(default_factory=lambda: itertools.count(1))


class JudgeRegistry:
    """Single-judge-pass-at-a-time registry, mirroring RunRegistry."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.config: JudgeConfig | None = None
        self.current: JudgePass | None = None

    def configure(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        provider_id: str = DEFAULT_PROVIDER_ID,
    ) -> None:
        self.config = JudgeConfig(api_key=api_key, model=model, base_url=base_url, provider_id=provider_id)

    def ready(self) -> bool:
        return self.config is not None and bool(self.config.api_key)

    async def start(self, run_id: str, results_path: Path) -> JudgePass:
        if not self.ready():
            raise HTTPException(status_code=400, detail="judge not configured")
        async with self._lock:
            if self.current is not None and not self.current.done:
                raise HTTPException(
                    status_code=409,
                    detail=f"judge already running for run_id={self.current.run_id}",
                )
            cancel_event = asyncio.Event()
            queue: asyncio.Queue = asyncio.Queue()
            jp = JudgePass(
                run_id=run_id,
                model=self.config.model,  # type: ignore[union-attr]
                cancel_event=cancel_event,
                queue=queue,
            )
            self.current = jp
            # Keep a strong ref — asyncio only holds a weak ref to tasks, so
            # an unreferenced task can be GC'd mid-flight.
            jp.runner_task = asyncio.create_task(self._drive(jp, results_path))
            return jp

    async def _drive(self, jp: JudgePass, results_path: Path) -> None:
        from .judge import judge_run

        async def on_verdict(v) -> None:
            evt = {
                "type": "judge_verdict",
                "data": {
                    "seq": v.seq,
                    "verdict": v.verdict,
                    "rationale": v.rationale,
                    "model": v.model,
                    "latency_ms": v.latency_ms,
                    "ts": v.ts,
                },
            }
            async with jp.history_lock:
                evt["seq"] = next(jp._seq_counter)
                jp.history.append(evt)
                for sub in list(jp.subscribers):
                    try:
                        sub.put_nowait(evt)
                    except asyncio.QueueFull:
                        pass

        try:
            summary = await judge_run(
                jsonl_path=results_path,
                config=self.config,  # type: ignore[arg-type]
                on_verdict=on_verdict,
            )
            jp.summary = summary
            complete = {"type": "judge_complete", "data": summary}
        except Exception as e:
            complete = {"type": "judge_error", "data": {"message": f"{type(e).__name__}: {e}"}}
        async with jp.history_lock:
            complete["seq"] = next(jp._seq_counter)
            jp.history.append(complete)
            for sub in list(jp.subscribers):
                try:
                    sub.put_nowait(complete)
                except asyncio.QueueFull:
                    pass
        jp.done = True

    def get(self, run_id: str) -> JudgePass:
        if self.current is None or self.current.run_id != run_id:
            raise HTTPException(status_code=404, detail="no judge pass for that run_id")
        return self.current


judge_registry = JudgeRegistry()

def _seed_judge_from_env() -> None:
    """Restore the judge selection saved by /api/judge/config, else guess."""
    saved_provider = _os.environ.get("JUDGE_PROVIDER_ID")
    if saved_provider:
        try:
            key = _os.environ.get(provider_env_var(saved_provider))
        except ValueError:
            key = None
        if key:
            judge_registry.configure(
                api_key=key,
                model=_os.environ.get("JUDGE_MODEL") or DEFAULT_MODEL,
                base_url=_os.environ.get("JUDGE_BASE_URL") or DEFAULT_BASE_URL,
                provider_id=saved_provider,
            )
            return
    # No saved selection (e.g. a key set by hand in .env) — last resort.
    # Prefer .env file order: the last "*_API_KEY" line in the file is the
    # most recently added provider, which approximates "last configured" for
    # .env files written before JUDGE_PROVIDER_ID started being persisted.
    catalog = _read_cached_catalog() or []
    var_to_provider: dict[str, str] = {}
    for provider_id in BASE_URLS:
        try:
            var_to_provider[provider_env_var(provider_id)] = provider_id
        except ValueError:
            continue  # e.g. "google-ai" isn't a valid <PROVIDER>_API_KEY identifier
    env_file = load_env_file(ENV_FILE)
    for var_name in reversed(list(env_file)):
        provider_id = var_to_provider.get(var_name)
        key = env_file.get(var_name)
        if not provider_id or not key:
            continue
        row = next((r for r in catalog if r["provider_id"] == provider_id), None)
        judge_registry.configure(
            api_key=key,
            model=row["model_id"] if row else DEFAULT_MODEL,
            base_url=row["base_url"] if row else BASE_URLS[provider_id],
            provider_id=provider_id,
        )
        return
    # No .env on disk (or nothing usable in it) — shell-only environment:
    # scan every known provider for a present API key in BASE_URLS order.
    for provider_id, base_url in BASE_URLS.items():
        try:
            key = _os.environ.get(provider_env_var(provider_id))
        except ValueError:
            continue
        if not key:
            continue
        row = next((r for r in catalog if r["provider_id"] == provider_id), None)
        judge_registry.configure(
            api_key=key,
            model=row["model_id"] if row else DEFAULT_MODEL,
            base_url=row["base_url"] if row else base_url,
            provider_id=provider_id,
        )
        return


_seed_judge_from_env()

registry = RunRegistry()


class StartRunBody(BaseModel):
    target_url: str = Field(..., min_length=1)
    categories: list[str] | None = None
    limit: int = Field(20, ge=1, le=2000)
    pacing_s: float = Field(3.0, ge=0.0, le=120.0)
    # Skip prompts longer than this many characters (0 = no cap).
    max_prompt_chars: int = Field(0, ge=0, le=100000)
    shuffle: bool = True
    # Optional platform metadata from a prior /api/discover call. Lets the
    # backend skip re-discovery and route to the right runner.
    platform: str = ""
    platform_label: str = ""
    recommended_runner: str = ""
    host_page_url: str = ""
    identity: str = "browser"
    custom_headers: str = ""

    @field_validator("target_url")
    @classmethod
    def _validate_target_url(cls, v: str) -> str:
        return validate_public_url(v)

    @field_validator("host_page_url")
    @classmethod
    def _validate_host_page_url(cls, v: str) -> str:
        # Optional, but when set it is handed to page.goto() in the browser
        # runner — a real navigation, so it needs the same guard as
        # target_url or it is a way around it (file://, link-local, ...).
        return validate_public_url(v) if v else v

    @field_validator("identity")
    @classmethod
    def _validate_identity(cls, v: str) -> str:
        return v if v in ("browser", "honest", "custom") else "browser"


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/categories")
async def categories() -> JSONResponse:
    """Return category names with counts from prompts.json."""
    if not PROMPTS_FILE.exists():
        raise HTTPException(status_code=500, detail="prompts.json not found")
    prompts = await _run_blocking(
        lambda: json.loads(PROMPTS_FILE.read_text(encoding="utf-8"))
    )
    counts = CounterCol(p.get("category", "?") for p in prompts)
    return JSONResponse({
        "categories": [
            {"name": name, "count": count}
            for name, count in sorted(counts.items(), key=lambda kv: -kv[1])
        ],
        "total": len(prompts),
    })


class NewPromptBody(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000)
    category: str = Field(..., min_length=1, max_length=64)
    source: str = "user"
    reference: str | None = Field(default=None, max_length=500)


class UpdatePromptBody(BaseModel):
    text: str | None = None
    category: str | None = None
    source: str | None = None
    reference: str | None = Field(default=None, max_length=500)


@app.get("/api/prompts")
async def list_prompts(
    q: str = "",
    category: str = "",
    offset: int = 0,
    limit: int = 100,
) -> JSONResponse:
    """Paginated list with optional substring search + category filter."""
    from .prompts_store import load_prompts as _load
    rows = await _run_blocking(_load, PROMPTS_FILE)
    if category:
        rows = [r for r in rows if r.get("category") == category]
    # Effective text = what run.py actually sends (fill_prompt_slots fills
    # unfilled template slots at send time; see run.py:172). `text` on disk is
    # never touched, since `id` is a hash of it (prompts_store.py).
    if q:
        # Search matches what fires, not just what's stored, so a miss on the
        # stored text has to be re-checked against the filled text. The `or`
        # short-circuits, so the fill only runs on rows the cheap checks miss.
        ql = q.lower()
        rows = [
            r for r in rows
            if ql in (r.get("text", "") or "").lower()
            or ql in (r.get("source", "") or "").lower()
            or ql in (r.get("id", "") or "").lower()
            or ql in fill_prompt_slots(r.get("text", "") or "").lower()
        ]
    total = len(rows)
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0
    # Only the returned page is filled — browsing does not pay for 1481 rows.
    page = []
    for r in rows[offset:offset + limit]:
        row = dict(r)
        eff = fill_prompt_slots(row.get("text", "") or "")
        row["text_effective"] = eff
        row["slot_filled"] = eff != row.get("text", "")
        page.append(row)
    return JSONResponse({"prompts": page, "total": total, "offset": offset, "limit": limit})


@app.post("/api/prompts")
async def create_prompt(body: NewPromptBody) -> JSONResponse:
    from .prompts_store import add_prompt
    try:
        async with _prompts_lock:
            rec = await _run_blocking(
                add_prompt,
                PROMPTS_FILE,
                text=body.text,
                category=body.category,
                source=body.source,
                reference=body.reference,
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return JSONResponse(rec)


@app.put("/api/prompts/{prompt_id}")
async def edit_prompt(prompt_id: str, body: UpdatePromptBody) -> JSONResponse:
    from .prompts_store import update_prompt
    try:
        async with _prompts_lock:
            rec = await _run_blocking(
                update_prompt,
                PROMPTS_FILE,
                prompt_id,
                text=body.text,
                category=body.category,
                source=body.source,
                reference=body.reference,
            )
    except KeyError:
        raise HTTPException(status_code=404, detail="prompt not found") from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return JSONResponse(rec)


@app.delete("/api/prompts/{prompt_id}")
async def remove_prompt(prompt_id: str) -> JSONResponse:
    from .prompts_store import delete_prompt
    try:
        async with _prompts_lock:
            await _run_blocking(delete_prompt, PROMPTS_FILE, prompt_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="prompt not found") from None
    return JSONResponse({"status": "deleted", "id": prompt_id})


class ImportPromptsBody(BaseModel):
    prompts: list[Any] = Field(default_factory=list)


@app.post("/api/prompts/import")
async def import_prompts(body: ImportPromptsBody) -> JSONResponse:
    """Bulk-import prompts. Validates each item against NewPromptBody's rules,
    dedupes by normalized-text hash against the existing corpus, and does a
    single save at the end. A malformed item lands in `errors` without
    aborting the rest of the batch.
    """
    if len(body.prompts) > 5000:
        raise HTTPException(status_code=400, detail="too many prompts (max 5000 per import)")

    from scripts.build_corpus import text_hash

    from .prompts_store import ALLOWED_CATEGORIES, load_prompts, new_prompt_id, save_prompts

    added: list[dict[str, Any]] = []
    skipped_duplicates = 0
    errors: list[dict[str, Any]] = []

    async with _prompts_lock:
        prompts = await _run_blocking(load_prompts, PROMPTS_FILE)
        seen = {text_hash(p.get("text", "")) for p in prompts}

        for i, item in enumerate(body.prompts):
            try:
                parsed = NewPromptBody.model_validate(item)
                if parsed.category not in ALLOWED_CATEGORIES:
                    raise ValueError(f"category must be one of {ALLOWED_CATEGORIES}")
                text = parsed.text.strip()
                if not text:
                    raise ValueError("text required")
            except Exception as e:
                errors.append({"index": i, "reason": str(e)})
                continue

            h = text_hash(text)
            if h in seen:
                skipped_duplicates += 1
                continue
            seen.add(h)

            rec: dict[str, Any] = {
                "id": new_prompt_id(prompts),
                "category": parsed.category,
                "source": (parsed.source or "user").strip()[:200] or "user",
                "text": text,
            }
            ref = (parsed.reference or "").strip()
            if ref:
                rec["reference"] = ref
            prompts.append(rec)
            added.append(rec)

        if added:
            await _run_blocking(save_prompts, PROMPTS_FILE, prompts)

    return JSONResponse({
        "added": len(added),
        "skipped_duplicates": skipped_duplicates,
        "errors": errors,
        "ids": [r["id"] for r in added],
    })


class JudgeConfigBody(BaseModel):
    api_key: str | None = None
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    provider_id: str = DEFAULT_PROVIDER_ID
    clear: bool = False

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, v: str) -> str:
        # Scheme only — NOT validate_public_url. This URL receives the API key
        # and the captured transcripts, so the scheme matters, but a private
        # host is legitimate: README documents self-hosted OpenAI-compatible
        # judges (Ollama et al), which live on localhost or the LAN.
        from urllib.parse import urlparse
        if v and urlparse(v).scheme not in ("http", "https"):
            raise ValueError("base_url scheme must be http or https")
        return v


@app.post("/api/judge/config")
async def judge_config(body: JudgeConfigBody) -> JSONResponse:
    from .judge import JUDGE_ENV_KEYS, clear_api_key_from_env, save_judge_config_to_env
    if body.clear:
        # Clear the provider that is actually configured — the body's default
        # would otherwise leave a non-openai key behind in .env.
        provider_id = judge_registry.config.provider_id if judge_registry.config else body.provider_id
        try:
            clear_api_key_from_env(ENV_FILE, provider_id=provider_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid provider_id") from None
        for var in (provider_env_var(provider_id), *JUDGE_ENV_KEYS):
            _os.environ.pop(var, None)
        judge_registry.config = None
        return JSONResponse({"status": "cleared"})
    if not body.api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    try:
        save_judge_config_to_env(
            ENV_FILE, body.api_key, body.model, body.base_url, body.provider_id
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid judge config") from None
    judge_registry.configure(
        api_key=body.api_key, model=body.model, base_url=body.base_url, provider_id=body.provider_id
    )
    return JSONResponse({"status": "ready", "model": body.model, "provider_id": body.provider_id})


@app.get("/api/judge/status")
async def judge_status() -> JSONResponse:
    if not judge_registry.ready():
        return JSONResponse({"ready": False})
    cur = judge_registry.current
    return JSONResponse({
        "ready": True,
        "model": judge_registry.config.model,  # type: ignore[union-attr]
        "provider_id": judge_registry.config.provider_id,  # type: ignore[union-attr]
        "base_url": judge_registry.config.base_url,  # type: ignore[union-attr]
        "current_run_id": cur.run_id if cur and not cur.done else None,
    })


@app.get("/api/judge/catalog")
async def judge_catalog(refresh: bool = False) -> JSONResponse:
    from .judge import fetch_catalog
    rows = await fetch_catalog(force_refresh=refresh)
    return JSONResponse({"models": rows, "total": len(rows)})


@app.post("/api/judge/{run_id}")
async def judge_start(run_id: str) -> JSONResponse:
    run_entry = registry.get(run_id)
    results_path: Path | None = run_entry["state"].results_path
    if results_path is None or not results_path.exists():
        raise HTTPException(status_code=400, detail="run has no results file yet")
    jp = await judge_registry.start(run_id=run_id, results_path=results_path)
    return JSONResponse({"run_id": run_id, "status": "judging", "model": jp.model})


@app.get("/api/judge/stream/{run_id}")
async def judge_stream(run_id: str, request: Request) -> StreamingResponse:
    jp = judge_registry.get(run_id)
    sub: asyncio.Queue = asyncio.Queue(maxsize=10000)
    async with jp.history_lock:
        snapshot = list(jp.history)
        jp.subscribers.append(sub)

    last_id = _parse_last_event_id(request)
    if last_id is not None:
        snapshot = [e for e in snapshot if e.get("seq", 0) > last_id]

    is_done = jp.done

    async def gen():
        try:
            for evt in snapshot:
                yield _format_sse(evt)
            if is_done:
                return
            heartbeat_at = asyncio.get_event_loop().time() + 15
            while True:
                if await request.is_disconnected():
                    return
                timeout = max(0.1, heartbeat_at - asyncio.get_event_loop().time())
                try:
                    evt = await asyncio.wait_for(sub.get(), timeout=timeout)
                    yield _format_sse(evt)
                    if evt["type"] in ("judge_complete", "judge_error"):
                        return
                except TimeoutError:
                    yield _format_sse({"type": "heartbeat", "data": {}})
                    heartbeat_at = asyncio.get_event_loop().time() + 15
        finally:
            try:
                jp.subscribers.remove(sub)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _load_run(jsonl_path: Path) -> tuple[dict, list[dict]] | None:
    """Return (meta, records) for a results file, regraded with today's classifier.

    Returns None for empty/unreadable JSONL. Prefers the .meta.json sidecar for
    the meta; falls back to synthesizing one for legacy files.

    Every row is passed through `regrade_record` on the way out, and the meta's
    cached counters are re-tallied from the regraded rows. Grades are written
    once at capture time, so without this a classifier fix never reaches a run
    already on disk — and a report keeps showing the verdict of whatever code
    the server had loaded on the day the scan ran. Read-only: the file itself is
    left alone (`scripts/rescore.py --apply` is the one that rewrites it).
    """
    if jsonl_path.stat().st_size == 0:
        return None
    records: list[dict] = []
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(regrade_record(json.loads(line)))
            except json.JSONDecodeError:
                continue

    meta_path = jsonl_path.with_suffix(".meta.json")
    meta: dict | None = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            meta = None  # corrupt sidecar — fall through and synthesize
    if meta is None:
        if not records:
            return None
        total = len(records)
        meta = {
            "run_id": jsonl_path.stem.removeprefix("ui-"),
            "target_url": records[0].get("url", ""),
            "categories": sorted({
                r.get("category") for r in records if r.get("category")
            }),
            "started_at": records[0].get("timestamp"),
            "finished_at": records[-1].get("timestamp"),
            # Synthesized from a complete JSONL log, so the run did finish. Provenance
            # ("this meta was reconstructed") is carried separately by the `source` field.
            "status": "completed",
            "counters": {"total_done": total, "total": total},
            "findings": [],
            "judge": None,
        }

    # Re-tally from the regraded rows so the headline can never disagree with the
    # rows underneath it. total/total_done stay as captured — they're run
    # progress, not a grade.
    counters = meta.get("counters")
    if isinstance(counters, dict):
        before = dict(counters)
        counters.update(count_outcomes(records))
        # A cached narrative was written from the old numbers. If they moved it
        # now argues against its own report — drop it so the view regenerates.
        if counters != before:
            meta.pop("narrative", None)
    # All derived here rather than stored by the runner: a regrade moves which
    # turn broke first and which row is worst, and a sidecar copy would then
    # contradict its own rows.
    meta["session_cascade"] = session_cascade(records)
    # The headline is the single worst finding, never an average — one data
    # leak among fifty clean turns is a 2% rate and a notifiable breach, and
    # the percentage is the less important of those two facts.
    meta["worst_finding"] = worst_finding(records)
    meta["owner_questions"] = owner_questions(records)
    meta["remediation"] = [
        {"category": cat, "text": CATEGORY_REMEDIATION[cat]}
        for cat in sorted(
            {
                normalize_category(r.get("category"))
                for r in records
                if r.get("injection_outcome") == "compromised"
            },
            key=harm_rank,
        )
        if cat in CATEGORY_REMEDIATION
    ]
    return meta, records


@app.get("/api/runs")
async def list_runs() -> JSONResponse:
    """List every saved scan. Newest first."""
    if not RESULTS_DIR.exists():
        return JSONResponse([])
    rows = []
    for jsonl in RESULTS_DIR.glob("ui-*.jsonl"):
        loaded = _load_run(jsonl)
        if loaded is None:
            continue
        meta, _ = loaded
        source = "meta" if jsonl.with_suffix(".meta.json").exists() else "legacy"
        rows.append({
            "run_id": meta["run_id"],
            "target_url": meta["target_url"],
            "status": meta["status"],
            "started_at": meta["started_at"],
            "finished_at": meta["finished_at"],
            "counters": meta["counters"],
            "source": source,
        })
    rows.sort(key=lambda r: r.get("started_at") or "", reverse=True)
    return JSONResponse(rows)


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str) -> JSONResponse:
    """Return meta + all per-prompt records for one saved run."""
    if not run_id or "/" in run_id or ".." in run_id:
        raise HTTPException(status_code=400, detail="invalid run_id")
    jsonl = RESULTS_DIR / f"ui-{run_id}.jsonl"
    if not jsonl.exists():
        raise HTTPException(status_code=404, detail="unknown run_id")
    loaded = _load_run(jsonl)
    if loaded is None:
        raise HTTPException(status_code=404, detail="empty results")
    meta, records = loaded
    return JSONResponse({"meta": meta, "records": records})


def _safe_run_paths(run_id: str) -> tuple[Path, Path]:
    """Resolve the (jsonl, sidecar-meta) paths for a run_id, rejecting traversal."""
    if not run_id or "/" in run_id or ".." in run_id or "\\" in run_id:
        raise HTTPException(status_code=400, detail="invalid run_id")
    jsonl = RESULTS_DIR / f"ui-{run_id}.jsonl"
    meta_path = jsonl.with_suffix(".meta.json")
    return jsonl, meta_path


@app.post("/api/runs/{run_id}/narrative")
async def generate_run_narrative(run_id: str) -> JSONResponse:
    """Generate (or replay cached) LLM strengths/weaknesses narrative for a run."""
    jsonl, meta_path = _safe_run_paths(run_id)
    if not jsonl.exists():
        raise HTTPException(status_code=404, detail="unknown run_id")
    cfg = judge_registry.config
    if not cfg or not cfg.api_key:
        raise HTTPException(status_code=400, detail="no judge model configured")
    loaded = _load_run(jsonl)
    if loaded is None:
        raise HTTPException(status_code=404, detail="empty results")
    meta, records = loaded
    from openai import AsyncOpenAI

    from .narrative import generate_narrative
    client = AsyncOpenAI(api_key=cfg.api_key, base_url=cfg.base_url)
    try:
        narrative = await generate_narrative(meta, records, client, cfg.model)
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}") from exc
    meta["narrative"] = narrative
    try:
        meta_path.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    return JSONResponse(narrative)


@app.delete("/api/runs/{run_id}")
async def delete_run(run_id: str) -> JSONResponse:
    """Delete a single saved run (both jsonl + sidecar meta)."""
    jsonl, meta_path = _safe_run_paths(run_id)
    removed = False
    if jsonl.exists():
        jsonl.unlink()
        removed = True
    if meta_path.exists():
        meta_path.unlink()
        removed = True
    if not removed:
        raise HTTPException(status_code=404, detail="unknown run_id")
    return JSONResponse({"status": "deleted", "run_id": run_id})


class DeleteRunsBody(BaseModel):
    ids: list[str] = Field(default_factory=list)


@app.post("/api/runs/delete")
async def delete_runs(body: DeleteRunsBody) -> JSONResponse:
    """Bulk-delete runs. Returns lists of {deleted, missing} ids."""
    deleted: list[str] = []
    missing: list[str] = []
    for rid in body.ids:
        try:
            jsonl, meta_path = _safe_run_paths(rid)
        except HTTPException:
            missing.append(rid)
            continue
        any_removed = False
        if jsonl.exists():
            jsonl.unlink()
            any_removed = True
        if meta_path.exists():
            meta_path.unlink()
            any_removed = True
        (deleted if any_removed else missing).append(rid)
    return JSONResponse({"deleted": deleted, "missing": missing})


@app.get("/api/current")
async def current_run() -> JSONResponse:
    """Return the currently active (not-yet-done) run, if any.

    Lets the browser reconnect to an in-progress scan after a page refresh —
    the server-side run task keeps going regardless of who's listening.
    """
    cur = registry.current
    if cur is None:
        return JSONResponse({"run_id": None})
    state: RunState = cur["state"]
    if state.done:
        return JSONResponse({"run_id": None})
    c = state.counters
    return JSONResponse({
        "run_id": state.run_id,
        "paused": bool(state.paused),
        "counters": {
            "reached": c.reached,
            "blocked": c.blocked,
            "compromised": c.compromised,
            "refused": c.refused,
            "total_done": c.total_done,
            "total": c.total,
        },
    })


class DiscoverBody(BaseModel):
    url: str = Field(..., min_length=1, max_length=2000)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_public_url(v)


@app.post("/api/discover")
async def discover(body: DiscoverBody) -> JSONResponse:
    """Discover the chat-API URL for a site by scraping its HTML + JS bundles.

    No-op safe to call on a full URL too (it'll just discover everything
    chat-shaped on that domain).
    """
    from .discover import discover_chat_endpoint, result_to_dict
    result = await discover_chat_endpoint(body.url)
    return JSONResponse(result_to_dict(result))


@app.post("/api/run")
async def start_run(body: StartRunBody) -> JSONResponse:
    run_id = await registry.start(
        target_url=body.target_url,
        categories=body.categories,
        limit=body.limit,
        pacing_s=body.pacing_s,
        shuffle=body.shuffle,
        max_prompt_chars=body.max_prompt_chars,
        platform=body.platform,
        platform_label=body.platform_label,
        recommended_runner=body.recommended_runner,
        host_page_url=body.host_page_url,
        identity=body.identity,
        custom_headers=body.custom_headers,
    )
    return JSONResponse({"run_id": run_id})


@app.post("/api/stop/{run_id}")
async def stop_run(run_id: str) -> JSONResponse:
    await registry.stop(run_id)
    return JSONResponse({"ok": True})


class ResumeBody(BaseModel):
    pacing_s: float | None = Field(None, ge=0.0, le=120.0)


@app.post("/api/pause/{run_id}")
async def pause_run(run_id: str) -> JSONResponse:
    await registry.pause(run_id)
    return JSONResponse({"ok": True, "paused": True})


@app.post("/api/resume/{run_id}")
async def resume_run(run_id: str, body: ResumeBody | None = None) -> JSONResponse:
    pacing_s = body.pacing_s if body else None
    await registry.resume(run_id, pacing_s=pacing_s)
    return JSONResponse({"ok": True, "paused": False, "pacing_s": pacing_s})


@app.get("/api/stream/{run_id}")
async def stream(run_id: str, request: Request) -> StreamingResponse:
    entry = registry.get(run_id)
    history: list[dict] = entry["history"]
    subscribers: list[asyncio.Queue] = entry["subscribers"]
    history_lock: asyncio.Lock = entry["history_lock"]
    sub: asyncio.Queue = asyncio.Queue(maxsize=10000)
    async with history_lock:
        snapshot = list(history)
        subscribers.append(sub)

    last_id = _parse_last_event_id(request)
    if last_id is not None:
        snapshot = [e for e in snapshot if e.get("seq", 0) > last_id]

    state: RunState = entry["state"]
    run_done = state.done

    async def gen():
        try:
            for evt in snapshot:
                yield _format_sse(evt)
            if run_done:
                return
            heartbeat_at = asyncio.get_event_loop().time() + 15
            while True:
                if await request.is_disconnected():
                    return
                timeout = max(0.1, heartbeat_at - asyncio.get_event_loop().time())
                try:
                    evt = await asyncio.wait_for(sub.get(), timeout=timeout)
                    yield _format_sse(evt)
                    if evt["type"] == "run_complete":
                        return
                except TimeoutError:
                    yield _format_sse({"type": "heartbeat", "data": {}})
                    heartbeat_at = asyncio.get_event_loop().time() + 15
        finally:
            try:
                subscribers.remove(sub)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/results/{run_id}")
async def results(run_id: str) -> Response:
    entry = registry.get(run_id)
    path: Path | None = entry["state"].results_path
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="no results yet")
    return FileResponse(str(path), media_type="application/x-ndjson", filename=path.name)


def _parse_last_event_id(request: Request) -> int | None:
    """Best-effort SSE resume: browsers auto-send Last-Event-ID on reconnect."""
    raw = request.headers.get("last-event-id")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _format_sse(evt: dict) -> bytes:
    payload = json.dumps(evt["data"], ensure_ascii=False)
    id_line = f"id: {evt['seq']}\n" if "seq" in evt else ""
    return f"{id_line}event: {evt['type']}\ndata: {payload}\n\n".encode()


def main() -> None:
    import uvicorn  # type: ignore
    # No auth on any endpoint (see .planning/codebase/CONCERNS.md). Must stay
    # bound to 127.0.0.1 unless/until an auth layer is added — do not change
    # host to 0.0.0.0 or expose this port on a shared/public network.
    uvicorn.run(
        "ui.server:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
