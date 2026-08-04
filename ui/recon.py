"""
Recon / passport negotiation.

Before any prompt is sent, probe the target with a benign request and
adaptively spoof headers (and harvest session state) until either:
  - the server returns 200 (we have a working passport), or
  - we run out of spoof variants for the current block layer.

Each rung of the ladder is recorded as a LayerEvent so the UI can show
the discovered security posture: which control fired, what value beat it.

Pure-async, no FastAPI dependencies — testable in isolation.
"""
from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .browser_profile import CHROME_UA

BENIGN_PROBE_BODY = {"message": "hello", "history": []}
PROBE_TIMEOUT = 15.0


@dataclass
class LayerEvent:
    """One step in the recon ladder — what we tried and what happened."""
    layer: str               # e.g., "Origin allowlist"
    spoof_header: str        # e.g., "Origin" (empty for harvest steps)
    spoof_value: str         # e.g., "https://www.example.com"
    verdict: str             # bypassed | still-blocked | hard-block | no-bypass-known | unknown
    http_before: int
    http_after: int
    note: str = ""


@dataclass
class Passport:
    target_url: str
    headers: dict[str, str]
    cookies: dict[str, str] = field(default_factory=dict)
    layers: list[LayerEvent] = field(default_factory=list)
    final_status: int = 0
    success: bool = False


# ---- block-layer classification (recon-internal; mirrors classifiers.py
# but returns the canonical layer key our SPOOF_VARIANTS dict expects) ----

_HARD_BLOCK_NOTES: dict[str, str] = {
    "Bot manager (Akamai/Shape)": (
        "Akamai Bot Manager / Shape sensor - no header set can pass. "
        "Set Runner = browser."
    ),
    "Connection timeout": (
        "No response before timeout. Target may be dropping non-browser "
        "clients silently."
    ),
}


def classify_block_layer(http_status: int, body: str, cookies: str = "") -> str | None:
    """Return canonical layer key for this response, or None if 2xx / unknown.

    Distinct from classifiers.detect_findings: this one is keyed for the
    spoof registry (one key per known defense), not for human findings.

    `cookies` is an optional semicolon-joined dump of cookie names seen on the
    client so far. Akamai's `_abck` cookie lands in the jar even when the body
    is an opaque challenge page, so callers with a live client should pass it.
    """
    if http_status == 0:
        return "Connection timeout"
    body_l = body.lower()

    # Checked BEFORE the 2xx early-return below, because Akamai and Shape serve
    # their interstitial with HTTP 200 — a 2xx is not proof we got through. Left
    # unchecked, recon declared the passport negotiated and the runner fired the
    # whole corpus into a challenge page, scoring every turn as "reached".
    #
    # Markers are taken from the live page: `scf-akamai-*` are its stylesheet
    # classes, `chlgeId` its challenge-id variable. Bare "akamai" is deliberately
    # NOT used — the genuine site's CSP references akamaihd.net, and a bot reply
    # discussing Akamai would otherwise be misread as a block.
    if "scf-akamai" in body_l or "chlgeid" in body_l:
        return "Bot manager (Akamai/Shape)"

    if 200 <= http_status < 300:
        return None

    # Bot-manager check runs before the 403 chain below on purpose — but stays
    # scoped to signals that don't collide with it. The literal string
    # "akamai" is deliberately excluded here: the existing WAF (Akamai) 403
    # branch below already owns that keyword and a test pins it
    # (test_classify_block_layer_waf_akamai), so widening this check to bare
    # "akamai" text would shadow it. `_abck`/`perfdrive` are the actual
    # bot-manager signals (cookie name, CDN domain) and don't appear in that
    # generic-WAF fixture.
    #
    # Only the BODY is a strong signal here. The cookie jar is checked further
    # down, because `_abck` is set on every response from an Akamai-fronted
    # host — including 404s, 405s and schema rejections. Treating its mere
    # presence as a block told the operator "set Runner = browser" when the
    # real fault was a wrong endpoint or a wrong body shape.
    if http_status == 410 or "_abck" in body_l or "perfdrive" in body_l:
        return "Bot manager (Akamai/Shape)"

    if http_status == 403:
        if "origin" in body_l or "cors" in body_l:
            return "Origin allowlist"
        if "referer" in body_l or "referrer" in body_l:
            return "Referer check"
        if "user-agent" in body_l or "bot" in body_l or "automation" in body_l:
            return "UA filter"
        if "csrf" in body_l or "xsrf" in body_l or "token" in body_l:
            return "CSRF token required"
        if "cloudflare" in body_l or "cf-ray" in body_l or "attention required" in body_l:
            return "WAF (Cloudflare)"
        if "akamai" in body_l:
            return "WAF (Akamai)"
        if "forbidden" in body_l:
            return "Origin allowlist"  # best guess; most common cause
    if http_status == 401:
        return "Authentication required"
    if http_status == 429:
        return "Rate limit"
    if http_status == 400 and ("invalid_type" in body_l or "schema" in body_l):
        return "Schema validation"
    # Weak signal, last resort: an Akamai/Shape cookie plus a status that
    # actually denotes refusal. A 404/405/400 carrying the same cookie means
    # the endpoint is wrong, not that we were blocked — leave those alone so
    # the operator goes looking for the right endpoint instead of the browser
    # runner.
    cookies_l = cookies.lower()
    if http_status in (403, 503) and ("_abck" in cookies_l or "perfdrive" in cookies_l):
        return "Bot manager (Akamai/Shape)"
    return None


# ---- spoof variants ----
# Each entry: (header_name, value_fn(host, headers) -> str)
# value_fn may take 1 arg (host) or 2 args (host, current_headers).

def _origin_variants() -> list[tuple[str, Callable[..., str]]]:
    return [
        ("Origin", lambda host: f"https://{host}"),
        ("Origin", lambda host: f"https://www.{host}"),
        ("Origin", lambda host: f"https://app.{host}"),
        ("Origin", lambda host: f"https://chat.{host}"),
        ("Origin", lambda host: f"https://{host.removeprefix('www.')}"),
        ("Origin", lambda host: "null"),
    ]


SPOOF_VARIANTS: dict[str, list[tuple[str, Callable[..., str]]]] = {
    "Origin allowlist": _origin_variants(),
    "Referer check": [
        ("Referer", lambda host, headers: (headers.get("Origin") or f"https://{host}") + "/"),
        ("Referer", lambda host: f"https://{host}/"),
        ("Referer", lambda host: f"https://www.{host}/"),
    ],
    "UA filter": [
        ("User-Agent", lambda host: CHROME_UA),
    ],
    "WAF (Cloudflare)": [
        # No clean header bypass for CF challenges — UA helps for simple cases.
        ("User-Agent", lambda host: CHROME_UA),
    ],
    "WAF (Akamai)": [
        ("User-Agent", lambda host: CHROME_UA),
    ],
    # "CSRF token required" is handled by a dedicated harvest step (below).
    # "Authentication required" / "Rate limit" / "Schema validation" -> hard blocks
    # for the recon phase (no auto-bypass without creds / waiting / payload change).
}

HARD_BLOCK_LAYERS = {
    "Authentication required",
    "Rate limit",
    "Schema validation",
    "Connection timeout",
    "Bot manager (Akamai/Shape)",
}


def _call_value_fn(fn: Callable[..., str], host: str, headers: dict[str, str]) -> str:
    try:
        return fn(host, headers)  # type: ignore[call-arg]
    except TypeError:
        return fn(host)  # type: ignore[call-arg]


# ---- landing-page harvest (cookies + CSRF tokens) ----

_META_CSRF_RX = re.compile(
    r'<meta\s+name=["\'](?:csrf-token|csrf|_csrf)["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_CSRF_RX = re.compile(
    r'["\'](?:csrf|csrfToken|csrf_token|xsrfToken)["\']\s*:\s*["\']([^"\']{8,256})["\']',
    re.IGNORECASE,
)


async def _harvest_landing(
    client: httpx.AsyncClient,
    target_url: str,
    headers: dict[str, str],
) -> dict[str, str]:
    """GET the landing page, return token headers to add.

    Cookies are already auto-stored on `client.cookies` by httpx — caller
    doesn't need to do anything to persist them; subsequent requests on
    the same client inherit the jar.
    """
    p = urlparse(target_url)
    landing = f"{p.scheme}://{p.netloc}/"
    try:
        resp = await client.get(
            landing,
            headers={"User-Agent": headers.get("User-Agent", CHROME_UA)},
        )
        body = resp.text
    except httpx.RequestError:
        return {}

    new_headers: dict[str, str] = {}

    m = _META_CSRF_RX.search(body)
    if m:
        new_headers["X-CSRF-Token"] = m.group(1)
    else:
        m = _JS_CSRF_RX.search(body)
        if m:
            new_headers["X-CSRF-Token"] = m.group(1)

    # XSRF-TOKEN cookie pattern (Laravel, Angular, NestJS, etc.)
    for cookie_name in ("XSRF-TOKEN", "csrf-token", "_csrf"):
        if cookie_name in client.cookies:
            new_headers.setdefault("X-XSRF-Token", client.cookies[cookie_name])

    return new_headers


# ---- probe ----

async def _probe(
    client: httpx.AsyncClient,
    target_url: str,
    headers: dict[str, str],
) -> tuple[int, str]:
    """Send the benign body to target_url, return (status, body_text)."""
    try:
        resp = await client.post(
            target_url,
            headers={**headers, "Content-Type": "application/json"},
            content=json.dumps(BENIGN_PROBE_BODY),
        )
        return resp.status_code, resp.text
    except httpx.RequestError as e:
        return 0, f"__network_error__: {type(e).__name__}: {e}"


# ---- main entry point ----

OnAttempt = Callable[[LayerEvent], Awaitable[None]]


async def negotiate_passport(
    target_url: str,
    on_attempt: OnAttempt | None = None,
    max_steps: int = 12,
) -> Passport:
    """Walk the spoof ladder until 200 OK or no variant helps.

    Args:
      target_url: full URL of the chat endpoint (e.g. https://x.com/api/chat).
      on_attempt: optional async callback invoked once per LayerEvent so the
                  UI can stream recon progress in real time.
      max_steps: safety cap on total ladder rungs (prevents infinite loops
                 from misclassification).
    """
    host = urlparse(target_url).netloc
    headers: dict[str, str] = {}
    layers: list[LayerEvent] = []

    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT,
        follow_redirects=True,
    ) as client:
        status, body = await _probe(client, target_url, headers)

        for _ in range(max_steps):
            if 200 <= status < 300:
                break

            layer = classify_block_layer(status, body, cookies=";".join(client.cookies.keys()))
            if layer is None:
                evt = LayerEvent(
                    layer=f"Unknown defense (HTTP {status})",
                    spoof_header="",
                    spoof_value="",
                    verdict="unknown",
                    http_before=status,
                    http_after=status,
                    note=body[:160],
                )
                layers.append(evt)
                if on_attempt:
                    await on_attempt(evt)
                break

            if layer in HARD_BLOCK_LAYERS:
                evt = LayerEvent(
                    layer=layer,
                    spoof_header="",
                    spoof_value="",
                    verdict="hard-block",
                    http_before=status,
                    http_after=status,
                    note=_HARD_BLOCK_NOTES.get(
                        layer,
                        "no auto-bypass (would need credentials, waiting, or payload change)",
                    ),
                )
                layers.append(evt)
                if on_attempt:
                    await on_attempt(evt)
                break

            if layer == "CSRF token required":
                token_headers = await _harvest_landing(client, target_url, headers)
                if not token_headers:
                    evt = LayerEvent(
                        layer=layer,
                        spoof_header="",
                        spoof_value="",
                        verdict="no-bypass-known",
                        http_before=status,
                        http_after=status,
                        note="landing page yielded no CSRF token or session cookie",
                    )
                    layers.append(evt)
                    if on_attempt:
                        await on_attempt(evt)
                    break
                new_headers = {**headers, **token_headers}
                new_status, new_body = await _probe(client, target_url, new_headers)
                new_layer = classify_block_layer(
                    new_status, new_body, cookies=";".join(client.cookies.keys())
                )
                evt = LayerEvent(
                    layer=layer,
                    spoof_header=", ".join(token_headers.keys()),
                    spoof_value=", ".join(f"{k}={v[:24]}…" for k, v in token_headers.items()),
                    verdict=("bypassed" if new_layer != layer else "still-blocked"),
                    http_before=status,
                    http_after=new_status,
                    note="harvested from landing page",
                )
                layers.append(evt)
                if on_attempt:
                    await on_attempt(evt)
                if evt.verdict == "bypassed":
                    headers = new_headers
                    status, body = new_status, new_body
                    continue
                break

            variants = SPOOF_VARIANTS.get(layer, [])
            if not variants:
                evt = LayerEvent(
                    layer=layer,
                    spoof_header="",
                    spoof_value="",
                    verdict="no-bypass-known",
                    http_before=status,
                    http_after=status,
                )
                layers.append(evt)
                if on_attempt:
                    await on_attempt(evt)
                break

            bypassed = False
            for header_name, value_fn in variants:
                value = _call_value_fn(value_fn, host, headers)
                trial_headers = {**headers, header_name: value}
                new_status, new_body = await _probe(client, target_url, trial_headers)
                new_layer = classify_block_layer(new_status, new_body, cookies=";".join(client.cookies.keys()))
                if new_layer != layer:
                    evt = LayerEvent(
                        layer=layer,
                        spoof_header=header_name,
                        spoof_value=value,
                        verdict="bypassed",
                        http_before=status,
                        http_after=new_status,
                    )
                    layers.append(evt)
                    if on_attempt:
                        await on_attempt(evt)
                    headers = trial_headers
                    status, body = new_status, new_body
                    bypassed = True
                    break

            if not bypassed:
                evt = LayerEvent(
                    layer=layer,
                    spoof_header=variants[0][0],
                    spoof_value="(all variants exhausted)",
                    verdict="hard-block",
                    http_before=status,
                    http_after=status,
                )
                layers.append(evt)
                if on_attempt:
                    await on_attempt(evt)
                break

        cookies = {k: v for k, v in client.cookies.items()}

    return Passport(
        target_url=target_url,
        headers=headers,
        cookies=cookies,
        layers=layers,
        final_status=status,
        success=(200 <= status < 300),
    )


# ---- inline escalation (used by runner.py during the prompt loop) ----

async def escalate_once(
    target_url: str,
    current_headers: dict[str, str],
    current_cookies: dict[str, str],
    block_layer: str,
    on_attempt: OnAttempt | None = None,
) -> tuple[dict[str, str], dict[str, str], LayerEvent] | None:
    """Try ONE spoof variant for `block_layer` not already in current_headers.

    Returns (new_headers, new_cookies, LayerEvent) on success, None if no
    variant helps (so caller can record the layer as a hard inline-block).
    """
    if block_layer in HARD_BLOCK_LAYERS:
        return None
    host = urlparse(target_url).netloc

    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT,
        follow_redirects=True,
        cookies=current_cookies,
    ) as client:
        if block_layer == "CSRF token required":
            token_headers = await _harvest_landing(client, target_url, current_headers)
            if not token_headers:
                return None
            trial = {**current_headers, **token_headers}
            new_status, new_body = await _probe(client, target_url, trial)
            new_layer = classify_block_layer(new_status, new_body, cookies=";".join(client.cookies.keys()))
            if new_layer != block_layer:
                evt = LayerEvent(
                    layer=block_layer,
                    spoof_header=", ".join(token_headers.keys()),
                    spoof_value=", ".join(f"{k}={v[:24]}…" for k, v in token_headers.items()),
                    verdict="bypassed",
                    http_before=0,
                    http_after=new_status,
                    note="inline escalation (harvested mid-scan)",
                )
                if on_attempt:
                    await on_attempt(evt)
                new_cookies = {k: v for k, v in client.cookies.items()}
                return trial, new_cookies, evt
            return None

        variants = SPOOF_VARIANTS.get(block_layer, [])
        for header_name, value_fn in variants:
            value = _call_value_fn(value_fn, host, current_headers)
            if current_headers.get(header_name) == value:
                continue  # already tried this exact value
            trial = {**current_headers, header_name: value}
            new_status, new_body = await _probe(client, target_url, trial)
            new_layer = classify_block_layer(new_status, new_body, cookies=";".join(client.cookies.keys()))
            if new_layer != block_layer:
                evt = LayerEvent(
                    layer=block_layer,
                    spoof_header=header_name,
                    spoof_value=value,
                    verdict="bypassed",
                    http_before=0,
                    http_after=new_status,
                    note="inline escalation",
                )
                if on_attempt:
                    await on_attempt(evt)
                new_cookies = {k: v for k, v in client.cookies.items()}
                return trial, new_cookies, evt
        return None
