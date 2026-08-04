"""
Chat-endpoint discovery.

Given a bare domain or landing URL, fetch the HTML + same-origin JS bundles,
regex-scan for chat-API URL patterns, and validate the top candidates with
a benign POST probe.

The premise: chat widgets render in the browser, which means their endpoint
URL is shipped as a literal string in the JS bundle. We can read the same
bundles the browser reads — no execution required.

Pure-async, no FastAPI dependencies. Safe to import from a test or CLI.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .browser_profile import NAVIGATION, XHR

# Keywords that mark a path as plausibly chat-related. "ask" carries a
# lookbehind because bare `ask` matches task/mask/flask/basket — one noisy
# route like /per-task/foo can fill the whole probe budget with junk.
CHAT_KW = (r"chat|conversation|messages?|completion|stream|prompt|(?<![a-z])ask"
           r"|generate|reply|llm|gpt|claude|assistant")

# Inside a string literal, find a path or absolute URL containing a chat keyword.
PATH_RX = re.compile(
    r"""['"`](/[A-Za-z0-9_\-./]*(?:""" + CHAT_KW + r""")[A-Za-z0-9_\-./]*)['"`]""",
    re.IGNORECASE,
)
ABS_URL_RX = re.compile(
    r"""['"`](https?://[A-Za-z0-9_\-.]+/[A-Za-z0-9_\-./]*(?:""" + CHAT_KW + r""")[A-Za-z0-9_\-./]*)['"`]""",
    re.IGNORECASE,
)
# fetch("/x"), axios.post("/x"), .post('/x', ...), .get(`/x`) etc.
FETCH_CALL_RX = re.compile(
    r"""(?:fetch|axios(?:\.(?:post|get|put))?|\.(?:post|get|put))\s*\(\s*['"`]([^'"`]{2,300})['"`]""",
    re.IGNORECASE,
)
SCRIPT_SRC_RX = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
# Vite/Next split vendor chunks out of the entry bundle and reference them with
# <link rel="modulepreload"> instead of <script src>. Without this we scan only
# the entry chunk and miss whatever lazy chunk holds the chat call.
MODULEPRELOAD_RX = re.compile(
    r'<link[^>]+rel=["\']?modulepreload["\']?[^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
IFRAME_SRC_RX = re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# Subdomain prefixes worth probing when given a bare root domain. Ordered by
# how commonly we'd expect to find a chatbot living there.
SUBDOMAIN_HINTS = ("chat", "chatbot", "bot", "assistant", "ai", "support",
                   "help", "agent")

# Third-party chatbot widget providers. Many enterprise sites embed a SaaS
# chatbot (Ada, Intercom, Drift, etc.) whose API isn't on the host's domain.
# Each entry: how to detect the widget (signature regex), how to extract the
# customer-specific identifier ("handle"), and the API URL templates to try.
WIDGET_PROVIDERS: list[dict] = [
    {
        "name": "Ada",
        "signature_rx": re.compile(r"(?:static\.ada\.support|adaEmbed|window\.adaSettings)",
                                   re.IGNORECASE),
        # Page typically contains: handle: "customer-name" or "handle":"customer-name"
        "handle_rx": re.compile(r"""['"]?handle['"]?\s*[:=]\s*['"]([a-z0-9][a-z0-9_-]{1,80})['"]""",
                                re.IGNORECASE),
        "url_templates": [
            "https://{handle}.ada.support/api/v2/conversations",
            "https://{handle}.ada.support/chat/core/api/v2/conversations",
            "https://{handle}.ada.support/api/v1/conversations",
        ],
    },
    {
        "name": "Intercom",
        "signature_rx": re.compile(r"(?:widget\.intercom\.io|window\.intercomSettings|Intercom\()",
                                   re.IGNORECASE),
        "handle_rx": re.compile(r"""['"]?app_id['"]?\s*[:=]\s*['"]([a-z0-9]{4,20})['"]""",
                                re.IGNORECASE),
        "url_templates": [
            "https://api-iam.intercom.io/messenger/web/messages",
            "https://api-iam.intercom.io/messenger/web/conversations",
        ],
    },
    {
        "name": "Drift",
        "signature_rx": re.compile(r"(?:js\.driftt?\.com|window\.drift|drift\.load\()",
                                   re.IGNORECASE),
        "handle_rx": re.compile(r"""['"]?(?:org|orgId|driftt?\.load)['"]?\s*[:=\(]\s*['"]([a-z0-9_-]{4,40})['"]""",
                                re.IGNORECASE),
        "url_templates": [
            "https://customer.drift.com/api/conversation",
        ],
    },
    {
        "name": "Zendesk",
        "signature_rx": re.compile(r"(?:static\.zdassets\.com|zE\(|zopim)",
                                   re.IGNORECASE),
        "handle_rx": re.compile(r"""['"]?(?:account_key|subdomain)['"]?\s*[:=]\s*['"]([a-z0-9_-]{3,40})['"]""",
                                re.IGNORECASE),
        "url_templates": [
            "https://{handle}.zendesk.com/api/v2/chat/chats",
        ],
    },
]

# Backends where the chat rides a persistent socket rather than a POST-able
# HTTP route. When one of these is present and we found nothing, discovery
# didn't "fail to look hard enough" — there is no endpoint to find, and the
# only way in is to drive the page in a browser.
REALTIME_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("Convex", re.compile(r"convex\.cloud|Convex-Client", re.IGNORECASE)),
    ("Socket.IO", re.compile(r"socket\.io/\?EIO=|socket\.io-client", re.IGNORECASE)),
    ("Pusher", re.compile(r"ws\.pusherapp\.com|pusher\.com/app/|new Pusher\(", re.IGNORECASE)),
    ("Ably", re.compile(r"realtime\.ably\.io|ably-js", re.IGNORECASE)),
    ("Firebase", re.compile(r"firebaseio\.com|firestore\.googleapis\.com", re.IGNORECASE)),
    ("Supabase", re.compile(r"supabase\.co/realtime/", re.IGNORECASE)),
]

# Identity providers. An auth-gated app hides its chat route behind login, so
# an empty result says nothing about whether an endpoint exists.
AUTH_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("Auth0", re.compile(r"auth0-spa-js|@auth0/|[a-z0-9-]+\.auth0\.com", re.IGNORECASE)),
    ("Clerk", re.compile(r"clerk\.accounts\.dev|@clerk/", re.IGNORECASE)),
    ("Cognito", re.compile(r"cognito-idp\.[a-z0-9-]+\.amazonaws\.com", re.IGNORECASE)),
    ("Firebase Auth", re.compile(r"identitytoolkit\.googleapis\.com", re.IGNORECASE)),
]

MAX_BUNDLES = 25       # cap parallel fetches to avoid hammering
MAX_BUNDLE_BYTES = 5 * 1024 * 1024  # ignore bundles bigger than 5 MB
MAX_LANDINGS = 6       # cap total landing pages we'll scan (root + subdomains + iframes)
PROBE_TIMEOUT = 12.0
DISCOVERY_TIMEOUT = 25.0
TOP_N_PROBE = 8        # validate this many candidates with a real POST


@dataclass
class Candidate:
    url: str
    found_in: str             # source label (e.g. "landing.html" or bundle basename)
    in_fetch_call: bool       # was this matched inside a fetch()/axios call?
    score: int = 0
    probe_status: int = 0
    probe_body_snippet: str = ""
    verdict: str = "untested"  # untested | confirmed | likely | rejected


@dataclass
class DiscoveryResult:
    input_url: str
    landing_status: int
    bundles_scanned: int
    candidates: list[Candidate] = field(default_factory=list)
    best: Candidate | None = None
    duration_ms: int = 0
    error: str = ""
    # Platform classification — derived from best candidate after probing.
    # One of: "ada", "intercom", "drift", "zendesk", "thin_wrapper", or "" if none.
    platform: str = ""
    # Human-readable label, e.g. "Ada Chat Platform (SaaS)".
    platform_label: str = ""
    # Which runner type fits: "http" (a directly reachable chat API) or
    # "browser" (a SaaS widget that needs a real DOM). Empty when unknown.
    recommended_runner: str = ""
    # The page that hosts the widget (only meaningful for SaaS platforms).
    # Browser runner navigates here to drive the chat.
    host_page_url: str = ""
    # Realtime transports / identity providers seen in the page or bundles.
    realtime_backends: list[str] = field(default_factory=list)
    auth_providers: list[str] = field(default_factory=list)
    # Plain-English reason discovery came up empty, when we can name one.
    notes: str = ""


PLATFORM_LABELS = {
    "ada": ("Ada Chat Platform (SaaS)", "browser"),
    "intercom": ("Intercom Messenger (SaaS)", "browser"),
    "drift": ("Drift Conversations (SaaS)", "browser"),
    "zendesk": ("Zendesk Chat (SaaS)", "browser"),
    "thin_wrapper": ("First-party LLM endpoint", "http"),
}


def _classify_platform(best: Candidate | None) -> tuple[str, str, str, str]:
    """Return (platform_key, label, recommended_runner, host_page_url).

    Parses Candidate.found_in to detect widget-based bots (Ada/Intercom/etc.)
    vs first-party endpoints (thin wrapper). Empty tuple if no best candidate.
    """
    if best is None:
        return ("", "", "", "")
    src = best.found_in or ""
    if src.startswith("widget:"):
        # Format: "widget:Ada(host.example.com:landing)"
        provider_part, _, rest = src[len("widget:"):].partition("(")
        provider_key = provider_part.strip().lower()
        host_label = rest.rstrip(")")
        # host_label is like "help.cebupacificair.com:landing" — strip the suffix.
        host = host_label.split(":")[0] if host_label else ""
        host_page = f"https://{host}/" if host else ""
        label, runner = PLATFORM_LABELS.get(
            provider_key, (f"{provider_part} (SaaS widget)", "browser"),
        )
        return (provider_key, label, runner, host_page)
    # Otherwise: first-party endpoint (thin wrapper).
    label, runner = PLATFORM_LABELS["thin_wrapper"]
    return ("thin_wrapper", label, runner, "")


OnEvent = Callable[[str, dict], Awaitable[None]]


def _normalize_input(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url):
        url = "https://" + url
    return url


def is_bare_domain(url: str) -> bool:
    """True if the URL has no meaningful path — discovery worth triggering."""
    if not url:
        return False
    u = _normalize_input(url)
    try:
        p = urlparse(u)
    except Exception:
        return False
    return p.path in ("", "/") and not p.query


# Simple eTLD+1 heuristic. Doesn't handle multi-label public suffixes (co.uk,
# com.au) perfectly, but covers the common case without requiring the
# tldextract dependency. False-positives here mean we'd probe one extra
# subdomain — not a correctness problem.
_TWO_LABEL_TLDS = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "ne.jp", "com.au",
    "net.au", "org.au", "com.br", "com.mx", "co.nz", "co.in", "com.sg",
}

def _root_domain(host: str) -> str:
    """Extract eTLD+1 from a host. 'chat.foo.example.com' -> 'example.com'."""
    if not host:
        return ""
    host = host.lower().split(":")[0]  # strip port
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tail = ".".join(labels[-2:])
    if tail in _TWO_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


def _is_subdomain_of(host: str, root: str) -> bool:
    """True if host == root OR host endswith '.root'."""
    if not host or not root:
        return False
    host = host.lower()
    root = root.lower()
    return host == root or host.endswith("." + root)


def _candidate_key(url: str) -> str:
    """Canonical form for dedupe: strip query+fragment, lowercase host."""
    p = urlparse(url)
    host = (p.netloc or "").lower()
    return f"{p.scheme}://{host}{p.path}"


def _score(c: Candidate, host: str, root: str) -> int:
    s = 0
    u = c.url.lower()
    candidate_host = urlparse(c.url).netloc.lower()
    if c.in_fetch_call:
        s += 60
    if "/api/" in u:
        s += 25
    if "/api/chat" in u or u.endswith("/chat") or "/chat/" in u:
        s += 35
    if "/conversation" in u or "/message" in u:
        s += 15
    if "/completion" in u or "/generate" in u or "/stream" in u:
        s += 10
    if candidate_host == host:
        s += 10  # same-host bonus
    elif _is_subdomain_of(candidate_host, root):
        s += 8   # same-root bonus (e.g. chatbot.example.com)
    # Chatbot-named subdomain is a strong locality signal.
    first_label = candidate_host.split(".")[0] if "." in candidate_host else ""
    if first_label in SUBDOMAIN_HINTS:
        s += 20
    # Penalize obvious non-API matches.
    for skip in (".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".map",
                 "googletag", "analytics", "/static/", "/_next/static/"):
        if skip in u:
            s -= 80
            break
    return s


async def _fetch_text(client: httpx.AsyncClient, url: str) -> tuple[int, str]:
    try:
        r = await client.get(url, headers=NAVIGATION)
        body = r.text
        if len(body) > MAX_BUNDLE_BYTES:
            return r.status_code, ""
        return r.status_code, body if 200 <= r.status_code < 300 else ""
    except httpx.RequestError:
        return 0, ""


async def _probe_candidate(client: httpx.AsyncClient, c: Candidate) -> None:
    """Send a benign POST. Classify the response."""
    p = urlparse(c.url)
    origin = f"{p.scheme}://{p.netloc}"
    headers = {
        **XHR,
        "Content-Type": "application/json",
        "Origin": origin,
        "Referer": origin + "/",
    }
    body = json.dumps({"message": "hello", "history": []})
    try:
        r = await client.post(c.url, headers=headers, content=body)
    except httpx.RequestError:
        c.verdict = "untested"
        return

    c.probe_status = r.status_code
    snippet = r.text[:240]
    c.probe_body_snippet = snippet
    lower = snippet.lower()

    if 200 <= r.status_code < 300:
        ctype = r.headers.get("content-type", "").lower()
        if "json" in ctype or any(k in lower for k in
                                  ('"id"', '"message"', '"content"', '"role"',
                                   '"choice', '"reply"', '"response"')):
            c.verdict = "confirmed"
        else:
            c.verdict = "likely"
        return

    if r.status_code == 400 and any(k in lower for k in
                                    ("validation", "schema", "required", "invalid",
                                     "zod", "pydantic", "expected")):
        c.verdict = "likely"  # POST shape rejected — it IS a typed API
        return

    if r.status_code == 403:
        # Origin/CSRF allowlist — endpoint exists, recon will handle it.
        c.verdict = "likely"
        return

    if r.status_code == 401:
        c.verdict = "likely"  # auth-gated chat is still a chat
        return

    if r.status_code in (404, 405, 410, 501):
        c.verdict = "rejected"
        return

    c.verdict = "untested"


async def _probe_landing(
    client: httpx.AsyncClient, url: str,
) -> tuple[str, int, str]:
    """GET a landing URL. Returns (final_url_after_redirects, status, html)."""
    try:
        r = await client.get(url, headers=NAVIGATION)
        body = r.text if 200 <= r.status_code < 300 else ""
        if len(body) > MAX_BUNDLE_BYTES:
            body = ""
        return str(r.url), r.status_code, body
    except httpx.RequestError:
        return url, 0, ""


async def discover_chat_endpoint(
    input_url: str,
    on_event: OnEvent | None = None,
) -> DiscoveryResult:
    """Discover the chat API URL for a given site.

    Scans multiple landing pages: the input URL itself, plus same-root-domain
    iframes referenced from it, plus common chatbot-named subdomain prefixes
    (chat.foo.com, chatbot.foo.com, etc.) that respond to a GET probe.

    Returns a DiscoveryResult with ranked candidates; .best is the top pick
    if its verdict is confirmed or likely, else None.
    """
    norm = _normalize_input(input_url)
    if not norm:
        return DiscoveryResult(input_url=input_url, landing_status=0,
                               bundles_scanned=0, error="empty url")

    p = urlparse(norm)
    input_host = p.netloc.lower()
    root = _root_domain(input_host)
    t0 = time.time()

    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT,
        follow_redirects=True,
    ) as client:
        # Step 1: fetch the input URL's landing — but don't bail if it fails.
        # The main www may be behind a WAF that blocks plain HTTPS clients
        # (Akamai/Imperva fingerprinting) while subdomains are reachable.
        primary_final, primary_status, primary_html = await _probe_landing(client, norm)
        landings: list[tuple[str, str]] = []
        landing_hosts: set[str] = set()
        if primary_html:
            landings.append((primary_final, primary_html))
            landing_hosts.add(urlparse(primary_final).netloc.lower())
        if on_event:
            await on_event("html_fetched", {
                "url": primary_final, "status": primary_status,
                "bytes": len(primary_html),
                "skipped": not bool(primary_html),
            })

        # Step 2: parallel speculative landings — subdomain hints + iframes.
        # Run subdomain hints if input is a bare domain OR if the primary
        # landing failed (so we still have a chance against WAF-protected
        # sites with reachable subdomains).
        extra_landing_urls: list[str] = []
        if is_bare_domain(norm) or not primary_html:
            for prefix in SUBDOMAIN_HINTS:
                hint_host = f"{prefix}.{root}"
                if hint_host in landing_hosts:
                    continue
                extra_landing_urls.append(f"https://{hint_host}/")
        # Iframe srcs from the primary landing (same root only).
        if primary_html:
            for m in IFRAME_SRC_RX.finditer(primary_html):
                src = m.group(1)
                if src.startswith(("data:", "blob:", "javascript:", "#")):
                    continue
                full = urljoin(primary_final, src)
                full = full.split("#")[0]
                ihost = urlparse(full).netloc.lower()
                if not _is_subdomain_of(ihost, root) or ihost in landing_hosts:
                    continue
                extra_landing_urls.append(full)

        if extra_landing_urls:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*[_probe_landing(client, u) for u in extra_landing_urls]),
                    timeout=DISCOVERY_TIMEOUT,
                )
            except TimeoutError:
                results = []
            for final_url, _status, html in results:
                if not html or len(landings) >= MAX_LANDINGS:
                    continue
                h = urlparse(final_url).netloc.lower()
                if h in landing_hosts:
                    continue
                landings.append((final_url, html))
                landing_hosts.add(h)
            if on_event:
                await on_event("extra_landings", {
                    "tried": len(extra_landing_urls),
                    "kept": len(landings) - 1,
                    "hosts": sorted(landing_hosts),
                })

        # Step 3: collect script srcs from all landings (same-root only).
        script_urls: list[str] = []
        seen: set[str] = set()
        for landing_url, html in landings:
            for s in SCRIPT_SRC_RX.findall(html) + MODULEPRELOAD_RX.findall(html):
                if s.startswith(("data:", "blob:", "javascript:")):
                    continue
                full = urljoin(landing_url, s)
                host_of = urlparse(full).netloc.lower()
                if host_of and not _is_subdomain_of(host_of, root):
                    continue  # skip true cross-origin (third-party CDNs)
                if full in seen:
                    continue
                seen.add(full)
                script_urls.append(full)
                if len(script_urls) >= MAX_BUNDLES:
                    break
            if len(script_urls) >= MAX_BUNDLES:
                break

        # Step 4: fetch bundles in parallel
        bundles: list[tuple[str, str]] = []
        if script_urls:
            async def fetch_one(u: str) -> tuple[str, str]:
                status, body = await _fetch_text(client, u)
                return u, body
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*[fetch_one(u) for u in script_urls]),
                    timeout=DISCOVERY_TIMEOUT,
                )
                bundles = [(u, b) for u, b in results if b]
            except TimeoutError:
                pass
        if on_event:
            await on_event("bundles_fetched", {
                "count": len(bundles), "landings": len(landings),
            })

        # Step 5: extract candidates from every landing + every bundle.
        candidates: dict[str, Candidate] = {}

        def _add(u: str, source: str, in_fetch: bool, base_for_relative: str) -> None:
            if not u:
                return
            if u.startswith("/"):
                bp = urlparse(base_for_relative)
                full = f"{bp.scheme}://{bp.netloc}{u}"
            elif u.startswith("http"):
                full = u
            else:
                return
            full = full.split("#")[0].split("?")[0]
            if len(full) > 400:
                return
            # Reject cross-root candidates UNLESS they're in a fetch() call.
            # A fetch-call match is a strong signal — likely a third-party
            # widget endpoint (Ada, Intercom, Drift, etc.). Bare string
            # matches across origins are too noisy (random analytics URLs).
            chost = urlparse(full).netloc.lower()
            if chost and not _is_subdomain_of(chost, root) and not in_fetch:
                return
            key = _candidate_key(full)
            existing = candidates.get(key)
            if existing is None:
                candidates[key] = Candidate(
                    url=full, found_in=source, in_fetch_call=in_fetch,
                )
            elif in_fetch and not existing.in_fetch_call:
                existing.in_fetch_call = True
                existing.found_in = source

        def _scan(text: str, source: str, base_for_relative: str) -> None:
            for m in FETCH_CALL_RX.finditer(text):
                u = m.group(1)
                if re.search(CHAT_KW, u, re.IGNORECASE):
                    _add(u, source, True, base_for_relative)
            for m in PATH_RX.finditer(text):
                _add(m.group(1), source, False, base_for_relative)
            for m in ABS_URL_RX.finditer(text):
                _add(m.group(1), source, False, base_for_relative)

        for landing_url, html in landings:
            label = urlparse(landing_url).netloc + (urlparse(landing_url).path or "/")
            _scan(html, f"landing:{label}", landing_url)
        for url, body in bundles:
            name = urlparse(url).netloc + ":" + (urlparse(url).path.rsplit("/", 1)[-1] or url)
            _scan(body, name, url)

        # Step 5b: detect third-party widget providers (Ada, Intercom, ...)
        # by scanning landings + bundles. When matched, extract the
        # customer handle and add the provider's known API URL templates
        # as high-confidence candidates.
        widget_hits: list[tuple[str, str]] = []  # (provider, handle)
        all_text_sources = (
            [(label, html) for label, html in
             ((urlparse(u).netloc + ":landing", h) for u, h in landings)]
            + [(urlparse(u).netloc + ":" + (urlparse(u).path.rsplit("/", 1)[-1] or u), b)
               for u, b in bundles]
        )
        for provider in WIDGET_PROVIDERS:
            for source, text in all_text_sources:
                if not provider["signature_rx"].search(text):
                    continue
                m = provider["handle_rx"].search(text)
                if not m:
                    continue
                handle = m.group(1)
                if (provider["name"], handle) in widget_hits:
                    continue
                widget_hits.append((provider["name"], handle))
                for tmpl in provider["url_templates"]:
                    url = tmpl.format(handle=handle)
                    key = _candidate_key(url)
                    if key in candidates:
                        candidates[key].in_fetch_call = True  # boost it
                    else:
                        candidates[key] = Candidate(
                            url=url, found_in=f"widget:{provider['name']}({source})",
                            in_fetch_call=True,
                        )
                break  # one match per provider is enough
        if on_event and widget_hits:
            await on_event("widgets_detected", {
                "hits": [{"provider": p, "handle": h} for p, h in widget_hits],
            })

        # Step 5c: realtime transports + auth gating. Cheap to check over text
        # we already hold, and it's the difference between "we found nothing"
        # and "nothing of this shape exists here".
        realtime_backends = sorted({
            name for name, rx in REALTIME_SIGNATURES
            if any(rx.search(text) for _, text in all_text_sources)
        })
        auth_providers = sorted({
            name for name, rx in AUTH_SIGNATURES
            if any(rx.search(text) for _, text in all_text_sources)
        })

        # Step 6: score
        for c in candidates.values():
            c.score = _score(c, input_host, root)

        ranked = sorted(candidates.values(), key=lambda c: -c.score)
        ranked = [c for c in ranked if c.score > -50]

        if on_event:
            await on_event("candidates_extracted", {
                "count": len(ranked), "top": [c.url for c in ranked[:5]],
            })

        # Step 7: probe top N
        to_probe = ranked[:TOP_N_PROBE]
        await asyncio.gather(*[_probe_candidate(client, c) for c in to_probe])

        VERDICT_BOOST = {
            "confirmed": 1000, "likely": 200,
            "untested": 0, "rejected": -1000,
        }
        for c in ranked:
            c.score += VERDICT_BOOST.get(c.verdict, 0)
        ranked.sort(key=lambda c: -c.score)

        best = None
        if ranked and ranked[0].verdict in ("confirmed", "likely"):
            best = ranked[0]

        platform, platform_label, runner, host_page = _classify_platform(best)

        notes = ""
        if best is None:
            reasons = []
            if realtime_backends:
                reasons.append(
                    f"chat runs over a realtime socket ({', '.join(realtime_backends)}), "
                    "so there is no HTTP endpoint to POST to — drive the page in a browser"
                )
            if auth_providers:
                reasons.append(
                    f"the app is login-gated ({', '.join(auth_providers)}), "
                    "so the chat route is only reachable after sign-in"
                )
            notes = "; ".join(reasons)

        return DiscoveryResult(
            input_url=norm,
            landing_status=primary_status,
            bundles_scanned=len(bundles),
            candidates=ranked,
            best=best,
            duration_ms=int((time.time() - t0) * 1000),
            platform=platform,
            platform_label=platform_label,
            recommended_runner=runner,
            host_page_url=host_page,
            realtime_backends=realtime_backends,
            auth_providers=auth_providers,
            notes=notes,
        )


def candidate_to_dict(c: Candidate) -> dict:
    return {
        "url": c.url,
        "found_in": c.found_in,
        "in_fetch_call": c.in_fetch_call,
        "score": c.score,
        "probe_status": c.probe_status,
        "probe_body_snippet": c.probe_body_snippet,
        "verdict": c.verdict,
    }


def result_to_dict(r: DiscoveryResult) -> dict:
    return {
        "input_url": r.input_url,
        "landing_status": r.landing_status,
        "bundles_scanned": r.bundles_scanned,
        "duration_ms": r.duration_ms,
        "error": r.error,
        "platform": r.platform,
        "platform_label": r.platform_label,
        "recommended_runner": r.recommended_runner,
        "host_page_url": r.host_page_url,
        "realtime_backends": r.realtime_backends,
        "auth_providers": r.auth_providers,
        "notes": r.notes,
        "best": candidate_to_dict(r.best) if r.best else None,
        "candidates": [candidate_to_dict(c) for c in r.candidates[:10]],
    }
