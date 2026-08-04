"""Operator custom headers must not leak past the target.

Playwright's extra_http_headers is context-wide, so wiring custom headers
there would send an `Authorization:` line to every CDN, font and analytics
origin the widget page loads. The route handler exists to stop that; these
tests cover the host predicate and prove the handler actually applies.
"""
import asyncio

import pytest

from ui.runner_browser import _scope_headers_to_target, belongs_to_target


@pytest.mark.parametrize("url", [
    "https://acme.com/chat",
    "https://acme.com:8443/chat",
    "https://widget.acme.com/embed.js",
    "https://a.b.acme.com/x",
])
def test_target_and_its_subdomains_belong(url):
    assert belongs_to_target(url, "acme.com")


@pytest.mark.parametrize("url", [
    "https://cdn.cloudflare.com/lib.js",       # the leak this prevents
    "https://fonts.googleapis.com/css",
    "https://acme.com.evil.test/x",            # suffix-confusion, not a subdomain
    "https://notacme.com/x",
    "https://ada.support/widget",              # cross-origin widget: documented gap
])
def test_third_party_origins_do_not_belong(url):
    assert not belongs_to_target(url, "acme.com")


def test_empty_target_never_matches():
    # No host page => scope to nothing rather than to everything.
    assert not belongs_to_target("https://acme.com/x", "")


class _FakeRoute:
    def __init__(self):
        self.headers = None
        self.continued = False

    async def continue_(self, headers=None):
        self.continued = True
        self.headers = headers


class _FakeRequest:
    def __init__(self, url):
        self.url = url
        self.headers = {"user-agent": "chrome", "accept": "*/*"}


class _FakeContext:
    def __init__(self):
        self.handler = None

    async def route(self, _pattern, handler):
        self.handler = handler


def _run(url, extra=None):
    ctx = _FakeContext()
    extra = extra if extra is not None else {"Authorization": "Bearer secret"}
    asyncio.run(_scope_headers_to_target(ctx, "https://acme.com/support", extra))
    route, request = _FakeRoute(), _FakeRequest(url)
    asyncio.run(ctx.handler(route, request))
    return route


def test_target_request_receives_the_custom_headers():
    route = _run("https://acme.com/api/chat")
    assert route.continued
    assert route.headers["authorization"] == "Bearer secret"
    assert route.headers["user-agent"] == "chrome"  # existing headers preserved


def test_third_party_request_does_not_receive_them():
    route = _run("https://cdn.cloudflare.com/lib.js")
    assert route.continued
    # continue_ called with no header override at all — nothing added.
    assert route.headers is None
