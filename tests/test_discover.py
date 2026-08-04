"""Tests for the pure/deterministic helpers in ui/discover.py.

Anything that requires a live HTTP round-trip (_fetch_text, _probe_candidate,
_probe_landing, discover_chat_endpoint) is out of scope here — those are
integration-level and need a real or mocked httpx client.
"""
from __future__ import annotations

from ui.discover import (
    Candidate,
    DiscoveryResult,
    _candidate_key,
    _classify_platform,
    _is_subdomain_of,
    _normalize_input,
    _root_domain,
    _score,
    candidate_to_dict,
    is_bare_domain,
    result_to_dict,
)

# ---- _normalize_input ----

def test_normalize_input_adds_scheme():
    assert _normalize_input("example.com") == "https://example.com"


def test_normalize_input_keeps_existing_scheme():
    assert _normalize_input("http://example.com") == "http://example.com"
    assert _normalize_input("https://example.com/path") == "https://example.com/path"


def test_normalize_input_strips_whitespace():
    assert _normalize_input("  example.com  ") == "https://example.com"


def test_normalize_input_empty():
    assert _normalize_input("") == ""
    assert _normalize_input("   ") == ""


# ---- is_bare_domain ----

def test_is_bare_domain_true_for_root():
    assert is_bare_domain("https://example.com") is True
    assert is_bare_domain("https://example.com/") is True
    assert is_bare_domain("example.com") is True


def test_is_bare_domain_false_with_path():
    assert is_bare_domain("https://example.com/chat") is False


def test_is_bare_domain_false_with_query():
    assert is_bare_domain("https://example.com/?x=1") is False


def test_is_bare_domain_empty():
    assert is_bare_domain("") is False


# ---- _root_domain ----

def test_root_domain_simple():
    assert _root_domain("example.com") == "example.com"


def test_root_domain_subdomain():
    assert _root_domain("chat.foo.example.com") == "example.com"


def test_root_domain_two_label_tld():
    assert _root_domain("shop.example.co.uk") == "example.co.uk"


def test_root_domain_strips_port():
    assert _root_domain("example.com:8080") == "example.com"


def test_root_domain_empty():
    assert _root_domain("") == ""


# ---- _is_subdomain_of ----

def test_is_subdomain_of_exact_match():
    assert _is_subdomain_of("example.com", "example.com") is True


def test_is_subdomain_of_true_subdomain():
    assert _is_subdomain_of("chat.example.com", "example.com") is True


def test_is_subdomain_of_unrelated():
    assert _is_subdomain_of("evil.com", "example.com") is False


def test_is_subdomain_of_empty_args():
    assert _is_subdomain_of("", "example.com") is False
    assert _is_subdomain_of("example.com", "") is False


# ---- _candidate_key ----

def test_candidate_key_strips_query_and_fragment():
    assert _candidate_key("https://x.com/api/chat?foo=1#frag") == "https://x.com/api/chat"


def test_candidate_key_lowercases_host():
    assert _candidate_key("https://X.COM/api/chat") == "https://x.com/api/chat"


# ---- _score ----

def test_score_fetch_call_bonus():
    c = Candidate(url="https://example.com/api/chat", found_in="x", in_fetch_call=True)
    s = _score(c, "example.com", "example.com")
    assert s > 0


def test_score_same_host_bonus_beats_unrelated_host():
    same_host = Candidate(url="https://example.com/x", found_in="x", in_fetch_call=False)
    unrelated_host = Candidate(url="https://random-cdn.io/x", found_in="x", in_fetch_call=False)
    assert _score(same_host, "example.com", "example.com") > _score(unrelated_host, "example.com", "example.com")


def test_score_subdomain_hint_bonus():
    c = Candidate(url="https://chat.example.com/widget", found_in="x", in_fetch_call=False)
    s = _score(c, "example.com", "example.com")
    assert s > 0  # subdomain-hint + same-root bonuses outweigh no /api/ match


def test_score_penalizes_static_assets():
    c = Candidate(url="https://example.com/static/chat-widget.css", found_in="x", in_fetch_call=False)
    s = _score(c, "example.com", "example.com")
    assert s < 0


def test_score_path_keyword_bonuses():
    chat_path = Candidate(url="https://example.com/api/chat", found_in="x", in_fetch_call=False)
    plain_api = Candidate(url="https://example.com/api/other", found_in="x", in_fetch_call=False)
    assert _score(chat_path, "example.com", "example.com") > _score(plain_api, "example.com", "example.com")


# ---- _classify_platform ----

def test_classify_platform_no_candidate():
    assert _classify_platform(None) == ("", "", "", "")


def test_classify_platform_widget():
    c = Candidate(
        url="https://acme.ada.support/api/v2/conversations",
        found_in="widget:Ada(help.example.com:landing)",
        in_fetch_call=True,
    )
    platform, label, runner, host_page = _classify_platform(c)
    assert platform == "ada"
    assert label == "Ada Chat Platform (SaaS)"
    assert runner == "browser"
    assert host_page == "https://help.example.com/"


def test_classify_platform_unknown_widget_falls_back_to_generic_label():
    c = Candidate(url="https://x.foo.com/api", found_in="widget:Foo(bar.com:landing)", in_fetch_call=True)
    platform, label, runner, host_page = _classify_platform(c)
    assert platform == "foo"
    assert label == "Foo (SaaS widget)"
    assert runner == "browser"


def test_classify_platform_thin_wrapper():
    c = Candidate(url="https://example.com/api/chat", found_in="landing:example.com/", in_fetch_call=True)
    platform, label, runner, host_page = _classify_platform(c)
    assert platform == "thin_wrapper"
    assert label == "First-party LLM endpoint"
    assert runner == "http"
    assert host_page == ""


# ---- candidate_to_dict / result_to_dict ----

def test_candidate_to_dict():
    c = Candidate(
        url="https://example.com/api/chat", found_in="landing:example.com/",
        in_fetch_call=True, score=90, probe_status=200,
        probe_body_snippet='{"reply":"hi"}', verdict="confirmed",
    )
    d = candidate_to_dict(c)
    assert d == {
        "url": "https://example.com/api/chat",
        "found_in": "landing:example.com/",
        "in_fetch_call": True,
        "score": 90,
        "probe_status": 200,
        "probe_body_snippet": '{"reply":"hi"}',
        "verdict": "confirmed",
    }


def test_result_to_dict_with_best_and_truncated_candidates():
    best = Candidate(
        url="https://example.com/api/chat", found_in="x", in_fetch_call=True, score=100, verdict="confirmed"
    )
    candidates = [best] + [
        Candidate(url=f"https://example.com/c{i}", found_in="x", in_fetch_call=False, score=-i)
        for i in range(15)
    ]
    result = DiscoveryResult(
        input_url="https://example.com", landing_status=200, bundles_scanned=3,
        candidates=candidates, best=best, duration_ms=42,
        platform="thin_wrapper", platform_label="First-party LLM endpoint",
        recommended_runner="http", host_page_url="",
    )
    d = result_to_dict(result)
    assert d["best"]["url"] == "https://example.com/api/chat"
    assert len(d["candidates"]) == 10  # capped at top 10
    assert d["platform"] == "thin_wrapper"


def test_result_to_dict_no_best():
    result = DiscoveryResult(input_url="https://example.com", landing_status=0, bundles_scanned=0)
    d = result_to_dict(result)
    assert d["best"] is None
    assert d["candidates"] == []


# ---------------------------------------------------------------------------
# Keyword false positives + realtime/auth fingerprints
# ---------------------------------------------------------------------------

def test_chat_kw_does_not_match_ask_inside_a_word():
    # Regression: /per-task/foo used to match on "ask" and crowd out the
    # probe budget with routes that are plainly not chat APIs.
    import re

    from ui.discover import CHAT_KW
    rx = re.compile(CHAT_KW, re.IGNORECASE)
    for junk in ("/per-task/eurips", "/unmask", "/flask", "/basket/items"):
        assert not rx.search(junk), junk
    for real in ("/api/ask", "/v1/ask-question", "/livechat/send", "/api/chat"):
        assert rx.search(real), real


def test_realtime_and_auth_signatures_match_a_convex_auth0_bundle():
    from ui.discover import AUTH_SIGNATURES, REALTIME_SIGNATURES
    bundle = 'const a="https://example-deployment-000.convex.cloud";import"@auth0/auth0-spa-js"'
    assert [n for n, rx in REALTIME_SIGNATURES if rx.search(bundle)] == ["Convex"]
    assert [n for n, rx in AUTH_SIGNATURES if rx.search(bundle)] == ["Auth0"]


def test_modulepreload_links_are_treated_as_bundles():
    from ui.discover import MODULEPRELOAD_RX
    html = '<link rel="modulepreload" crossorigin href="/assets/vendor-ab12.js">'
    assert MODULEPRELOAD_RX.findall(html) == ["/assets/vendor-ab12.js"]
