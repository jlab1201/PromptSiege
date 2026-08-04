"""Tests for the pure/deterministic helpers in ui/recon.py.

The network-driving pieces (_harvest_landing, _probe, negotiate_passport,
escalate_once) all need a live/mocked httpx client and are out of scope here.
"""
from __future__ import annotations

from ui.recon import (
    HARD_BLOCK_LAYERS,
    SPOOF_VARIANTS,
    _call_value_fn,
    _origin_variants,
    classify_block_layer,
)

# ---- classify_block_layer ----

def test_classify_block_layer_2xx_is_none():
    assert classify_block_layer(200, "anything") is None


def test_classify_block_layer_origin_allowlist():
    assert classify_block_layer(403, "bad Origin header") == "Origin allowlist"


def test_classify_block_layer_referer_check():
    assert classify_block_layer(403, "missing Referer") == "Referer check"


def test_classify_block_layer_ua_filter():
    assert classify_block_layer(403, "bot traffic blocked") == "UA filter"


def test_classify_block_layer_csrf():
    assert classify_block_layer(403, "csrf token invalid") == "CSRF token required"


def test_classify_block_layer_waf_cloudflare():
    assert classify_block_layer(403, "cf-ray: 12345, attention required") == "WAF (Cloudflare)"


def test_classify_block_layer_waf_akamai():
    assert classify_block_layer(403, "blocked by akamai") == "WAF (Akamai)"


def test_classify_block_layer_generic_forbidden_fallback():
    assert classify_block_layer(403, "403 forbidden") == "Origin allowlist"


def test_classify_block_layer_unmatched_403_is_none():
    assert classify_block_layer(403, "no recognizable keywords here") is None


def test_classify_block_layer_auth_required():
    assert classify_block_layer(401, "") == "Authentication required"


def test_classify_block_layer_rate_limit():
    assert classify_block_layer(429, "") == "Rate limit"


def test_classify_block_layer_schema_validation():
    assert classify_block_layer(400, "invalid_type on field x") == "Schema validation"


def test_classify_block_layer_unknown_status_is_none():
    assert classify_block_layer(500, "internal error") is None


# ---- _origin_variants ----

def test_origin_variants_produce_distinct_values():
    variants = _origin_variants()
    values = [_call_value_fn(fn, "example.com", {}) for _header, fn in variants]
    assert "https://example.com" in values
    assert "https://www.example.com" in values
    assert "https://app.example.com" in values
    assert "null" in values
    # all header names are "Origin"
    assert all(header == "Origin" for header, _fn in variants)


def test_origin_variants_strip_www_prefix():
    variants = _origin_variants()
    strip_fn = next(fn for _h, fn in variants if _call_value_fn(fn, "www.example.com", {}) == "https://example.com")
    assert _call_value_fn(strip_fn, "example.com", {}) == "https://example.com"


# ---- _call_value_fn ----

def test_call_value_fn_single_arg():
    assert _call_value_fn(lambda host: f"https://{host}", "x.com", {}) == "https://x.com"


def test_call_value_fn_two_arg_uses_headers():
    def fn(host, headers):
        return (headers.get("Origin") or f"https://{host}") + "/"

    assert _call_value_fn(fn, "x.com", {"Origin": "https://spoofed.com"}) == "https://spoofed.com/"
    assert _call_value_fn(fn, "x.com", {}) == "https://x.com/"


# ---- SPOOF_VARIANTS / HARD_BLOCK_LAYERS registry sanity ----

def test_hard_block_layers_have_no_spoof_variants():
    """Layers marked hard-block are exactly the ones with no bypass registered
    (Authentication required, Rate limit, Schema validation) — recon.py relies
    on this split to decide whether to even try spoofing."""
    for layer in HARD_BLOCK_LAYERS:
        assert layer not in SPOOF_VARIANTS


def test_spoof_variants_cover_known_bypassable_layers():
    assert "Origin allowlist" in SPOOF_VARIANTS
    assert "Referer check" in SPOOF_VARIANTS
    assert "UA filter" in SPOOF_VARIANTS
    for layer, variants in SPOOF_VARIANTS.items():
        assert len(variants) > 0, f"{layer} registered with no variants"
