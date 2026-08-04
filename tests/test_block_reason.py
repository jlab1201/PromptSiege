"""
Offline tests for classify_block_reason (ui/classifiers.py) and the
Akamai/Shape + timeout additions to classify_block_layer (ui/recon.py).

No network — same scope restriction as tests/test_recon.py.
"""
from ui.classifiers import classify_block_reason
from ui.recon import classify_block_layer

# ---- classify_block_reason ----

def test_timeout_status_zero():
    assert classify_block_reason(0, "") == "timeout"


def test_timeout_network_error_body():
    assert classify_block_reason(200, "__network_error__: ConnectTimeout") == "timeout"


def test_bot_block_410():
    assert classify_block_reason(410, "") == "bot_block"


def test_bot_block_abck_cookie_marker():
    assert classify_block_reason(403, "set via _abck cookie") == "bot_block"


def test_bot_block_perfdrive():
    assert classify_block_reason(403, "served by perfdrive.com") == "bot_block"


def test_akamai_403_is_waf_not_bot_block():
    # Bare "akamai" at a refusal status is a generic WAF block, matching what
    # classify_block_layer calls it. It is NOT a bot_block marker on its own:
    # this tool sends security-flavoured prompts, so a 200 reply discussing
    # Akamai must not be scored as a block. See test_akamai_in_a_reply_is_ok.
    assert classify_block_reason(403, "blocked by akamai") == "waf_challenge"


def test_akamai_in_a_reply_is_ok():
    reply = '{"reply":"Akamai is a CDN and bot-management vendor."}'
    assert classify_block_reason(200, reply) == "ok"


def test_akamai_interstitial_served_as_200_is_still_a_block():
    # The live cebupacificair.com challenge page: HTTP 200, Akamai's own
    # stylesheet classes in the body. Scoring this "ok" would fire the whole
    # corpus into a challenge page and report every turn as reached.
    challenge = '<div class="scf-akamai-logo-sec-abc">Powered and protected by</div>'
    assert classify_block_reason(200, challenge) == "bot_block"
    assert classify_block_layer(200, challenge) == "Bot manager (Akamai/Shape)"


def test_genuine_2xx_still_passes():
    assert classify_block_layer(200, '{"reply":"hello"}') is None


def test_bot_block_reference_number():
    assert classify_block_reason(403, "Your support ID is Reference #12345") == "bot_block"


def test_waf_challenge_cloudflare():
    assert classify_block_reason(403, "cloudflare attention required") == "waf_challenge"


def test_waf_challenge_503():
    assert classify_block_reason(503, "cf-ray: abc123, please complete the challenge") == "waf_challenge"


def test_schema_400():
    assert classify_block_reason(400, "invalid_type on field x") == "schema"


def test_auth_401():
    assert classify_block_reason(401, "") == "auth"


def test_rate_limit_429():
    assert classify_block_reason(429, "") == "rate_limit"


def test_ok_200():
    assert classify_block_reason(200, "hello there") == "ok"


def test_unmatched_status_falls_through():
    assert classify_block_reason(500, "internal error") == "http_500"


# ---- classify_block_layer additions (ui/recon.py) ----

def test_connection_timeout():
    assert classify_block_layer(0, "") == "Connection timeout"


def test_bot_manager_via_cookie():
    assert classify_block_layer(410, "", "_abck") == "Bot manager (Akamai/Shape)"


def test_cloudflare_still_wins_over_bot_manager():
    # Proves the new bot-manager branch didn't shadow the existing WAF chain.
    assert classify_block_layer(403, "cloudflare attention required") == "WAF (Cloudflare)"


def test_akamai_waf_403_still_classified_as_waf_not_bot_manager():
    # Pinned by tests/test_recon.py::test_classify_block_layer_waf_akamai —
    # bare "akamai" text at 403 (no 410, no _abck/perfdrive) stays WAF (Akamai).
    assert classify_block_layer(403, "blocked by akamai") == "WAF (Akamai)"


# ---- the cookie signal must not over-fire ----
# `_abck` is set on EVERY response from an Akamai-fronted host, including ones
# that are plainly not blocks. Treating its presence alone as a block told the
# operator "set Runner = browser" when the real fault was a wrong endpoint or a
# wrong body shape — which defeats the point of diagnosing honestly.

def test_cookie_alone_is_not_a_block_on_non_refusal_statuses():
    for status in (404, 405):
        assert classify_block_layer(status, "", "_abck") is None, status
    # A schema rejection keeps its own, more useful diagnosis.
    assert classify_block_layer(400, "invalid_type", "_abck") == "Schema validation"


def test_cookie_plus_refusal_status_is_a_block():
    assert classify_block_layer(403, "", "_abck") == "Bot manager (Akamai/Shape)"
    assert classify_block_layer(503, "", "perfdrive") == "Bot manager (Akamai/Shape)"


def test_specific_403_cause_beats_generic_bot_manager():
    # The cookie fallback is last-resort: a 403 that names its own cause keeps it.
    assert classify_block_layer(403, "bad origin", "_abck") == "Origin allowlist"
