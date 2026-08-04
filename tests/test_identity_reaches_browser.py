"""Identity must reach the Playwright context, not just the RunState.

test_identity_wiring.py asserts identity lands on RunState — then monkeypatches
run_batch_browser away, which is the only code that consumes it. That left the
browser path free to hardcode CHROME_UA regardless of identity, and it did:
picking "honest" (which exists so a client can attribute the traffic in their
own logs) silently sent the spoofed Chrome UA.

These tests import the real resolver out of runner_browser. Do NOT reimplement
its logic here — a local copy asserts only that the copy behaves like itself,
which is the exact hole that let the original bug through.
"""
import asyncio

import pytest

from ui.browser_adapters import CHROME_UA
from ui.runner import Counters, RunState
from ui.runner_browser import context_identity


def _state(identity: str, custom: dict | None = None) -> RunState:
    return RunState(
        run_id="t", target_url="https://example.com", pacing_s=0.0,
        cancel_event=asyncio.Event(), queue=asyncio.Queue(), counters=Counters(),
        identity=identity, custom_headers=custom or {},
    )


def test_honest_identity_sends_the_attributable_ua():
    ua, _ = context_identity(_state("honest"))
    assert ua == "PromptSiege/0.1.0"
    assert ua != CHROME_UA


def test_browser_identity_keeps_the_chrome_ua():
    assert context_identity(_state("browser"))[0] == CHROME_UA


def test_custom_identity_does_not_silently_spoof_chrome():
    # The HTTP runner sends no browser UA for "custom"; the browser path can't
    # send none, so it must fall back to the attributable UA, never a spoof.
    assert context_identity(_state("custom"))[0] != CHROME_UA


def test_custom_headers_survive_to_the_context():
    _, extra = context_identity(_state("browser", {"Authorization": "Bearer x", "X-Env": "stg"}))
    assert extra == {"Authorization": "Bearer x", "X-Env": "stg"}


def test_custom_user_agent_wins_over_the_identity_default():
    ua, extra = context_identity(_state("honest", {"User-Agent": "custom/1.0"}))
    assert ua == "custom/1.0"
    # ...and must not ALSO remain in the header dict, where Playwright would
    # let it override the user_agent kwarg on the wire.
    assert extra == {}


def test_lowercase_user_agent_is_also_lifted_out():
    # The UI hint is `Name: value`, so `user-agent:` is a realistic typing.
    ua, extra = context_identity(_state("browser", {"user-agent": "custom/2.0"}))
    assert ua == "custom/2.0"
    assert extra == {}


@pytest.mark.parametrize("identity", ["browser", "honest", "custom", "bogus"])
def test_every_identity_resolves_to_a_non_empty_ua(identity):
    assert context_identity(_state(identity))[0]
