"""Guard: a Pace (s) of 0 must survive the browser and the API.

The Pace field's own help text says "Set 0 for fastest (server-allowed) speed",
but the start-run body was built with `parseFloat($('f-pacing').value) || 3` --
and `0 || 3` is 3 in JavaScript, so a legal, documented pace of 0 was silently
turned into 3 before it ever left the browser.

There is no JS test runner in this repo, so the first test below is a text guard
rather than a behavioural one. It is brittle to reformatting, but it is the only
thing here that can catch a regression inside that inline script at all.
"""

import re
from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_identity_wiring import _start_run

INDEX_HTML = Path(__file__).resolve().parents[1] / "ui" / "static" / "index.html"

# `pacing_s: <something> || <fallback>` -- the exact shape of the original bug.
# Deliberately narrow: it must not flag the correct `isFinite(...) ? ... : 3`
# form, nor the unrelated `|| 0` fallbacks on the sibling numeric fields.
FALSY_COERCION = re.compile(r"pacing_s\s*:\s*[^,\n]*\|\|")


def test_frontend_does_not_falsy_coerce_pacing():
    matches = FALSY_COERCION.findall(INDEX_HTML.read_text(encoding="utf-8"))
    assert not matches, (
        "index.html builds pacing_s with `||`, which collapses a pace of 0 into "
        f"the fallback. Use `isFinite(paceVal) ? paceVal : 3` instead. Found: {matches}"
    )


def test_pacing_zero_reaches_run_state(monkeypatch):
    from ui.server import app

    captured = _start_run(TestClient(app), monkeypatch, pacing_s=0)
    assert captured["state"].pacing_s == 0.0


def test_pacing_defaults_to_three_when_omitted(monkeypatch):
    from ui.server import app

    captured = _start_run(TestClient(app), monkeypatch)
    assert captured["state"].pacing_s == 3.0
