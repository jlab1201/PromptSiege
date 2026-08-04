import json

from ui.browser_profile import CHROME_UA, HONEST
from ui.runner import (
    Counters,
    FindingAggregate,
    RunState,
    _identity_headers,
    _write_meta_sidecar,
)


def _make_state(tmp_path, run_id: str = "t0001") -> RunState:
    state = RunState(
        run_id=run_id,
        target_url="http://x.test/api/chat",
        pacing_s=0.0,
        cancel_event=None,
        queue=None,
        counters=Counters(
            reached=2, blocked=1, compromised=1, refused=2,
            total_done=3, total=3,
        ),
    )
    state.started_at = "2026-05-28T10:00:00Z"
    state.results_path = tmp_path / f"ui-{run_id}.jsonl"
    state.findings = {
        "Rate limiting": FindingAggregate(
            layer="Rate limiting", severity="medium",
            description="429 burst", count=2, first_seen_seq=1,
            last_evidence={"sample": "..."},
        ),
    }
    return state


def test_meta_sidecar_completed(tmp_path):
    state = _make_state(tmp_path)
    _write_meta_sidecar(
        state, categories=["dan"], status="completed",
        finished_at="2026-05-28T10:01:30Z",
    )
    meta_path = tmp_path / "ui-t0001.meta.json"
    assert meta_path.exists()
    m = json.loads(meta_path.read_text())
    assert m["run_id"] == "t0001"
    assert m["target_url"] == "http://x.test/api/chat"
    assert m["categories"] == ["dan"]
    assert m["started_at"] == "2026-05-28T10:00:00Z"
    assert m["finished_at"] == "2026-05-28T10:01:30Z"
    assert m["status"] == "completed"
    assert m["counters"]["compromised"] == 1
    assert m["counters"]["total_done"] == 3
    assert len(m["findings"]) == 1
    assert m["findings"][0]["layer"] == "Rate limiting"
    assert m["findings"][0]["count"] == 2
    assert m["findings"][0]["first_seen_seq"] == 1
    assert m["judge"] is None


def test_meta_sidecar_stopped(tmp_path):
    state = _make_state(tmp_path, run_id="t0002")
    _write_meta_sidecar(
        state, categories=["dan", "role_play"], status="stopped",
        finished_at="2026-05-28T10:00:15Z",
    )
    m = json.loads((tmp_path / "ui-t0002.meta.json").read_text())
    assert m["status"] == "stopped"
    assert m["categories"] == ["dan", "role_play"]


def test_meta_sidecar_error(tmp_path):
    state = _make_state(tmp_path, run_id="t0003")
    _write_meta_sidecar(
        state, categories=None, status="error",
        finished_at="2026-05-28T10:00:05Z",
    )
    m = json.loads((tmp_path / "ui-t0003.meta.json").read_text())
    assert m["status"] == "error"
    assert m["categories"] == []


def test_meta_sidecar_no_results_path(tmp_path):
    """When results_path is None (e.g., prompts failed to load), the writer is
    a no-op and does not raise."""
    state = _make_state(tmp_path)
    state.results_path = None
    _write_meta_sidecar(
        state, categories=["dan"], status="error",
        finished_at="2026-05-28T10:00:00Z",
    )
    # Nothing should have been written; tmp_path stays empty for sidecars.
    assert not list(tmp_path.glob("*.meta.json"))


def test_identity_headers_browser(tmp_path):
    state = _make_state(tmp_path)
    headers = _identity_headers(state)
    assert headers["User-Agent"] == CHROME_UA


def test_identity_headers_honest(tmp_path):
    state = _make_state(tmp_path)
    state.identity = "honest"
    headers = _identity_headers(state)
    assert headers["User-Agent"] == HONEST["User-Agent"]


def test_identity_headers_custom(tmp_path):
    state = _make_state(tmp_path)
    state.identity = "custom"
    state.custom_headers = {"X-Foo": "bar"}
    headers = _identity_headers(state)
    assert headers == {"X-Foo": "bar"}


def test_identity_headers_includes_custom_headers_for_browser(tmp_path):
    state = _make_state(tmp_path)
    state.custom_headers = {"Cookie": "session=abc"}
    headers = _identity_headers(state)
    assert headers["Cookie"] == "session=abc"
    assert headers["User-Agent"] == CHROME_UA


def test_per_request_header_precedence(tmp_path):
    """passport_headers (recon-proven) beat operator-supplied custom_headers."""
    custom_headers = {"Origin": "a"}
    passport_headers = {"Origin": "b"}
    req_headers = {
        **custom_headers,
        **passport_headers,
        "Content-Type": "application/json",
    }
    assert req_headers["Origin"] == "b"
