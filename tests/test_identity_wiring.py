from fastapi.testclient import TestClient


def _start_run(client, monkeypatch, **body):
    """POST /api/run with a runner monkeypatched out so no network happens.

    Captures the RunState handed to whichever runner (http or browser) got
    selected and returns it.
    """
    import ui.server as srv

    monkeypatch.setenv("PROMPTSIEGE_ALLOW_PRIVATE_TARGETS", "1")
    srv.registry.current = None  # registry is a module-level singleton; reset between tests
    captured: dict = {}

    async def fake_run_batch(state, categories, limit, shuffle):
        captured["state"] = state
        captured["runner"] = "http"

    async def fake_run_batch_browser(state, categories, limit, shuffle):
        captured["state"] = state
        captured["runner"] = "browser"

    monkeypatch.setattr(srv, "run_batch", fake_run_batch)
    monkeypatch.setattr("ui.runner_browser.run_batch_browser", fake_run_batch_browser)

    resp = client.post("/api/run", json={
        "target_url": "http://localhost:9/api",
        "limit": 1,
        **body,
    })
    assert resp.status_code == 200, resp.text
    return captured


def test_identity_and_custom_headers_reach_run_state(monkeypatch):
    from ui.server import app

    client = TestClient(app)
    captured = _start_run(
        client, monkeypatch,
        identity="honest",
        custom_headers="Authorization: Bearer x\nX-Env: staging",
    )
    state = captured["state"]
    assert state.identity == "honest"
    assert state.custom_headers == {"Authorization": "Bearer x", "X-Env": "staging"}


def test_recommended_runner_override_still_works(monkeypatch):
    from ui.server import app

    client = TestClient(app)
    captured = _start_run(client, monkeypatch, recommended_runner="browser")
    assert captured["runner"] == "browser"


def test_unknown_identity_falls_back_to_browser(monkeypatch):
    from ui.server import app

    client = TestClient(app)
    captured = _start_run(client, monkeypatch, identity="bogus")
    assert captured["state"].identity == "browser"
