import json

from fastapi.testclient import TestClient


def _seed_results_dir(tmp_path, monkeypatch):
    import ui.runner as runner
    import ui.server as srv

    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setattr(runner, "RESULTS_DIR", results)
    monkeypatch.setattr(srv, "RESULTS_DIR", results, raising=False)
    return results


def _write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_list_runs_meta_and_legacy(tmp_path, monkeypatch):
    from ui.server import app

    results = _seed_results_dir(tmp_path, monkeypatch)

    # Meta-backed run (newer)
    _write_jsonl(results / "ui-aaa111.jsonl", [{
        "id": "p1", "seq": 1, "category": "dan",
        "url": "http://x.test/api",
        "timestamp": "2026-05-28T10:00:00Z",
        "http_status": 200, "run_health": "reached",
        "injection_outcome": "refused",
        "prompt": "hi", "response": "no",
    }])
    (results / "ui-aaa111.meta.json").write_text(json.dumps({
        "run_id": "aaa111", "target_url": "http://x.test/api",
        "categories": ["dan"],
        "started_at": "2026-05-28T10:00:00Z",
        "finished_at": "2026-05-28T10:00:30Z",
        "status": "completed",
        "counters": {
            "reached": 1, "blocked": 0, "compromised": 0,
            "refused": 1, "total_done": 1, "total": 1,
        },
        "findings": [], "judge": None,
    }))

    # Legacy run (older, no meta)
    _write_jsonl(results / "ui-bbb222.jsonl", [
        {
            "id": "p1", "seq": 1, "category": "role_play",
            "url": "http://y.test/api",
            "timestamp": "2026-05-27T09:00:00Z",
            "http_status": 429, "run_health": "blocked",
            "injection_outcome": "refused",
            "prompt": "hi", "response": "429",
        },
        {
            "id": "p2", "seq": 2, "category": "role_play",
            "url": "http://y.test/api",
            "timestamp": "2026-05-27T09:00:10Z",
            "http_status": 200, "run_health": "reached",
            "injection_outcome": "compromised",
            # Long, no refusal language, no soft-block phrasing — has to still
            # grade compromised when the loader replays the classifier over it.
            "prompt": "go", "response": "Sure thing, here is the full plan: " + "x" * 80,
        },
    ])

    # Empty file should be skipped
    (results / "ui-empty99.jsonl").write_text("")

    client = TestClient(app)
    r = client.get("/api/runs")
    assert r.status_code == 200
    rows = r.json()
    # Sorted descending by started_at, so newer ("aaa111") first
    assert [row["run_id"] for row in rows] == ["aaa111", "bbb222"]

    meta_row = rows[0]
    assert meta_row["source"] == "meta"
    assert meta_row["status"] == "completed"
    assert meta_row["target_url"] == "http://x.test/api"
    assert meta_row["counters"]["total_done"] == 1

    legacy = rows[1]
    assert legacy["source"] == "legacy"
    assert legacy["status"] == "completed"
    assert legacy["target_url"] == "http://y.test/api"
    assert legacy["counters"]["total_done"] == 2
    assert legacy["counters"]["compromised"] == 1
    assert legacy["counters"]["reached"] == 1
    assert legacy["counters"]["blocked"] == 1


def test_list_runs_empty_dir(tmp_path, monkeypatch):
    from ui.server import app

    _seed_results_dir(tmp_path, monkeypatch)
    client = TestClient(app)
    r = client.get("/api/runs")
    assert r.status_code == 200
    assert r.json() == []


def test_get_run_detail_meta(tmp_path, monkeypatch):
    from ui.server import app

    results = _seed_results_dir(tmp_path, monkeypatch)
    _write_jsonl(results / "ui-ccc333.jsonl", [{
        "id": "p1", "seq": 1, "category": "dan",
        "url": "http://z/api",
        "timestamp": "2026-05-28T11:00:00Z",
        "prompt": "a", "response": "b",
        "http_status": 200, "run_health": "reached",
        "injection_outcome": "refused",
    }])
    (results / "ui-ccc333.meta.json").write_text(json.dumps({
        "run_id": "ccc333", "target_url": "http://z/api",
        "categories": ["dan"],
        "started_at": "2026-05-28T11:00:00Z",
        "finished_at": "2026-05-28T11:00:05Z",
        "status": "completed",
        "counters": {
            "reached": 1, "blocked": 0, "compromised": 0,
            "refused": 1, "total_done": 1, "total": 1,
        },
        "findings": [], "judge": None,
    }))

    client = TestClient(app)
    r = client.get("/api/runs/ccc333")
    assert r.status_code == 200
    j = r.json()
    assert j["meta"]["run_id"] == "ccc333"
    assert j["meta"]["status"] == "completed"
    assert len(j["records"]) == 1
    assert j["records"][0]["prompt"] == "a"


def test_get_run_detail_legacy_synthesizes_meta(tmp_path, monkeypatch):
    from ui.server import app

    results = _seed_results_dir(tmp_path, monkeypatch)
    _write_jsonl(results / "ui-leg999.jsonl", [
        {
            "id": "p1", "seq": 1, "category": "dan",
            "url": "http://legacy/api",
            "timestamp": "2026-05-25T00:00:00Z",
            "prompt": "one", "response": "...",
            "http_status": 200, "run_health": "reached",
            "injection_outcome": "compromised",
        },
    ])
    client = TestClient(app)
    r = client.get("/api/runs/leg999")
    assert r.status_code == 200
    j = r.json()
    assert j["meta"]["status"] == "completed"
    assert j["meta"]["target_url"] == "http://legacy/api"
    assert len(j["records"]) == 1


def test_get_run_detail_404(tmp_path, monkeypatch):
    from ui.server import app

    _seed_results_dir(tmp_path, monkeypatch)
    client = TestClient(app)
    assert client.get("/api/runs/doesnotexist").status_code == 404


def test_get_run_detail_rejects_path_traversal(tmp_path, monkeypatch):
    from ui.server import app

    _seed_results_dir(tmp_path, monkeypatch)
    client = TestClient(app)
    # An embedded ".." that survives URL normalization should be rejected by
    # the handler (defense in depth — the framework already blocks "/" but
    # an embedded ".." like "foo..bar" reaches us as-is).
    r = client.get("/api/runs/foo..bar")
    assert r.status_code == 400
