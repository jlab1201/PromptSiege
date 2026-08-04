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


def _seed_valid_run(results, run_id="ccc333"):
    _write_jsonl(results / f"ui-{run_id}.jsonl", [{
        "id": "p1", "seq": 1, "category": "dan",
        "url": "http://z/api",
        "timestamp": "2026-05-28T11:00:00Z",
        "prompt": "a", "response": "b",
        "http_status": 200, "run_health": "reached",
        "injection_outcome": "refused",
    }])
    (results / f"ui-{run_id}.meta.json").write_text(json.dumps({
        "run_id": run_id, "target_url": "http://z/api",
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


def test_narrative_rejects_path_traversal(tmp_path, monkeypatch):
    from ui.server import app

    _seed_results_dir(tmp_path, monkeypatch)
    client = TestClient(app)
    r = client.post("/api/runs/foo..bar/narrative")
    assert r.status_code == 400


def test_narrative_requires_judge_config(tmp_path, monkeypatch):
    import ui.server as srv

    results = _seed_results_dir(tmp_path, monkeypatch)
    _seed_valid_run(results, "ccc333")
    monkeypatch.setattr(srv.judge_registry, "config", None, raising=False)

    client = TestClient(srv.app)
    r = client.post("/api/runs/ccc333/narrative")
    assert r.status_code == 400


def test_narrative_caches_and_surfaces_on_get(tmp_path, monkeypatch):
    import ui.narrative as narrative_mod
    import ui.server as srv
    from ui.judge import JudgeConfig

    results = _seed_results_dir(tmp_path, monkeypatch)
    _seed_valid_run(results, "ccc333")

    stub_cfg = JudgeConfig(api_key="sk-test", model="gpt-4o-mini", base_url="http://x.test/v1")
    monkeypatch.setattr(srv.judge_registry, "config", stub_cfg, raising=False)

    fake_narrative = {
        "risk_level": "High",
        "strengths": ["refuses DAN"],
        "weaknesses": ["leaks system prompt"],
        "remediation": ["add output filter"],
        "atlas_refs": ["AML.T0056"],
        "owasp_refs": ["LLM07"],
        "model": "gpt-4o-mini",
        "generated_at": "2026-05-28T12:00:00Z",
    }

    async def _fake_generate_narrative(meta, records, client, model):
        return fake_narrative

    monkeypatch.setattr(narrative_mod, "generate_narrative", _fake_generate_narrative)

    client = TestClient(srv.app)
    r = client.post("/api/runs/ccc333/narrative")
    assert r.status_code == 200
    assert r.json() == fake_narrative

    r2 = client.get("/api/runs/ccc333")
    assert r2.status_code == 200
    assert r2.json()["meta"]["narrative"] == fake_narrative
