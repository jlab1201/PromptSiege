"""Tests for POST /api/prompts/import in ui/server.py."""
import json

from fastapi.testclient import TestClient


def _seed_prompts(tmp_path, monkeypatch):
    import ui.server as srv

    p = tmp_path / "prompts.json"
    p.write_text(json.dumps([
        {"id": "aaaaaaaaaaaa", "category": "dan", "source": "seed", "text": "existing prompt"},
    ]), encoding="utf-8")
    monkeypatch.setattr(srv, "PROMPTS_FILE", p, raising=False)
    return p


def test_import_multiple_prompts(tmp_path, monkeypatch):
    from ui.server import app

    p = _seed_prompts(tmp_path, monkeypatch)
    client = TestClient(app)
    r = client.post("/api/prompts/import", json={"prompts": [
        {"text": "brand new prompt one", "category": "dan"},
        {"text": "brand new prompt two", "category": "encoding", "source": "batch"},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == 2
    assert body["skipped_duplicates"] == 0
    assert body["errors"] == []
    assert len(body["ids"]) == 2

    rows = json.loads(p.read_text(encoding="utf-8"))
    assert len(rows) == 3


def test_import_skips_duplicates(tmp_path, monkeypatch):
    from ui.server import app

    p = _seed_prompts(tmp_path, monkeypatch)
    client = TestClient(app)
    r = client.post("/api/prompts/import", json={"prompts": [
        {"text": "  Existing Prompt  ", "category": "dan"},  # dupe of seed (normalized)
        {"text": "existing prompt", "category": "dan"},       # dupe of the item above too
        {"text": "actually new", "category": "other"},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == 1
    assert body["skipped_duplicates"] == 2

    rows = json.loads(p.read_text(encoding="utf-8"))
    assert len(rows) == 2


def test_import_malformed_item_does_not_abort_batch(tmp_path, monkeypatch):
    from ui.server import app

    _seed_prompts(tmp_path, monkeypatch)
    client = TestClient(app)
    r = client.post("/api/prompts/import", json={"prompts": [
        {"text": "good one", "category": "dan"},
        {"text": "   ", "category": "dan"},          # blank text
        {"text": "bad category", "category": "nope"},  # invalid category
        "not-even-an-object",                          # wrong type entirely
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == 1
    assert len(body["errors"]) == 3
    assert {e["index"] for e in body["errors"]} == {1, 2, 3}


def test_import_rejects_oversized_batch(tmp_path, monkeypatch):
    from ui.server import app

    p = _seed_prompts(tmp_path, monkeypatch)
    client = TestClient(app)
    r = client.post("/api/prompts/import", json={"prompts": [
        {"text": f"prompt {i}", "category": "dan"} for i in range(5001)
    ]})
    assert r.status_code == 400
    # Nothing written — corpus unchanged.
    assert len(json.loads(p.read_text(encoding="utf-8"))) == 1
