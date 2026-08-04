"""Tests for ui/prompts_store.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ui.prompts_store import (
    add_prompt,
    delete_prompt,
    load_prompts,
    new_prompt_id,
    save_prompts,
    update_prompt,
)


def _seed(tmp: Path) -> Path:
    p = tmp / "prompts.json"
    p.write_text(json.dumps([
        {"id": "aaaaaaaaaaaa", "category": "dan", "source": "test", "text": "p1"},
        {"id": "bbbbbbbbbbbb", "category": "other", "source": "test", "text": "p2"},
    ]), encoding="utf-8")
    return p


def test_load_save_roundtrip(tmp_path: Path):
    p = _seed(tmp_path)
    rows = load_prompts(p)
    assert len(rows) == 2
    save_prompts(p, rows)
    assert load_prompts(p) == rows


def test_load_missing_file(tmp_path: Path):
    assert load_prompts(tmp_path / "missing.json") == []


def test_new_prompt_id_avoids_collisions():
    existing = [{"id": "abc"}, {"id": "def"}]
    new_id = new_prompt_id(existing)
    assert new_id not in {"abc", "def"}
    assert len(new_id) == 12


def test_add_prompt_creates_entry(tmp_path: Path):
    p = _seed(tmp_path)
    rec = add_prompt(p, text="new prompt", category="encoding", source="me")
    assert rec["category"] == "encoding"
    assert rec["text"] == "new prompt"
    assert len(rec["id"]) == 12
    rows = load_prompts(p)
    assert len(rows) == 3
    assert rows[-1]["id"] == rec["id"]


def test_add_prompt_rejects_invalid_category(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(ValueError):
        add_prompt(p, text="x", category="not_a_category")


def test_add_prompt_rejects_empty_text(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(ValueError):
        add_prompt(p, text="   ", category="dan")


def test_update_prompt_mutates_fields(tmp_path: Path):
    p = _seed(tmp_path)
    rec = update_prompt(p, "aaaaaaaaaaaa", text="updated", category="other")
    assert rec["text"] == "updated"
    assert rec["category"] == "other"
    # other entries untouched
    rows = load_prompts(p)
    assert rows[1]["text"] == "p2"


def test_update_prompt_missing_raises(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(KeyError):
        update_prompt(p, "zzzzzzzzzzzz", text="x")


def test_update_prompt_rejects_empty_text(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(ValueError):
        update_prompt(p, "aaaaaaaaaaaa", text="   ")


def test_add_prompt_with_reference(tmp_path: Path):
    p = _seed(tmp_path)
    rec = add_prompt(
        p, text="x", category="dan", source="me",
        reference="https://github.com/u/r/blob/main/p.md",
    )
    assert rec["reference"] == "https://github.com/u/r/blob/main/p.md"
    assert load_prompts(p)[-1]["reference"] == rec["reference"]


def test_add_prompt_without_reference_omits_field(tmp_path: Path):
    p = _seed(tmp_path)
    rec = add_prompt(p, text="x", category="dan")
    assert "reference" not in rec


def test_add_prompt_rejects_reference_too_long(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(ValueError):
        add_prompt(p, text="x", category="dan", reference="u" * 501)


def test_add_prompt_blank_reference_treated_as_none(tmp_path: Path):
    p = _seed(tmp_path)
    rec = add_prompt(p, text="x", category="dan", reference="   ")
    assert "reference" not in rec


def test_update_prompt_sets_reference(tmp_path: Path):
    p = _seed(tmp_path)
    rec = update_prompt(p, "aaaaaaaaaaaa", reference="https://example.com")
    assert rec["reference"] == "https://example.com"


def test_update_prompt_clears_reference_with_empty_string(tmp_path: Path):
    p = _seed(tmp_path)
    update_prompt(p, "aaaaaaaaaaaa", reference="https://example.com")
    rec = update_prompt(p, "aaaaaaaaaaaa", reference="")
    assert "reference" not in rec


def test_update_prompt_rejects_reference_too_long(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(ValueError):
        update_prompt(p, "aaaaaaaaaaaa", reference="u" * 501)


def test_delete_prompt_removes_entry(tmp_path: Path):
    p = _seed(tmp_path)
    delete_prompt(p, "aaaaaaaaaaaa")
    rows = load_prompts(p)
    assert len(rows) == 1
    assert rows[0]["id"] == "bbbbbbbbbbbb"


def test_delete_prompt_missing_raises(tmp_path: Path):
    p = _seed(tmp_path)
    with pytest.raises(KeyError):
        delete_prompt(p, "zzzzzzzzzzzz")
