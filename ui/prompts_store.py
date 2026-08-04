"""
CRUD helpers for the prompts.json corpus.

Pure Python — no FastAPI imports. Atomic writes via temp + os.replace.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

# The seven harm categories the corpus uses today, followed by the technique
# names it used before the retag. The legacy names are still ACCEPTED — they are
# validated on update as well as on add, so dropping them would make a user's
# own older prompt fail validation the next time they edited it.
ALLOWED_CATEGORIES = (
    "made_up_promise", "unauthorized_action", "customer_data_leak",
    "brand_damage", "free_labor", "config_disclosure", "poisoned_input",
    "dan", "role_play", "system_leak", "indirect",
    "encoding", "instruction_override", "recon", "other",
)


def load_prompts(path: Path) -> list[dict[str, Any]]:
    """Read the prompts JSON file. Returns [] if missing."""
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("prompts.json must be a JSON array")
    return data


def save_prompts(path: Path, prompts: list[dict[str, Any]]) -> None:
    """Atomic save: write to temp + os.replace."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(prompts, ensure_ascii=False, indent=None), encoding="utf-8")
    os.replace(tmp, path)


def new_prompt_id(existing: list[dict[str, Any]]) -> str:
    """Generate a 12-char lowercase hex ID not present in `existing`."""
    used = {p.get("id") for p in existing}
    while True:
        cand = secrets.token_hex(6)
        if cand not in used:
            return cand


def add_prompt(
    path: Path,
    text: str,
    category: str,
    source: str = "user",
    reference: str | None = None,
) -> dict[str, Any]:
    """Append a new prompt. Returns the created record. Raises ValueError on
    invalid input.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("text required")
    if len(text) > 10_000:
        raise ValueError("text too long (max 10000 chars)")
    if category not in ALLOWED_CATEGORIES:
        raise ValueError(f"category must be one of {ALLOWED_CATEGORIES}")
    ref = (reference or "").strip()
    if len(ref) > 500:
        raise ValueError("reference too long (max 500 chars)")
    prompts = load_prompts(path)
    record: dict[str, Any] = {
        "id": new_prompt_id(prompts),
        "category": category,
        "source": (source or "user").strip()[:200] or "user",
        "text": text,
    }
    if ref:
        record["reference"] = ref
    prompts.append(record)
    save_prompts(path, prompts)
    return record


def update_prompt(
    path: Path,
    prompt_id: str,
    *,
    text: str | None = None,
    category: str | None = None,
    source: str | None = None,
    reference: str | None = None,
) -> dict[str, Any]:
    """Mutate fields on the prompt with `prompt_id`. Returns the updated
    record. Raises KeyError if not found, ValueError on invalid input.

    `reference=""` clears the field; `reference=None` leaves it unchanged.
    """
    prompts = load_prompts(path)
    idx = next((i for i, p in enumerate(prompts) if p.get("id") == prompt_id), -1)
    if idx < 0:
        raise KeyError(prompt_id)
    rec = dict(prompts[idx])  # shallow copy so we can validate before committing
    if text is not None:
        t = text.strip()
        if not t:
            raise ValueError("text cannot be empty")
        if len(t) > 10_000:
            raise ValueError("text too long")
        rec["text"] = t
    if category is not None:
        if category not in ALLOWED_CATEGORIES:
            raise ValueError(f"category must be one of {ALLOWED_CATEGORIES}")
        rec["category"] = category
    if source is not None:
        rec["source"] = source.strip()[:200] or "user"
    if reference is not None:
        ref = reference.strip()
        if len(ref) > 500:
            raise ValueError("reference too long (max 500 chars)")
        if ref:
            rec["reference"] = ref
        else:
            rec.pop("reference", None)
    prompts[idx] = rec
    save_prompts(path, prompts)
    return rec


def delete_prompt(path: Path, prompt_id: str) -> None:
    """Remove the prompt with `prompt_id`. Raises KeyError if not found."""
    prompts = load_prompts(path)
    new = [p for p in prompts if p.get("id") != prompt_id]
    if len(new) == len(prompts):
        raise KeyError(prompt_id)
    save_prompts(path, new)
