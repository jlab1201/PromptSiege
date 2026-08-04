"""Integrity checks against the real shipped prompts.json corpus.

Unlike the other test_prompts_* modules, this file does NOT build synthetic
fixtures — it validates the actual corpus that ships with the repo.
"""
from __future__ import annotations

import json
import re
import warnings
from pathlib import Path

from run import fill_prompt_slots
from ui.prompts_store import ALLOWED_CATEGORIES

CORPUS_PATH = Path(__file__).resolve().parents[1] / "prompts.json"

# Unfilled payload placeholders that should never be the tail of a shipped
# prompt (it means the scrape truncated before a variable was substituted).
# {{user}}/{{char}}/<user> are excluded: legitimate SillyTavern card syntax.
PLACEHOLDER_TOKENS = (
    "[INSERT PROMPT HERE]", "[PROMPT]", "[YOUR PROMPT]",
    "<prompt here>", "<PROMPT>", "[TARGETLANGUAGE]",
)

TAIL_WINDOW = 15  # chars from end-of-match a slot must fall within to count

# Generic {{word}} detector, independent of run.py's fill_prompt_slots token
# list — catches template slots the filler doesn't know about yet (e.g.
# {{action}}), not just the ones it already fills (e.g. {{input}}).
# {{user}}/{{char}} stay excluded: SillyTavern card syntax, not a slot.
_CURLY_SLOT_RX = re.compile(r"\{\{\s*(\w+)\s*\}\}")
_CURLY_SLOT_EXCLUDED = {"user", "char"}


def _trailing_slot(text: str) -> str | None:
    """Return the offending placeholder if `text` ends on an unfilled slot,
    else None. A match counts if it ends within TAIL_WINDOW chars of the
    text's end (measuring from the END of the match, not its start).
    """
    tail_start = len(text) - TAIL_WINDOW
    last_end = -1
    last_token = None
    for token in PLACEHOLDER_TOKENS:
        pos = text.rfind(token)
        if pos != -1:
            end = pos + len(token)
            if end >= tail_start and end > last_end:
                last_end, last_token = end, token
    for m in _CURLY_SLOT_RX.finditer(text):
        if m.group(1).lower() in _CURLY_SLOT_EXCLUDED:
            continue
        if m.end() >= tail_start and m.end() > last_end:
            last_end, last_token = m.end(), m.group(0)
    return last_token

# The store's write-path cap (add_prompt/update_prompt) is 10_000 chars, but
# the scraped corpus predates that cap and still has ~40 legitimately over
# it. We assert a much looser ceiling here so a genuinely corrupt/runaway
# entry still fails, without blocking on the known-over-cap backlog.
MAX_TEXT_CHARS = 60_000
MIN_TEXT_CHARS = 40

MAX_SOURCE_CHARS = 200
MAX_REFERENCE_CHARS = 500


def _load_corpus() -> list[dict]:
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, list), "prompts.json must be a JSON array"
    return data


def test_corpus_parses_as_list():
    rows = _load_corpus()
    assert len(rows) > 0


def test_required_fields_non_empty():
    rows = _load_corpus()
    bad = [
        r.get("id", "<no-id>")
        for r in rows
        if not str(r.get("id") or "").strip()
        or not str(r.get("source") or "").strip()
        or not str(r.get("category") or "").strip()
        or not str(r.get("text") or "").strip()
    ]
    assert not bad, f"entries with empty required field(s): {bad}"


def test_ids_are_unique():
    rows = _load_corpus()
    ids = [r.get("id") for r in rows]
    seen: set = set()
    dupes = []
    for i in ids:
        if i in seen:
            dupes.append(i)
        seen.add(i)
    assert not dupes, f"duplicate ids: {dupes}"


def test_categories_are_allowed():
    rows = _load_corpus()
    bad = {r["id"]: r.get("category") for r in rows if r.get("category") not in ALLOWED_CATEGORIES}
    assert not bad, f"entries with disallowed category: {bad}"


def test_text_not_too_short_or_blank():
    rows = _load_corpus()
    bad = [r["id"] for r in rows if len(str(r.get("text") or "").strip()) < MIN_TEXT_CHARS]
    assert not bad, f"entries with text under {MIN_TEXT_CHARS} chars (or blank): {bad}"


def test_text_not_absurdly_long():
    # Loose ceiling — not the 10k write-path cap. See MAX_TEXT_CHARS comment.
    rows = _load_corpus()
    bad = [r["id"] for r in rows if len(str(r.get("text") or "")) > MAX_TEXT_CHARS]
    assert not bad, f"entries over {MAX_TEXT_CHARS} chars: {bad}"


def test_raw_corpus_slot_count_is_informational():
    """Non-failing: raw corpus texts are allowed to end on a slot — they are
    filled at load time by run.fill_prompt_slots, not edited in place
    (id is a content hash of text; editing would decouple ids and cause
    re-scrapes to re-add entries). This just surfaces the current count.
    """
    rows = _load_corpus()
    bad = {r["id"]: _trailing_slot(str(r.get("text") or "")) for r in rows}
    bad = {k: v for k, v in bad.items() if v}
    if bad:
        warnings.warn(
            f"{len(bad)} raw corpus entries end on a slot (expected — filled "
            f"at load time): {bad}",
            stacklevel=1,
        )


def test_prompts_are_slot_free_after_fill_prompt_slots():
    """The real invariant: every prompt must be test-ready as dispatched.
    Apply run.fill_prompt_slots (what run.py does at load time) and assert
    nothing still ends on an unfilled slot afterward. Catches both a corpus
    regression and a gap in fill_prompt_slots's own token list.
    """
    rows = _load_corpus()
    bad = {}
    for r in rows:
        filled = fill_prompt_slots(str(r.get("text") or ""))
        slot = _trailing_slot(filled)
        if slot:
            bad[r["id"]] = slot
    assert not bad, f"entries still ending on an unfilled slot after fill_prompt_slots: {bad}"


def test_authored_prompts_survive_a_rebuild():
    """scripts/build_corpus.py overwrites prompts.json wholesale and no scrape
    regenerates the hand-authored set, so it must come from a file the build
    does not write. If load_authored() ever reads prompts.json again, deleting
    that one file silently deletes every authored prompt.
    """
    from scripts.build_corpus import AUTHORED, AUTHORED_PREFIX, OUT, load_authored

    assert AUTHORED != OUT, "the authored source must not be the file the build overwrites"
    on_disk = {
        r["id"] for r in _load_corpus()
        if str(r.get("source") or "").startswith(AUTHORED_PREFIX)
    }
    assert on_disk, "corpus contains no authored prompts — expected the hand-written set"
    assert {r["id"] for r in load_authored()} == on_disk


def test_readme_quotes_the_real_corpus_count():
    """The README advertises the corpus size in prose, in more than one place.
    That number went stale once already (it said 1,381 at 1,481 entries), so
    assert every count the README states matches what actually ships.
    """
    readme = (CORPUS_PATH.parent / "README.md").read_text(encoding="utf-8")
    expected = f"{len(_load_corpus()):,}"
    # Matches both "432-prompt" and "1,686 prompt" — the count dropped below
    # four digits in the corpus cut, and a comma-only pattern silently stopped
    # matching anything, which reads as "nothing to check" rather than a failure.
    quoted = set(re.findall(r"\b(\d{1,3}(?:,\d{3})*)[- ]?(?:adversarial |prompt|entries)", readme))
    assert quoted, "README no longer quotes a corpus count — drop this test if that was deliberate"
    assert quoted == {expected}, (
        f"README quotes corpus count(s) {sorted(quoted)} but the corpus has {expected} entries"
    )


def test_reference_and_source_within_caps():
    rows = _load_corpus()
    bad_source = [r["id"] for r in rows if len(str(r.get("source") or "")) > MAX_SOURCE_CHARS]
    bad_reference = [
        r["id"] for r in rows
        if "reference" in r and len(str(r.get("reference") or "")) > MAX_REFERENCE_CHARS
    ]
    assert not bad_source, f"entries with source over {MAX_SOURCE_CHARS} chars: {bad_source}"
    assert not bad_reference, f"entries with reference over {MAX_REFERENCE_CHARS} chars: {bad_reference}"


def test_every_shipped_category_is_allowed_and_has_a_judge_criterion():
    """Three lists have to agree or a whole category grades badly in silence:
    what the corpus ships, what PromptStore will accept on an edit, and what the
    judge has a success criterion for. `CATEGORY_CRITERIA.get()` returns nothing
    on a miss, so a typo'd category name costs the judge its criterion with no
    error anywhere.
    """
    from ui.judge import CATEGORY_CRITERIA
    from ui.prompts_store import ALLOWED_CATEGORIES

    shipped = {r.get("category") for r in _load_corpus()}
    assert shipped <= set(ALLOWED_CATEGORIES), (
        f"corpus ships categories PromptStore would reject: "
        f"{sorted(shipped - set(ALLOWED_CATEGORIES))}"
    )
    assert shipped <= set(CATEGORY_CRITERIA), (
        f"corpus ships categories the judge has no criterion for: "
        f"{sorted(shipped - set(CATEGORY_CRITERIA))}"
    )


def test_legacy_categories_still_resolve_to_a_criterion():
    """Runs saved before the harm retag hold the old technique names. The alias
    map is the only thing keeping them gradeable — without it they'd fall
    through to no criterion and no disclosure oracle, with nothing logged.
    """
    from ui.classifiers import LEGACY_CATEGORY_ALIAS, normalize_category
    from ui.judge import CATEGORY_CRITERIA
    from ui.prompts_store import ALLOWED_CATEGORIES

    for legacy in LEGACY_CATEGORY_ALIAS:
        assert legacy in ALLOWED_CATEGORIES, (
            f"{legacy!r} is aliased but no longer accepted — a user's own older "
            f"prompt would fail validation on its next edit"
        )
        current = normalize_category(legacy)
        assert current == "" or current in CATEGORY_CRITERIA, (
            f"{legacy!r} aliases to {current!r}, which has no judge criterion"
        )


def test_obfuscated_prompts_are_tagged_by_harm_not_by_technique():
    """`encoding` was retired as a category: it names how a payload arrives, not
    what it costs the owner. Any prompt still carrying the delivery marker must
    sit in a harm category, or the report tells the owner "encoding" — which is
    not something they can act on.
    """
    from ui.classifiers import HARM_CATEGORIES

    encoded = [r for r in _load_corpus() if r.get("variant") == "encoded"]
    assert encoded, "expected obfuscated prompts in the corpus"
    bad = {r["id"]: r["category"] for r in encoded if r["category"] not in HARM_CATEGORIES}
    assert not bad, f"obfuscated prompts tagged by technique rather than harm: {bad}"


def test_business_harm_categories_have_real_coverage():
    """The measured gap this corpus was rebuilt to close: made-up refund or
    discount promises were 15 prompts (0.9%, all incidental), other-customer
    data 5 (0.3%), and the bot taking an action outright 0. A corpus that
    scores a bot on technique while never asking it to promise a refund tells
    an owner nothing about the bill they'd be left with.
    """
    counts: dict[str, int] = {}
    for r in _load_corpus():
        counts[r.get("category") or ""] = counts.get(r.get("category") or "", 0) + 1
    floors = {
        "made_up_promise": 40, "unauthorized_action": 35, "customer_data_leak": 30,
        "brand_damage": 25, "free_labor": 15, "config_disclosure": 15,
        "poisoned_input": 15,
    }
    thin = {c: counts.get(c, 0) for c, floor in floors.items() if counts.get(c, 0) < floor}
    assert not thin, f"harm categories below their coverage floor: {thin} (want {floors})"


def test_new_business_prompts_stay_short_and_backend_agnostic():
    """Two rules for the hand-written set, both about whether a prompt can work
    at all against a rented widget: a long prompt gets truncated by the input
    box (and a truncated prompt scoring "blocked" is false confidence), and a
    prompt naming a model vendor tests that vendor rather than the target.

    Scoped to the prompts written under this rule, identified by their source
    slug leading with their own category (`authored::made_up_promise_*`). The
    pre-retag set kept its original slugs (`authored::instruction_override_*`)
    and predates the length cap — holding it to a rule it was not written
    against would only teach us to loosen the rule.
    """
    vendor = re.compile(r"\b(chatgpt|openai|gpt-?[0-9]|anthropic)\b", re.I)
    rows = [
        r for r in _load_corpus()
        if str(r.get("source") or "").split("::")[-1].startswith(f"{r.get('category')}_")
    ]
    assert len(rows) >= 175, f"expected the business-harm prompts, found {len(rows)}"
    too_long = {r["id"]: len(r["text"]) for r in rows if len(r["text"]) > 500}
    named = {r["id"]: vendor.search(r["text"]).group(0) for r in rows if vendor.search(r["text"])}
    assert not too_long, f"business prompts over 500 chars: {too_long}"
    assert not named, f"business prompts naming a model vendor: {named}"
