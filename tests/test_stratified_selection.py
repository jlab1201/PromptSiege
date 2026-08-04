"""A default run is 20 prompts drawn from a shuffled 607-prompt corpus.

Taking the first 20 gives whatever the shuffle dealt, so a run can contain no
`customer_data_leak` prompt at all — and the report then reads as "no data-leak
risk" when the truth is "never tested for it". That is the failure these pin.
"""
from __future__ import annotations

import random

from run import stratified_pick
from ui.runner import select_under_cap

CATEGORIES = (
    "made_up_promise", "unauthorized_action", "customer_data_leak",
    "brand_damage", "free_labor", "config_disclosure", "poisoned_input",
)


def _corpus(per_category: dict[str, int]) -> list[dict]:
    return [
        {"id": f"{cat}-{i}", "category": cat, "text": "x" * 100}
        for cat, n in per_category.items()
        for i in range(n)
    ]


def _counts(rows: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[r["category"]] = out.get(r["category"], 0) + 1
    return out


def test_every_category_survives_a_default_twenty_prompt_run():
    """The skew is real: the corpus holds ~174 unauthorized_action against 15
    free_labor. A proportional sample would give free_labor half a prompt.
    """
    corpus = _corpus({
        "unauthorized_action": 174, "config_disclosure": 162,
        "poisoned_input": 161, "made_up_promise": 40,
        "customer_data_leak": 30, "brand_damage": 25, "free_labor": 15,
    })
    picked = stratified_pick(corpus, 20)
    assert len(picked) == 20
    assert set(_counts(picked)) == set(CATEGORIES), "a harm category went untested"
    assert min(_counts(picked).values()) >= 20 // len(CATEGORIES)


def test_a_plain_slice_would_have_missed_categories():
    """Guards the premise, not the fix — if the corpus ever becomes balanced
    enough that slicing is fine, this test says so instead of quietly passing.
    """
    corpus = _corpus({
        "unauthorized_action": 174, "config_disclosure": 162,
        "poisoned_input": 161, "made_up_promise": 40,
        "customer_data_leak": 30, "brand_damage": 25, "free_labor": 15,
    })
    random.Random(0).shuffle(corpus)
    assert len(_counts(corpus[:20])) < len(CATEGORIES), (
        "a plain slice now covers every category — stratification may be moot"
    )


def test_holds_at_any_n():
    corpus = _corpus(dict.fromkeys(CATEGORIES, 50))
    for n in (7, 14, 20, 100, 200):
        picked = stratified_pick(corpus, n)
        assert len(picked) == n
        assert set(_counts(picked)) == set(CATEGORIES)


def test_drained_categories_do_not_shrink_the_run():
    """free_labor runs out first. The remaining slots have to come from
    somewhere else — asking for 60 must still deliver 60, not 7 x 15.
    """
    corpus = _corpus({"free_labor": 2, "brand_damage": 40, "poisoned_input": 40})
    picked = stratified_pick(corpus, 60)
    assert len(picked) == 60
    assert _counts(picked)["free_labor"] == 2


def test_limit_beyond_the_corpus_returns_everything():
    corpus = _corpus({"free_labor": 3, "brand_damage": 4})
    assert len(stratified_pick(corpus, 100)) == 7
    assert len(stratified_pick(corpus, None)) == 7


def test_upstream_shuffle_still_chooses_which_prompt_represents_a_category():
    """Stratification fixes WHICH categories run, not which prompt stands for
    each — that must stay random, or every scan sends the same 20 payloads and
    a target that memorised them looks clean.
    """
    corpus = _corpus(dict.fromkeys(CATEGORIES, 50))
    a, b = list(corpus), list(corpus)
    random.Random(1).shuffle(a)
    random.Random(2).shuffle(b)
    assert [p["id"] for p in stratified_pick(a, 21)] != [p["id"] for p in stratified_pick(b, 21)]


def test_select_under_cap_stratifies_and_reserves_the_rest():
    """The UI path slices here, not in load_prompts. The reserve backfills
    over-cap prompts mid-run, so it must hold exactly what wasn't picked —
    no prompt in both, none dropped on the floor.
    """
    corpus = _corpus(dict.fromkeys(CATEGORIES, 10))
    selected, reserve = select_under_cap(corpus, max_chars=0, limit=14)

    assert len(selected) == 14
    assert set(_counts(selected)) == set(CATEGORIES)
    assert len(reserve) == len(corpus) - 14
    sel_ids = [p["id"] for p in selected]
    res_ids = [p["id"] for p in reserve]
    assert not set(sel_ids) & set(res_ids), "a prompt is in both the run and the reserve"
    assert sorted(sel_ids + res_ids) == sorted(p["id"] for p in corpus)


def test_select_under_cap_stratifies_within_the_length_cap():
    """Over-cap prompts are partitioned out BEFORE selection. If a category is
    entirely over-cap it genuinely can't run, but the rest must still spread.
    """
    corpus = _corpus(dict.fromkeys(CATEGORIES, 6))
    for p in corpus:
        if p["category"] == "free_labor":
            p["text"] = "x" * 5000
    selected, _ = select_under_cap(corpus, max_chars=500, limit=12)
    counts = _counts(selected)
    assert "free_labor" not in counts
    assert set(counts) == set(CATEGORIES) - {"free_labor"}
