from ui.runner import partition_by_char_cap, pop_under_cap, select_under_cap


def _p(id_: str, text: str) -> dict:
    return {"id": id_, "text": text}


def test_no_cap_keeps_everything():
    prompts = [_p("a", "x" * 5), _p("b", "y" * 5000)]
    kept, skipped = partition_by_char_cap(prompts, 0)
    assert kept == prompts
    assert skipped == []


def test_negative_cap_is_treated_as_no_cap():
    prompts = [_p("a", "x" * 5000)]
    kept, skipped = partition_by_char_cap(prompts, -1)
    assert kept == prompts
    assert skipped == []


def test_cap_splits_by_length():
    prompts = [_p("short", "x" * 10), _p("long", "y" * 200)]
    kept, skipped = partition_by_char_cap(prompts, 100)
    assert [p["id"] for p in kept] == ["short"]
    assert [p["id"] for p in skipped] == ["long"]


def test_boundary_is_inclusive():
    # A prompt exactly at the cap is kept (cap is <=, not <).
    prompts = [_p("exact", "x" * 100), _p("over", "x" * 101)]
    kept, skipped = partition_by_char_cap(prompts, 100)
    assert [p["id"] for p in kept] == ["exact"]
    assert [p["id"] for p in skipped] == ["over"]


def test_select_backfills_over_cap_to_hold_the_limit():
    # 2 requested, but one of the first two is over-cap: pull a short reserve so
    # the run still tests 2 prompts, not 1.
    prompts = [_p("a", "x" * 10), _p("big", "y" * 500), _p("c", "z" * 10)]
    selected, reserve = select_under_cap(prompts, max_chars=100, limit=2)
    assert [p["id"] for p in selected] == ["a", "c"]
    assert reserve == []


def test_select_keeps_leftover_within_cap_as_reserve():
    prompts = [_p("a", "x" * 10), _p("b", "x" * 10), _p("c", "x" * 10)]
    selected, reserve = select_under_cap(prompts, max_chars=100, limit=2)
    assert [p["id"] for p in selected] == ["a", "b"]
    assert [p["id"] for p in reserve] == ["c"]


def test_select_no_cap_reserves_the_tail_for_mid_run_swaps():
    # No upfront cap: still reserve the unpicked tail so a cap learned mid-run
    # has replacements to draw from.
    prompts = [_p("a", "x"), _p("b", "y" * 500), _p("c", "z")]
    selected, reserve = select_under_cap(prompts, max_chars=0, limit=1)
    assert [p["id"] for p in selected] == ["a"]
    assert [p["id"] for p in reserve] == ["b", "c"]


def test_pop_under_cap_discards_over_cap_reserves():
    pool = [_p("big", "y" * 500), _p("ok", "z" * 10)]
    got = pop_under_cap(pool, max_chars=100)
    assert got["id"] == "ok"
    assert pool == []  # the over-cap "big" was discarded during the scan


def test_pop_under_cap_returns_none_when_dry():
    assert pop_under_cap([], max_chars=100) is None
    assert pop_under_cap([_p("big", "y" * 500)], max_chars=100) is None
