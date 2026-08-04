from scripts.build_corpus import build_encoded_prompts


def _base(n):
    return [
        {"id": f"id{i}", "source": "seed", "category": "unauthorized_action",
         "text": f"malicious instruction number {i}"}
        for i in range(n)
    ]


def test_encoded_variants_keep_the_seed_harm_category():
    """Obfuscation is a delivery trick, not a harm. A base64-wrapped refund
    demand still costs the owner a refund, so the variant has to carry the
    seed's category and record the delivery separately — otherwise the report
    tells the owner the technique instead of the bill."""
    out = build_encoded_prompts(_base(3), per_category_cap=2)
    assert out, "expected encoded variants"
    assert all(p["category"] == "unauthorized_action" for p in out)
    assert all(p["variant"] == "encoded" for p in out)


def test_encoded_prompts_are_capped_per_category():
    # cap=2 base prompts * 4 encoders = 8 max from this category
    out = build_encoded_prompts(_base(50), per_category_cap=2)
    assert len(out) == 2 * 4


def test_encoded_prompt_ids_are_content_stable():
    out1 = build_encoded_prompts(_base(3), per_category_cap=2)
    out2 = build_encoded_prompts(_base(3), per_category_cap=2)
    assert [p["id"] for p in out1] == [p["id"] for p in out2]


def test_source_names_the_encoder():
    out = build_encoded_prompts(_base(1), per_category_cap=1)
    assert {p["source"].rsplit("::", 1)[-1] for p in out} == {
        "base64", "hex", "homoglyph", "leetspeak"
    }
