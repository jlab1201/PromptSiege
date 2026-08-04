from scripts.build_corpus import load_recon_seeds
from ui.prompts_store import ALLOWED_CATEGORIES


def test_recon_stays_an_allowed_category():
    """The harm categories replaced it in the corpus, but ALLOWED_CATEGORIES is
    validated on update as well as add — dropping the old name would make a
    user's own older prompt fail validation the next time they edited it."""
    assert "recon" in ALLOWED_CATEGORIES
    assert "config_disclosure" in ALLOWED_CATEGORIES


def test_recon_seeds_are_nonempty_and_tagged():
    seeds = load_recon_seeds()
    assert len(seeds) >= 5
    assert all(s["category"] == "config_disclosure" for s in seeds)
    assert all(s["id"] and s["text"] for s in seeds)


def test_recon_seed_ids_are_stable():
    assert [s["id"] for s in load_recon_seeds()] == [s["id"] for s in load_recon_seeds()]
