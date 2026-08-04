import pytest

from ui.judge import (
    clear_api_key_from_env,
    load_env_file,
    provider_env_var,
    save_api_key_to_env,
    save_judge_config_to_env,
)


def test_provider_id_with_newline_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_api_key_to_env(tmp_path / ".env", "sk-abc", provider_id="foo\nEVIL=bar")


def test_api_key_with_newline_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_api_key_to_env(tmp_path / ".env", "sk-abc\nEVIL=bar", provider_id="openai")


def test_valid_provider_id_ok(tmp_path):
    env_path = tmp_path / ".env"
    save_api_key_to_env(env_path, "sk-abc", provider_id="openai")
    assert "OPENAI_API_KEY=sk-abc" in env_path.read_text()


def test_provider_env_var_rejects_bad_chars():
    with pytest.raises(ValueError):
        provider_env_var("open ai; rm -rf")


def test_judge_config_round_trips_and_replaces(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("UNRELATED=keepme\n")
    save_judge_config_to_env(
        env_path, "sk-1", "claude-haiku-4-5-20251001",
        "https://api.anthropic.com/v1", "anthropic",
    )
    save_judge_config_to_env(
        env_path, "sk-2", "gpt-4o-mini", "https://api.openai.com/v1", "openai",
    )
    env = load_env_file(env_path)
    assert env["UNRELATED"] == "keepme"
    assert env["JUDGE_PROVIDER_ID"] == "openai"
    assert env["JUDGE_MODEL"] == "gpt-4o-mini"
    assert env["JUDGE_BASE_URL"] == "https://api.openai.com/v1"
    assert env["OPENAI_API_KEY"] == "sk-2"
    # Replaced in place, not appended twice.
    assert env_path.read_text().count("JUDGE_MODEL=") == 1

    clear_api_key_from_env(env_path, provider_id="openai")
    env = load_env_file(env_path)
    assert env == {"UNRELATED": "keepme", "ANTHROPIC_API_KEY": "sk-1"}


def test_judge_config_rejects_newline_in_model(tmp_path):
    with pytest.raises(ValueError):
        save_judge_config_to_env(
            tmp_path / ".env", "sk-abc", "gpt\nEVIL=bar", "https://x/v1", "openai",
        )


def test_seed_judge_from_env_fallback_picks_present_provider(monkeypatch, tmp_path):
    """No JUDGE_PROVIDER_ID recorded, no .env on disk (shell-only env), and no
    OpenAI/Anthropic key present — the old ladder only knew those two
    providers and would leave the judge unconfigured. It must fall back to
    whichever known provider's key actually exists, e.g. DeepSeek, not
    silently default to anthropic.
    """
    import ui.server as srv

    original_config = srv.judge_registry.config
    try:
        monkeypatch.setattr(srv, "ENV_FILE", tmp_path / ".env")  # no file on disk
        monkeypatch.delenv("JUDGE_PROVIDER_ID", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-ds")
        monkeypatch.setattr(srv, "_read_cached_catalog", lambda: [
            {"provider_id": "deepseek", "model_id": "deepseek-chat",
             "base_url": "https://api.deepseek.com/v1"},
        ])

        srv._seed_judge_from_env()

        assert srv.judge_registry.config.provider_id == "deepseek"
        assert srv.judge_registry.config.model == "deepseek-chat"
        assert srv.judge_registry.config.api_key == "sk-ds"
    finally:
        srv.judge_registry.config = original_config


def _seed_with_env_file(monkeypatch, tmp_path, env_text, catalog):
    """Write a temp .env, clear JUDGE_PROVIDER_ID/known keys from os.environ
    (so only the .env file drives the decision), seed, and return the config.
    """
    import ui.server as srv

    env_path = tmp_path / ".env"
    env_path.write_text(env_text)
    monkeypatch.setattr(srv, "ENV_FILE", env_path)
    monkeypatch.delenv("JUDGE_PROVIDER_ID", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(srv, "_read_cached_catalog", lambda: catalog)

    original_config = srv.judge_registry.config
    try:
        srv._seed_judge_from_env()
        return srv.judge_registry.config
    finally:
        srv.judge_registry.config = original_config


def test_seed_judge_from_env_file_order_last_key_wins(monkeypatch, tmp_path):
    """Anthropic added first, DeepSeek added later (no JUDGE_PROVIDER_ID yet)
    — file order says DeepSeek was the last thing configured, so it wins.
    """
    config = _seed_with_env_file(
        monkeypatch, tmp_path,
        "ANTHROPIC_API_KEY=sk-a\nDEEPSEEK_API_KEY=sk-d\n",
        [{"provider_id": "deepseek", "model_id": "deepseek-chat",
          "base_url": "https://api.deepseek.com/v1"}],
    )
    assert config.provider_id == "deepseek"
    assert config.api_key == "sk-d"


def test_seed_judge_from_env_file_order_reversed(monkeypatch, tmp_path):
    """Same two keys, reversed file order — proves this is genuinely
    order-driven, not a hardcoded provider preference.
    """
    config = _seed_with_env_file(
        monkeypatch, tmp_path,
        "DEEPSEEK_API_KEY=sk-d\nANTHROPIC_API_KEY=sk-a\n",
        [{"provider_id": "anthropic", "model_id": "claude-haiku-4-5-20251001",
          "base_url": "https://api.anthropic.com/v1"}],
    )
    assert config.provider_id == "anthropic"
    assert config.api_key == "sk-a"


def test_seed_judge_from_env_saved_provider_overrides_file_order(monkeypatch, tmp_path):
    """JUDGE_PROVIDER_ID always wins, even when file order would pick a
    different provider.
    """
    import ui.server as srv

    env_path = tmp_path / ".env"
    env_path.write_text(
        "ANTHROPIC_API_KEY=sk-a\nDEEPSEEK_API_KEY=sk-d\n"
        "JUDGE_PROVIDER_ID=anthropic\n"
    )
    monkeypatch.setattr(srv, "ENV_FILE", env_path)
    monkeypatch.setenv("JUDGE_PROVIDER_ID", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-d")
    monkeypatch.delenv("JUDGE_MODEL", raising=False)
    monkeypatch.delenv("JUDGE_BASE_URL", raising=False)

    original_config = srv.judge_registry.config
    try:
        srv._seed_judge_from_env()
        assert srv.judge_registry.config.provider_id == "anthropic"
        assert srv.judge_registry.config.api_key == "sk-a"
    finally:
        srv.judge_registry.config = original_config
