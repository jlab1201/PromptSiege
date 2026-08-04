# Contributing to PromptSiege

## Dev setup

Run the installer (`install.py`, cross-platform, safe to re-run) and skip the
interactive judge-key prompt with `--yes` if you don't need it yet:

```bash
# macOS / Linux
python3 install.py --yes
venv/bin/python -m pip install ruff   # not in requirements.txt, needed for `ruff check .`
./start.sh
```

```powershell
# Windows
py -3 install.py --yes
venv\Scripts\python -m pip install ruff
.\start.ps1
```

Or set it up by hand:

```bash
# macOS / Linux
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
cp .env.example .env   # optional, only needed for the judge pass
./start.sh
```

```powershell
# Windows
py -3 -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
copy .env.example .env
.\start.ps1
```

## Running tests

```bash
# macOS / Linux — activate the venv first if not already active
pytest tests/
```

```powershell
# Windows
venv\Scripts\Activate.ps1
pytest tests/
```

Tests live in `tests/` and cover the judge, prompt store, runner meta, and
server run-lifecycle logic. Classifiers and recon are pure-Python (no
FastAPI/httpx imports) — prefer testing them directly over spinning up the
server.

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting, configured
in `pyproject.toml` (`[tool.ruff]`): `line-length = 120`, `target-version =
"py312"`, `select = ["E", "F", "I", "UP", "B"]`. Running `ruff` without that
config picked up (e.g. from a directory outside the repo) will flag things
the project doesn't care about — run it from the repo root so it's picked up
automatically.

```bash
pip install ruff
ruff check .
```

Match the existing style: plain functions over classes where state doesn't
need to persist, dataclasses for state that does, no framework abstractions
beyond what's already in `ui/`.

## Reproducing CI locally

`.github/workflows/ci.yml` gates merges on ruff and bandit, neither of which
is in `requirements.txt` (only `pytest` is). Install both separately:

```bash
pip install ruff bandit
```

Then run the same checks CI runs:

```bash
ruff check .
pytest tests/
bandit -r ui/ scripts/ run.py -ll
```

## Adding new prompts / categories

The adversarial corpus lives in `prompts.json`, managed through
`ui/prompts_store.py`. Every prompt has an `id`, `category`, `source`, and
`text`; category must be one of `ALLOWED_CATEGORIES` in `ui/prompts_store.py`.

- **New prompt in an existing category** — add it via the web UI
  (`POST /api/prompts`) or edit `prompts.json` directly and validate with
  `pytest tests/test_prompts_store.py`.
- **New category** — add it to `ALLOWED_CATEGORIES` in
  `ui/prompts_store.py` first, then add prompts that reference it.
- **Bulk corpus refresh** — `python scripts/build_corpus.py` fetches and
  deduplicates upstream jailbreak corpora into `prompts.json`. If you're
  adding a new upstream source, wire it into that script rather than hand-
  editing the JSON.
- Prompts can restrict which runner they apply to via an optional
  `applies_to: ["thin_wrapper", "ada", ...]` field; omit it to apply to all
  platforms.

## Pull request expectations

- Keep PRs scoped to one change. Don't bundle a corpus refresh with a server
  change.
- Run `pytest tests/` before opening the PR.
- If you touch a behavior described in the README or `.env.example`, update
  those in the same PR — don't let docs drift from code.
- No new runtime dependencies without a reason in the PR description;
  `requirements.txt` pins every dependency to an exact version (`==`), so if
  you add one, pin it too and note why in the PR.
