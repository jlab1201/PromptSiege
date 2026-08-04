# Third-Party Notices

PromptSiege is licensed under Apache-2.0 (see `LICENSE`). **The adversarial
prompt corpus (`prompts.json`) is now entirely PromptSiege's own work** — it
ships no third-party content, so nothing in it carries an attribution
obligation. This file records what used to be in it and why it was removed.

## promptsiege/authored, promptsiege/recon, promptsiege/encoders

The whole corpus. Hand-authored by the PromptSiege project and licensed under
the repo's own Apache-2.0 license (see `LICENSE`). `promptsiege/encoders`
entries are obfuscated variants generated from the hand-authored ones.

## verazuo/jailbreak_llms (MIT) — REMOVED

Earlier versions drew 1,345 corpus entries from the
`jailbreak_prompts_2023_12_25.csv` dataset in
[verazuo/jailbreak_llms](https://github.com/verazuo/jailbreak_llms).

**Redistribution was clean.** The repo ships an MIT `LICENSE` file, verified
directly — *MIT License, Copyright (c) 2023 Vera*. GitHub's API reports
`license: null` for it only because its license detector fails to match the
file; that is a detector artifact, not a licensing problem. The removal was not
a licensing decision.

They were removed because they do not test what PromptSiege tests:

- 44.2% name ChatGPT or OpenAI explicitly, which is a no-op against an unknown
  backend
- the upstream categories are mislabeled — the `system_leak` entries are mostly
  roleplay, and one is simply ChatGPT's own system prompt pasted in as though
  it were an attack
- the `dan` family has a median length of 2,422 characters, 61% over 2,000; a
  chat-widget input box truncates them, and a truncated prompt scoring
  "blocked" is false confidence rather than a passing grade
- none carry a deterministic grading oracle — every canary-bearing prompt in
  the corpus is hand-written
- roughly 60% is persona roleplay, which says nothing about whether a business's
  bot will promise a refund it cannot honour

If you use the upstream dataset in research, its authors ask that you cite:

```
@inproceedings{SCBSZ24,
      author = {Xinyue Shen and Zeyuan Chen and Michael Backes and Yun Shen and Yang Zhang},
      title = {{``Do Anything Now'': Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models}},
      booktitle = {{ACM SIGSAC Conference on Computer and Communications Security (CCS)}},
      publisher = {ACM},
      year = {2024}
}
```

## NVIDIA/garak (Apache-2.0) — REMOVED

Earlier versions drew 12 DAN-family payloads from the `garak/data/dan/`
directory of [NVIDIA/garak](https://github.com/NVIDIA/garak) (Copyright 2023-
Leon Derczynski, Apache-2.0). Redistribution was clean here too; they were cut
for the same reason as the verazuo set — DAN-persona jailbreaks aimed at
ChatGPT, with no bearing on what a rented support widget will do.

## 0xk1h0/ChatGPT_DAN — REMOVED, NEVER REDISTRIBUTABLE

Unlike the two above, this one was a genuine licensing problem. A
pre-publication audit found that
[0xk1h0/ChatGPT_DAN](https://github.com/0xk1h0/ChatGPT_DAN) ships no `LICENSE`,
`LICENSE.md`, `LICENSE.txt`, `LICENCE`, or `COPYING` file at any common path
(all return 404), and the GitHub API reports `license: null` for the repo. Its
README carries no license statement either. That means the content is under
default copyright with no redistribution grant.

`scripts/build_corpus.py`'s module docstring previously labeled this source
"MIT" — that claim was incorrect and unsubstantiated. It has been corrected.

The 15 corpus entries previously sourced from `0xk1h0/ChatGPT_DAN` were removed
from `prompts.json` and the loader removed from `scripts/build_corpus.py`. This
source is not redistributed by PromptSiege.
