# Security Policy

## Authorized use only

PromptSiege is offensive security tooling. It sends adversarial prompt-injection
payloads to chatbot endpoints to test whether their guardrails hold. It exists to
help teams test **systems they own or have explicit written permission to test**.

- Do not run scans against third-party chatbots without authorization.
- Do not use this tool to extract, exfiltrate, or manipulate data you are not
  authorized to access.
- You are responsible for complying with applicable law and any agreements that
  govern the target system.

Misuse of this tool is the user's responsibility, not the maintainers'.

## Known design assumption: no auth, localhost-only

The FastAPI server (`ui/server.py`) has **no authentication or authorization layer**.
It binds to `127.0.0.1` by default and assumes a single trusted local operator.

- Do not expose the server to a network (including via a reverse proxy or port
  forwarding) without adding your own authentication in front of it.
- Anyone who can reach the bound port can start scans, read results, and read or
  write the judge LLM API key.

This is a deliberate scope limitation, not an oversight — if you need multi-user
or network-exposed operation, add an auth layer before deploying it that way.

## Supported versions

This project does not yet cut versioned releases. Security fixes land on the
default branch; there is no LTS or backport policy at this stage.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

- Use GitHub's **Private Vulnerability Reporting**: go to the repository's
  **Security** tab → **Report a vulnerability**. (Maintainer: enable this once
  under Settings → Code security → Private vulnerability reporting.)
- Include: a description of the issue, steps to reproduce, and its potential
  impact.
- You should receive an acknowledgment within a few business days. There is no
  formal SLA at this stage of the project.

This keeps the report private until a fix is ready, and needs no published
contact email.

Please do not test the vulnerability against systems you don't control, and do
not disclose it publicly until a fix is available.
